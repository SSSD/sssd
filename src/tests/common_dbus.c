/*
   SSSD

   Common utilities for dbus based tests.

   Authors:
        Stef Walter <stefw@redhat.com>

   Copyright (C) Red Hat, Inc 2014

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "config.h"

#include <stdio.h>
#include "tests/common.h"

struct mock_server {
    char *temp_dir;
    char *dbus_address;
    pid_t pid;
    DBusConnection *client;

    /* Used for synchronization */
    int sync_fds[2];

    /* Only used during init */
    sbus_server_conn_init_fn init_fn;
    void *init_pvt_data;
};

/*
 * If you think we're going to do full error propagation during tests ...
 * you're going to have a bad time (reading this code)
 */
#define verify_eq(x, y) \
    do { if ((x) != (y)) { fprintf(stderr, "failed: %s == %s\n", #x, #y); abort(); } } while (0)
#define verify_neq(x, y) \
    do { if ((x) == (y)) { fprintf(stderr, "failed: %s != %s\n", #x, #y); abort(); } } while (0)

static int
mock_server_cleanup(struct mock_server *mock)
{
    int child_status;
    const char *file;
    struct stat sb;

    dbus_connection_close(mock->client);
    dbus_connection_unref(mock->client);

    /* Tell the server thread to quit */
    verify_eq (write(mock->sync_fds[0], "X", 1), 1);

    /* Wait for the server child, it always returns mock */
    verify_eq (waitpid(mock->pid, &child_status, 0), mock->pid);
    verify_eq (child_status, 0);

    file = strchr(mock->dbus_address, '/');
    if (stat(file, &sb) == 0) {
        verify_eq (unlink(file), 0);
    }
    verify_eq (rmdir(mock->temp_dir), 0);

    return EOK;
}

static int
on_accept_connection(struct sbus_connection *conn,
                     void *data)
{
    struct mock_server *mock = data;

    verify_eq (mock->init_fn(conn, mock->init_pvt_data), EOK);

    /* Synchronization point: test_dbus_setup_mock() should return */
    verify_eq (write(mock->sync_fds[1], "X", 1), 1);

    return EOK;
}

static void
on_sync_fd_written(struct tevent_context *loop,
                   struct tevent_fd *fde,
                   uint16_t flags,
                   void *data)
{
    bool *stop_server = data;
    *stop_server = true;
}

static void
mock_server_child(void *data)
{
    struct mock_server *mock = data;
    struct tevent_context *loop;
    struct sbus_connection *server;
    bool stop_server = false;
    TALLOC_CTX *ctx;

    ctx = talloc_new(NULL);
    loop = tevent_context_init(ctx);

    verify_eq (sbus_new_server(ctx, loop, mock->dbus_address, false,
                               &server, on_accept_connection, mock), EOK);

    tevent_add_fd(loop, ctx, mock->sync_fds[1], TEVENT_FD_READ,
                  on_sync_fd_written, &stop_server);

    /* Synchronization point: test_dbus_setup_mock() should connect */
    verify_eq (write(mock->sync_fds[1], "X", 1), 1);

    /* Do the loop */
    while(!stop_server) {
        verify_eq (tevent_loop_once(loop), 0);
    }

    /* TODO: sbus doesn't support cleanup of a server */

    talloc_free(ctx);
}

struct DBusConnection *
test_dbus_setup_mock(TALLOC_CTX *mem_ctx,
                     struct tevent_context *loop,
                     sbus_server_conn_init_fn init_fn,
                     void *init_pvt_data)
{
    struct mock_server *mock;
    char dummy;

    mock = talloc_zero(mem_ctx, struct mock_server);
    talloc_set_destructor(mock, mock_server_cleanup);
    mock->init_fn = init_fn;
    mock->init_pvt_data = init_pvt_data;

    mock->temp_dir = mkdtemp(talloc_strdup(mock, "/tmp/sssd-dbus-tests.XXXXXX"));
    verify_neq (mock->temp_dir, NULL);
    mock->dbus_address = talloc_asprintf(mock, "unix:path=%s/sbus", mock->temp_dir);
    verify_neq (mock->dbus_address, NULL);

    /* We use an fd pair as a synchronization device, integrates with tevent well */
    verify_eq (socketpair(PF_LOCAL, SOCK_STREAM, 0, mock->sync_fds), 0);

    /* Run the dbus server in a child process */
    mock->pid = fork();
    if (mock->pid == 0) {
        mock_server_child(mock);
        _exit(0);
    }

    verify_neq (mock->pid, -1);

    /* Synchronization point: wait for sync point in mock_server_child */
    verify_eq (read(mock->sync_fds[0], &dummy, 1), 1);

    /* Open a shared D-BUS connection to the address */
    mock->client = dbus_connection_open_private(mock->dbus_address, NULL);
    verify_neq (mock->client, NULL);

    /* Synchronization point: wait for sync point in on_accept_connection */
    verify_eq (read(mock->sync_fds[0], &dummy, 1), 1);

    return mock->client;
}

DBusMessage *
test_dbus_call_sync(DBusConnection *conn, const char *object_path,
                    const char *interface, const char *method,
                    DBusError *error, int first_arg_type, ...)
{
    DBusMessage *message;
    DBusMessage *reply;
    va_list va;

    message = dbus_message_new_method_call(NULL, object_path, interface, method);
    verify_neq(message, NULL);

    va_start(va, first_arg_type);
    verify_eq(dbus_message_append_args_valist(message, first_arg_type, va), TRUE);
    va_end(va);

    reply = dbus_connection_send_with_reply_and_block(conn, message, -1, error);
    dbus_message_unref(message);

    return reply;
}
