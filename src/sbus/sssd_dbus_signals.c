/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include <talloc.h>
#include <dbus/dbus.h>
#include <dhash.h>

#include "util/util.h"
#include "util/sss_ptr_hash.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_private.h"

static int sbus_incoming_signal_destructor(struct sbus_incoming_signal *a_signal)
{
    dbus_message_unref(a_signal->message);
    return 0;
}

static struct sbus_incoming_signal *
sbus_new_incoming_signal(struct sbus_connection *conn,
                         DBusMessage *message)
{
    struct sbus_incoming_signal *a_signal;

    a_signal = talloc_zero(conn, struct sbus_incoming_signal);
    if (a_signal == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory allocating D-Bus signal\n");
        return NULL;
    }

    a_signal->conn = conn;
    a_signal->message = dbus_message_ref(message);
    a_signal->interface = dbus_message_get_interface(message);
    a_signal->signal = dbus_message_get_member(message);
    a_signal->path = dbus_message_get_path(message);

    talloc_set_destructor(a_signal, sbus_incoming_signal_destructor);

    return a_signal;
}

struct sbus_incoming_signal_data {
    sbus_incoming_signal_fn handler_fn;
    void *handler_data;
};

hash_table_t *
sbus_incoming_signal_hash_init(TALLOC_CTX *mem_ctx)
{
    return sss_ptr_hash_create(mem_ctx, NULL, NULL);
}

static errno_t
sbus_incoming_signal_hash_add(hash_table_t *table,
                              const char *iface,
                              const char *a_signal,
                              sbus_incoming_signal_fn handler_fn,
                              void *handler_data)
{
    TALLOC_CTX *tmp_ctx;
    struct sbus_incoming_signal_data *data;
    char *key;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    key = talloc_asprintf(tmp_ctx, "%s.%s", iface, a_signal);
    if (key == NULL) {
        ret = ENOMEM;
        goto done;
    }

    data = talloc_zero(tmp_ctx, struct sbus_incoming_signal_data);
    if (data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    data->handler_data = handler_data;
    data->handler_fn = handler_fn;

    ret = sss_ptr_hash_add(table, key, data, struct sbus_incoming_signal_data);
    if (ret != EOK) {
        goto done;
    }

    talloc_steal(table, data);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static struct sbus_incoming_signal_data *
sbus_incoming_signal_hash_lookup(hash_table_t *table,
                                 const char *iface,
                                 const char *a_signal)
{
    struct sbus_incoming_signal_data *data;
    char *key;

    key = talloc_asprintf(NULL, "%s.%s", iface, a_signal);
    if (key == NULL) {
        return NULL;
    }

    data = sss_ptr_hash_lookup(table, key, struct sbus_incoming_signal_data);
    talloc_free(key);

    return data;
}

errno_t
sbus_signal_listen(struct sbus_connection *conn,
                   const char *iface,
                   const char *a_signal,
                   sbus_incoming_signal_fn handler_fn,
                   void *handler_data)
{
    TALLOC_CTX *tmp_ctx;
    const char *rule;
    DBusError error;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    dbus_error_init(&error);

    ret = sbus_incoming_signal_hash_add(conn->incoming_signals, iface,
                                        a_signal, handler_fn, handler_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to register signal handler "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    rule = talloc_asprintf(tmp_ctx, "type='signal',interface='%s',member='%s'",
                           iface, a_signal);
    if (rule == NULL) {
        ret = ENOMEM;
        goto done;
    }

    dbus_bus_add_match(conn->dbus.conn, rule, &error);
    if (dbus_error_is_set(&error)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot add D-Bus match rule, cause: %s\n", error.message);
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Listening to signal %s.%s\n", iface, a_signal);

done:
    dbus_error_free(&error);
    talloc_free(tmp_ctx);

    return ret;
}

static void
sbus_signal_handler_got_caller_id(struct tevent_req *req);

DBusHandlerResult
sbus_signal_handler(DBusConnection *dbus_conn,
                    DBusMessage *message,
                    void *handler_data)
{
    struct tevent_req *req;
    struct sbus_connection *conn;
    struct sbus_incoming_signal *a_signal;
    const char *sender;
    int type;

    type = dbus_message_get_type(message);
    if (type != DBUS_MESSAGE_TYPE_SIGNAL) {
        /* We ignore other types here. */
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    conn = talloc_get_type(handler_data, struct sbus_connection);
    sender = dbus_message_get_sender(message);

    /* we have a valid handler, create D-Bus request */
    a_signal = sbus_new_incoming_signal(conn, message);
    if (a_signal == NULL) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Received D-Bus signal %s.%s\n",
          a_signal->interface, a_signal->signal);

    /* now get the sender ID */
    req = sbus_get_sender_id_send(a_signal, conn->ev, conn, sender);
    if (req == NULL) {
        talloc_free(a_signal);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }
    tevent_req_set_callback(req, sbus_signal_handler_got_caller_id, a_signal);

    return DBUS_HANDLER_RESULT_HANDLED;
}

static void
sbus_signal_handler_got_caller_id(struct tevent_req *req)
{
    struct sbus_incoming_signal_data *signal_data;
    struct sbus_incoming_signal *a_signal;
    errno_t ret;

    a_signal = tevent_req_callback_data(req, struct sbus_incoming_signal);

    ret = sbus_get_sender_id_recv(req, &a_signal->client);
    if (ret == ERR_SBUS_SENDER_BUS) {
        DEBUG(SSSDBG_TRACE_FUNC, "Got a signal from the bus..\n");
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to resolve caller's ID: %s\n", sss_strerror(ret));
        goto done;
    }

    signal_data = sbus_incoming_signal_hash_lookup(
                                            a_signal->conn->incoming_signals,
                                            a_signal->interface,
                                            a_signal->signal);
    if (signal_data == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Received signal %s.%s that we are "
              "not listening to.\n", a_signal->interface, a_signal->signal);
        goto done;
    }

    signal_data->handler_fn(a_signal, signal_data->handler_data);

done:
    talloc_free(a_signal);
}
