/*
    Authors:
        Simo Sorce <ssorce@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2009 Red Hat

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

#ifndef _SSSD_DBUS_PRIVATE_H_
#define _SSSD_DBUS_PRIVATE_H_

#include <dhash.h>

#include "sssd_dbus_meta.h"

union dbus_conn_pointer {
    DBusServer *server;
    DBusConnection *conn;
};
enum dbus_conn_type {
    SBUS_SERVER,
    SBUS_CONNECTION
};

struct sbus_watch_ctx;

struct sbus_connection {
    struct tevent_context *ev;

    enum dbus_conn_type type;
    union dbus_conn_pointer dbus;

    char *address;
    int connection_type;
    int disconnect;

    hash_table_t *managed_paths;
    hash_table_t *nodes_fns;
    hash_table_t *incoming_signals;

    /* reconnect settings */
    int retries;
    int max_retries;
    sbus_conn_reconn_callback_fn reconnect_callback;
    /* Private data needed to reinit after reconnection */
    void *reconnect_pvt;

    /* server related stuff */
    char *symlink;
    sbus_server_conn_init_fn srv_init_fn;
    void *srv_init_data;
    hash_table_t *clients;

    /* watches list */
    struct sbus_watch_ctx *watch_list;
};

/* =Standard=interfaces=================================================== */

struct sbus_vtable *sbus_introspect_vtable(void);
struct sbus_vtable *sbus_properties_vtable(void);

/* =Watches=============================================================== */

struct sbus_watch_ctx {
    struct sbus_watch_ctx *prev, *next;

    struct sbus_connection *conn;

    struct tevent_fd *fde;
    int fd;

    DBusWatch *dbus_read_watch;
    DBusWatch *dbus_write_watch;
};

dbus_bool_t sbus_add_watch(DBusWatch *watch, void *data);
void sbus_toggle_watch(DBusWatch *watch, void *data);
void sbus_remove_watch(DBusWatch *watch, void *data);

/* =Timeouts============================================================== */

struct sbus_timeout_ctx {
    DBusTimeout *dbus_timeout;
    struct tevent_timer *te;
};

dbus_bool_t sbus_add_timeout(DBusTimeout *dbus_timeout, void *data);
void sbus_toggle_timeout(DBusTimeout *dbus_timeout, void *data);
void sbus_remove_timeout(DBusTimeout *dbus_timeout, void *data);

/* =Requests============================================================== */

struct sbus_request *
sbus_new_request(struct sbus_connection *conn, struct sbus_interface *intf,
                 DBusMessage *message);

/* =Interface=and=object=paths============================================ */

struct sbus_interface_list {
    struct sbus_interface_list *prev, *next;
    struct sbus_interface *interface;
};

errno_t
sbus_opath_hash_init(TALLOC_CTX *mem_ctx,
                     struct sbus_connection *conn,
                     hash_table_t **_table);

struct sbus_interface *
sbus_opath_hash_lookup_iface(hash_table_t *table,
                             const char *object_path,
                             const char *iface_name);

errno_t
sbus_opath_hash_lookup_supported(TALLOC_CTX *mem_ctx,
                                 hash_table_t *table,
                                 const char *object_path,
                                 struct sbus_interface_list **_list);

errno_t
sbus_nodes_hash_init(TALLOC_CTX *mem_ctx,
                     struct sbus_connection *conn,
                     hash_table_t **_table);

const char **
sbus_nodes_hash_lookup(TALLOC_CTX *mem_ctx,
                       hash_table_t *table,
                       const char *object_path);

void
sbus_request_invoke_or_finish(struct sbus_request *dbus_req,
                              sbus_msg_handler_fn handler_fn,
                              void *handler_data,
                              sbus_method_invoker_fn invoker_fn);

/* A low-level, private variant of sbus_conn_send that accepts just
 * DBusConnection. It should never be used outside sbus code, responders
 * and back ends should use sbus_conn_send!
 */
int sss_dbus_conn_send(DBusConnection *dbus_conn,
                       DBusMessage *msg,
                       int timeout_ms,
                       DBusPendingCallNotifyFunction reply_handler,
                       void *pvt,
                       DBusPendingCall **pending);


/* =Retrieve-conn-credentials=============================================== */
struct tevent_req *sbus_get_sender_id_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sbus_connection *conn,
                                           const char *sender);
int sbus_get_sender_id_recv(struct tevent_req *req, int64_t *_uid);

/* =Properties============================================================ */

int sbus_properties_dispatch(struct sbus_request *dbus_req);

/* =Signals=============================================================== */

DBusHandlerResult
sbus_signal_handler(DBusConnection *conn,
                    DBusMessage *message,
                    void *handler_data);

errno_t
sbus_incoming_signal_hash_init(TALLOC_CTX *mem_ctx,
                               hash_table_t **_table);

void sbus_register_common_signals(struct sbus_connection *conn, void *pvt);

#endif /* _SSSD_DBUS_PRIVATE_H_ */
