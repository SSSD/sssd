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

union dbus_conn_pointer {
    DBusServer *server;
    DBusConnection *conn;
};
enum dbus_conn_type {
    SBUS_SERVER,
    SBUS_CONNECTION
};

struct sbus_interface_p;
struct sbus_watch_ctx;

struct sbus_connection {
    struct tevent_context *ev;

    enum dbus_conn_type type;
    union dbus_conn_pointer dbus;

    char *address;
    int connection_type;
    int disconnect;

    sbus_conn_destructor_fn destructor;
    void *pvt_data; /* Private data for this connection */

    /* dbus tables and handlers */
    struct sbus_interface_p *intf_list;

    /* reconnect settings */
    int retries;
    int max_retries;
    sbus_conn_reconn_callback_fn reconnect_callback;
    /* Private data needed to reinit after reconnection */
    void *reconnect_pvt;

    /* server related stuff */
    char *symlink;
    struct sbus_interface *server_intf;
    sbus_server_conn_init_fn srv_init_fn;
    void *srv_init_data;

    /* watches list */
    struct sbus_watch_ctx *watch_list;
};

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

#endif /* _SSSD_DBUS_PRIVATE_H_ */
