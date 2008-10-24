/*
   SSSD

   Service monitor - D-BUS features

   Copyright (C) Stephen Gallagher         2008

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

#ifndef MONITORDBUS_H_
#define MONITORDBUS_H_

#include "dbus/dbus.h"
#include "monitor.h"
#include "events.h"
#include "sssd_dbus_common.h"

/* Types */
struct dbus_server_toplevel_context {
    DBusServer *server;
    struct event_context *ev;
    void (*server_connection_setup)(DBusConnection *conn, struct event_context *);
};

struct dbus_server_watch_context {
    DBusWatch *watch;
    int fd;
    struct fd_event *fde;
    struct dbus_server_toplevel_context *top;
};

struct dbus_server_timeout_context {
    DBusTimeout *timeout;
    struct timed_event *te;
    struct dbus_server_toplevel_context *top;
};

/* Functions */
int integrate_server_with_event_loop(
        struct event_context *event_ctx,
        DBusServer *dbus_server,
        void (*server_connection_setup)(DBusConnection *conn, struct event_context *)
);

void new_connection_callback(DBusServer *server,
        DBusConnection *new_connection, void *data);

dbus_bool_t add_server_watch(DBusWatch *watch, void *data);
void toggle_server_watch(DBusWatch *watch, void *data);

dbus_bool_t add_server_timeout(DBusTimeout *timeout, void *data);
void toggle_server_timeout(DBusTimeout *timeout, void *data);

void dbus_server_read_write_handler(struct event_context *ev, struct fd_event *fde, uint16_t flags, void *ptr);
void dbus_server_timeout_handler(struct event_context *ev, struct timed_event *te, struct timeval t, void *data);

#endif /*MONITORDBUS_H_*/
