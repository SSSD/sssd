#ifndef CLIENT_DBUS_H_
#define CLIENT_DBUS_H_
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
#include "dbus/dbus.h"
#include "events.h"

/* Types */
struct dbus_connection_toplevel_context {
    DBusConnection *conn;
    struct event_context *ev;
};

struct dbus_connection_watch_context {
    DBusWatch *watch;
    int fd;
    struct fd_event *fde;
    struct dbus_connection_toplevel_context *top;
};

struct dbus_connection_timeout_context {
    DBusTimeout *timeout;
    struct timed_event *te;
    struct dbus_connection_toplevel_context *top;
};
/* Functions */
int integrate_connection_with_event_loop(struct event_context *event_ctx,
        DBusConnection *dbus_conn);
void dbus_connection_wakeup_main_setup(struct dbus_connection_toplevel_context *dct_ctx);

dbus_bool_t add_connection_watch(DBusWatch *watch, void *data);
void toggle_connection_watch(DBusWatch *watch, void *data);

dbus_bool_t add_connection_timeout(DBusTimeout *timeout, void *data);
void toggle_connection_timeout(DBusTimeout *timeout, void *data);
void dbus_connection_wakeup_main(void *data);

void dbus_connection_read_write_handler(struct event_context *ev, struct fd_event *fde, uint16_t flags, void *ptr);
void dbus_connection_timeout_handler(struct event_context *ev, struct timed_event *te, struct timeval t, void *data);
void dbus_connection_wakeup_main_handler(struct event_context *ev_ctx,
        struct signal_event *se, int signum,
        int count, void *_info, void *data);

void do_dispatch(struct event_context *ev,
        struct timed_event *te,
        struct timeval t, void *ptr);

const char* print_status(int status);
#endif /*CLIENT_DBUS_H_*/
