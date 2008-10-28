/*
   SSSD

   SSSD - D-BUS interface

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

#ifndef _SSSD_DBUS_H_
#define _SSSD_DBUS_H_

typedef int (*sssd_dbus_msg_handler_fn)(DBusMessage *msg, void *data,
                                        DBusMessage **reply);

extern int connection_type_slot;

enum {
    DBUS_CONNECTION_TYPE_PRIVATE = 1,
    DBUS_CONNECTION_TYPE_SHARED
};

struct sssd_dbus_method {
    const char *method;
    sssd_dbus_msg_handler_fn fn;
};

struct sssd_dbus_ctx {
    struct event_context *ev;
    char *name;
    char *path;
    struct sssd_dbus_method *methods;
};

/* Server Functions */
int sssd_new_dbus_server(struct sssd_dbus_ctx *ctx, const char *address);

/* Connection Functions */
int sssd_new_dbus_connection(struct sssd_dbus_ctx *ctx, const char *address,
                             DBusConnection **connection);
#endif /* _SSSD_DBUS_H_*/
