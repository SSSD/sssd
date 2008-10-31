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
struct dbus_connection_toplevel_context;
typedef int (*sssd_dbus_msg_handler_fn)(DBusMessage *msg, void *data,
                                        DBusMessage **reply);

/*
 * sssd_dbus_connection_destructor_fn
 * Function to be called when a connection is finalized
 */
typedef int (*sssd_dbus_connection_destructor_fn)(
        void *ctx);

/*
 * sssd_dbus_server_connection_init_fn
 * Set up function for connection-specific activities
 * This function should define the sssd_dbus_connection_destructor_fn
 * for this connection at a minimum
 */
typedef int (*sssd_dbus_server_connection_init_fn)(
        struct dbus_connection_toplevel_context *dct_ctx);

extern int connection_type_slot;

enum {
    DBUS_CONNECTION_TYPE_PRIVATE = 1,
    DBUS_CONNECTION_TYPE_SHARED
};

struct sssd_dbus_method {
    const char *method;
    sssd_dbus_msg_handler_fn fn;
};

struct sssd_dbus_method_ctx {
    struct sssd_dbus_method_ctx *prev, *next;
    /*struct event_context *ev;*/
    char *interface;
    char *path;
    
    /* If a non-default message_handler is desired, set it in this
     * object before calling dbus_connection_add_method_ctx()
     * Otherwise it will default to message_handler() in
     * sssd_dbus_connection.c
     */
    DBusObjectPathMessageFunction message_handler;
    struct sssd_dbus_method *methods;
};

/* Server Functions */
int sssd_new_dbus_server(struct event_context *ev, struct sssd_dbus_method_ctx *ctx, const char *address, sssd_dbus_server_connection_init_fn init_fn);

/* Connection Functions */
int sssd_new_dbus_connection(TALLOC_CTX *ctx, struct event_context *ev, const char *address,
                             struct dbus_connection_toplevel_context **dct_ctx, 
                             sssd_dbus_connection_destructor_fn destructor);

void sssd_dbus_connection_set_destructor(struct dbus_connection_toplevel_context *dct_ctx,
        sssd_dbus_connection_destructor_fn destructor);
int default_connection_destructor(void *ctx);

DBusConnection *sssd_get_dbus_connection(struct dbus_connection_toplevel_context *dct_ctx);
void sssd_dbus_disconnect (struct dbus_connection_toplevel_context *dct_ctx);
void sssd_connection_set_private_data(struct dbus_connection_toplevel_context *dct_ctx, void *private);
int dbus_connection_add_method_ctx(struct dbus_connection_toplevel_context *dct_ctx, struct sssd_dbus_method_ctx *method_ctx);

#endif /* _SSSD_DBUS_H_*/
