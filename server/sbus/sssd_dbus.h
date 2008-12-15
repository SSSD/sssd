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

struct sbus_conn_ctx;
struct sbus_srv_ctx;

#include "dbus/dbus.h"

typedef int (*sbus_msg_handler_fn)(DBusMessage *, void *, DBusMessage **);

/*
 * sbus_conn_destructor_fn
 * Function to be called when a connection is finalized
 */
typedef int (*sbus_conn_destructor_fn)(void *);

/*
 * sbus_server_conn_init_fn
 * Set up function for connection-specific activities
 * This function should define the sbus_conn_destructor_fn
 * for this connection at a minimum
 */
typedef int (*sbus_server_conn_init_fn)(struct sbus_conn_ctx *, void *);

enum {
    SBUS_CONN_TYPE_PRIVATE = 1,
    SBUS_CONN_TYPE_SHARED
};

struct sbus_method {
    const char *method;
    sbus_msg_handler_fn fn;
};

struct sbus_method_ctx {
    struct sbus_method_ctx *prev, *next;
    char *interface;
    char *path;
    DBusObjectPathMessageFunction message_handler;
    struct sbus_method *methods;
};

struct sbus_message_handler_ctx {
    struct sbus_conn_ctx *conn_ctx;
    struct sbus_method_ctx *method_ctx;
};

/* Server Functions */
int sbus_new_server(TALLOC_CTX *mem_ctx,
                    struct event_context *ev, struct sbus_method_ctx *ctx,
                    struct sbus_srv_ctx **server_ctx, const char *address,
                    sbus_server_conn_init_fn init_fn, void *init_pvt_data);

/* Connection Functions */
int sbus_new_connection(TALLOC_CTX *ctx, struct event_context *ev,
                        const char *address,
                        struct sbus_conn_ctx **conn_ctx,
                        sbus_conn_destructor_fn destructor);

void sbus_conn_set_destructor(struct sbus_conn_ctx *conn_ctx,
                              sbus_conn_destructor_fn destructor);

int sbus_default_connection_destructor(void *ctx);

DBusConnection *sbus_get_connection(struct sbus_conn_ctx *conn_ctx);
void sbus_disconnect(struct sbus_conn_ctx *conn_ctx);
void sbus_conn_set_private_data(struct sbus_conn_ctx *conn_ctx, void *pvt_data);
void *sbus_conn_get_private_data(struct sbus_conn_ctx *conn_ctx);
int sbus_conn_add_method_ctx(struct sbus_conn_ctx *conn_ctx,
                             struct sbus_method_ctx *method_ctx);

/* Default message handler
 * Should be usable for most cases */
DBusHandlerResult sbus_message_handler(DBusConnection *conn,
                                  DBusMessage *message,
                                  void *user_data);

#endif /* _SSSD_DBUS_H_*/
