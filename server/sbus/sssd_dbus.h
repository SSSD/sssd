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

struct sbus_connection;

#include "dbus/dbus.h"

typedef int (*sbus_msg_handler_fn)(DBusMessage *, struct sbus_connection *);

/*
 * sbus_conn_destructor_fn
 * Function to be called when a connection is finalized
 */
typedef int (*sbus_conn_destructor_fn)(void *);

typedef void (*sbus_conn_reconn_callback_fn)(struct sbus_connection *, int, void *);

/*
 * sbus_server_conn_init_fn
 * Set up function for connection-specific activities
 * This function should define the sbus_conn_destructor_fn
 * for this connection at a minimum
 */
typedef int (*sbus_server_conn_init_fn)(struct sbus_connection *, void *);

enum {
    SBUS_CONN_TYPE_PRIVATE = 1,
    SBUS_CONN_TYPE_SHARED
};

enum {
    SBUS_RECONNECT_SUCCESS = 1,
    SBUS_RECONNECT_EXCEEDED_RETRIES,
    SBUS_RECONNECT_ERROR
};

/* Special interface and method for D-BUS introspection */
#define DBUS_INTROSPECT_INTERFACE "org.freedesktop.DBus.Introspectable"
#define DBUS_INTROSPECT_METHOD "Introspect"

#define SBUS_DEFAULT_VTABLE { NULL, sbus_message_handler, NULL, NULL, NULL, NULL }

struct sbus_method {
    const char *method;
    sbus_msg_handler_fn fn;
};

struct sbus_interface {
    const char *interface;
    const char *path;
    DBusObjectPathVTable vtable;
    struct sbus_method *methods;
    sbus_msg_handler_fn introspect_fn;
};

/* Server Functions */
int sbus_new_server(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    const char *address,
                    struct sbus_interface *intf,
                    struct sbus_connection **server,
                    sbus_server_conn_init_fn init_fn, void *init_pvt_data);

/* Connection Functions */

/* sbus_new_connection
 * Use this function when connecting a new process to
 * the standard SSSD interface.
 * This will connect to the address specified and then
 * call sbus_add_connection to integrate with the main
 * loop.
 */
int sbus_new_connection(TALLOC_CTX *ctx,
                        struct tevent_context *ev,
                        const char *address,
                        struct sbus_interface *intf,
                        struct sbus_connection **conn);

/* sbus_add_connection
 * Integrates a D-BUS connection with the TEvent main
 * loop. Use this function when you already have a
 * DBusConnection object (for example from dbus_bus_get)
 * Connection type can be either:
 * SBUS_CONN_TYPE_PRIVATE: Used only from within a D-BUS
 *     server such as the Monitor in the
 *     new_connection_callback
 * SBUS_CONN_TYPE_SHARED: Used for all D-BUS client
 *     connections, including those retrieved from
 *     dbus_bus_get
 */
int sbus_init_connection(TALLOC_CTX *ctx,
                         struct tevent_context *ev,
                         DBusConnection *dbus_conn,
                         struct sbus_interface *intf,
                         int connection_type,
                         struct sbus_connection **_conn);

void sbus_conn_set_destructor(struct sbus_connection *conn,
                              sbus_conn_destructor_fn destructor);

int sbus_default_connection_destructor(void *ctx);

DBusConnection *sbus_get_connection(struct sbus_connection *conn);
void sbus_disconnect(struct sbus_connection *conn);
void sbus_conn_set_private_data(struct sbus_connection *conn, void *pvt_data);
void *sbus_conn_get_private_data(struct sbus_connection *conn);
int sbus_conn_add_interface(struct sbus_connection *conn,
                            struct sbus_interface *intf);
bool sbus_conn_disconnecting(struct sbus_connection *conn);

/* max_retries < 0: retry forever
 * max_retries = 0: never retry (why are you calling this function?)
 * max_retries > 0: obvious
 */
void sbus_reconnect_init(struct sbus_connection *conn,
                         int max_retries,
                         sbus_conn_reconn_callback_fn callback,
                         void *pvt);

/* Default message handler
 * Should be usable for most cases */
DBusHandlerResult sbus_message_handler(DBusConnection *conn,
                                  DBusMessage *message,
                                  void *user_data);

void sbus_conn_send_reply(struct sbus_connection *conn,
                          DBusMessage *reply);

int sbus_is_dbus_fixed_type(int dbus_type);
int sbus_is_dbus_string_type(int dbus_type);
size_t sbus_get_dbus_type_size(int dbus_type);
#endif /* _SSSD_DBUS_H_*/
