/*
   SSSD

   SystemBus Helpers

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#include "talloc.h"
#include "tevent.h"
#include "util/util.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "sysbus.h"
#include "infopipe/infopipe.h"

struct sysbus_ctx {
    struct sbus_conn_ctx *sconn;
    struct sbus_method_ctx *service_methods;
    void *pvt_data;
};

static int sysbus_destructor(TALLOC_CTX *ctx) {
    struct sysbus_ctx *system_bus = talloc_get_type(ctx, struct sysbus_ctx);
    dbus_connection_unref(sbus_get_connection(system_bus->sconn));
    return EOK;
}

static int sysbus_init_methods(TALLOC_CTX *mem_ctx,
                               struct sysbus_ctx *sysbus,
                               const char *interface,
                               const char *path,
                               struct sbus_method *methods,
                               sbus_msg_handler_fn introspect_method,
                               struct sbus_method_ctx **sm_ctx)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    struct sbus_method_ctx *method_ctx;

    tmp_ctx = talloc_new(mem_ctx);
    if(!tmp_ctx) {
        return ENOMEM;
    }

    method_ctx = talloc_zero(tmp_ctx, struct sbus_method_ctx);
    if (!method_ctx) {
        ret = ENOMEM;
        goto done;
    }

    method_ctx->interface = talloc_strdup(method_ctx, interface);
    if (method_ctx->interface == NULL) {
        ret = ENOMEM;
        goto done;
    }

    method_ctx->path = talloc_strdup(method_ctx, path);
    if (method_ctx->path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    method_ctx->methods = methods;
    method_ctx->introspect_fn = introspect_method;
    method_ctx->message_handler = sbus_message_handler;

    *sm_ctx = method_ctx;
    talloc_steal(mem_ctx, method_ctx);

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysbus_init(TALLOC_CTX *mem_ctx, struct sysbus_ctx **sysbus,
                struct tevent_context *ev, const char *dbus_name,
                const char *interface, const char *path,
                struct sbus_method *methods,
                sbus_msg_handler_fn introspect_method)
{
    DBusError dbus_error;
    DBusConnection *conn;
    struct sysbus_ctx *system_bus;
    int ret;

    system_bus = talloc_zero(mem_ctx, struct sysbus_ctx);
    if (system_bus == NULL) {
        return ENOMEM;
    }

    dbus_error_init(&dbus_error);

    /* Connect to the well-known system bus */
    conn = dbus_bus_get(DBUS_BUS_SYSTEM, &dbus_error);
    if (conn == NULL) {
        DEBUG(0, ("Failed to connect to D-BUS system bus.\n"));
        talloc_free(system_bus);
        return EIO;
    }
    dbus_connection_set_exit_on_disconnect(conn, FALSE);

    ret = dbus_bus_request_name(conn,
                                dbus_name,
                                /* We want exclusive access */
                                DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                &dbus_error
                                );
    if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        /* We were unable to register on the system bus */
        DEBUG(0, ("Unable to request name on the system bus. Error: %s\n", dbus_error.message));
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        dbus_connection_unref(conn);
        talloc_free(system_bus);
        return EIO;
    }

    DEBUG(1, ("Listening on %s\n", dbus_name));

    /* Integrate with TEvent loop */
    ret = sbus_add_connection(system_bus, ev, conn, &system_bus->sconn, SBUS_CONN_TYPE_SHARED);
    if (ret != EOK) {
        DEBUG(0, ("Could not integrate D-BUS into mainloop.\n"));
        dbus_connection_unref(conn);
        talloc_free(system_bus);
        return ret;
    }
    talloc_set_destructor((TALLOC_CTX *)system_bus,
                          sysbus_destructor);

    /* Set up methods */
    ret = sysbus_init_methods(system_bus, system_bus, interface, path,
                              methods, introspect_method,
                              &system_bus->service_methods);
    if (ret != EOK) {
        DEBUG(0, ("Could not set up service methods.\n"));
        talloc_free(system_bus);
        return ret;
    }

    ret = sbus_conn_add_method_ctx(system_bus->sconn, system_bus->service_methods);
    if (ret != EOK) {
        DEBUG(0, ("Could not add service methods to the connection.\n"));
        talloc_free(system_bus);
        return ret;
    }

    *sysbus = system_bus;
    return EOK;
}

struct sbus_conn_ctx *sysbus_get_sbus_conn(struct sysbus_ctx *sysbus)
{
    return sysbus->sconn;
}

char *sysbus_get_caller(TALLOC_CTX *mem_ctx, DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    char *caller;
    const char *conn_name;
    DBusError error;
    uid_t uid;

    /* Get the connection UID */
    conn_name = dbus_message_get_sender(message);
    if (conn_name == NULL) {
        DEBUG(0, ("Critical error: D-BUS client has no unique name\n"));
        return NULL;
    }
    dbus_error_init(&error);
    uid = dbus_bus_get_unix_user(sbus_get_connection(sconn), conn_name, &error);
    if (uid == -1) {
        DEBUG(0, ("Could not identify unix user. Error message was '%s:%s'\n", error.name, error.message));
        dbus_error_free(&error);
        return NULL;
    }
    caller = get_username_from_uid(mem_ctx, uid);
    if (caller == NULL) {
        DEBUG(0, ("No username matched the connected UID\n"));
        return NULL;
    }

    return caller;
}
