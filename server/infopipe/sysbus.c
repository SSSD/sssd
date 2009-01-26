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
    DBusConnection *conn;
    struct sbus_method_ctx *method_ctx_list;
    void *pvt_data;
};

static int sysbus_destructor(TALLOC_CTX *ctx) {
    struct sysbus_ctx *system_bus = talloc_get_type(ctx, struct sysbus_ctx);
    dbus_connection_unref(system_bus->conn);
    return EOK;
}

int sysbus_init(TALLOC_CTX *mem_ctx, struct sysbus_ctx **sysbus, struct sbus_method *methods)
{
    DBusError dbus_error;
    struct sysbus_ctx *system_bus;
    int ret;

    system_bus = talloc_zero(mem_ctx, struct sysbus_ctx);
    if (system_bus == NULL) {
        return ENOMEM;
    }

    dbus_error_init(&dbus_error);

    /* Connect to the well-known system bus */
    system_bus->conn = dbus_bus_get(DBUS_BUS_SYSTEM, &dbus_error);
    if (system_bus->conn == NULL) {
        DEBUG(0, ("Failed to connect to D-BUS system bus.\n"));
        talloc_free(system_bus);
        return EIO;
    }
    dbus_connection_set_exit_on_disconnect(system_bus->conn, FALSE);
    talloc_set_destructor((TALLOC_CTX *)system_bus,
                          sysbus_destructor);

    ret = dbus_bus_request_name(system_bus->conn,
                                INFOPIPE_DBUS_NAME,
                                /* We want exclusive access */
                                DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                &dbus_error
                                );
    if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        /* We were unable to register on the system bus */
        DEBUG(0, ("Unable to request name on the system bus. Error: %s\n", dbus_error.message));
        talloc_free(system_bus);
        return EIO;
    }

    DEBUG(1, ("Listening on %s\n", INFOPIPE_DBUS_NAME));

    *sysbus = system_bus;
    return EOK;
}

int sysbus_get_param(DBusMessage *message, void *data, DBusMessage **r) {
    /* TODO: remove this */
    DEBUG(0, ("Received message. Printing this garbage.\n"));
    return EOK;
}
