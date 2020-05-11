/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include <errno.h>
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/connection/sbus_dbus_private.h"

static errno_t
sbus_dbus_request_name(DBusConnection *dbus_conn, const char *name)
{
    DBusError dbus_error;
    errno_t ret;
    int flags;
    int dbret;

    dbus_error_init(&dbus_error);

    /* We are interested only in being the primary owner of this name. */
    flags = DBUS_NAME_FLAG_DO_NOT_QUEUE;

    dbret = dbus_bus_request_name(dbus_conn, name, flags, &dbus_error);
    if (dbret == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to request name on the "
              "system bus [%s]: %s\n", dbus_error.name, dbus_error.message);
        ret = EIO;
        goto done;
    } else if (dbret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to request name on the "
              "system bus [%d]\n", dbret);
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    dbus_error_free(&dbus_error);

    return ret;
}

DBusConnection *
sbus_dbus_connect_bus(DBusBusType bus, const char *name)
{
    DBusConnection *dbus_conn;
    DBusError dbus_error;
    const char *busname = "not-set";
    errno_t ret;

    switch (bus) {
    case DBUS_BUS_SESSION:
        busname = "session";
        break;
    case DBUS_BUS_SYSTEM:
        busname = "system";
        break;
    case DBUS_BUS_STARTER:
        busname = "starter";
        break;
    }

    dbus_error_init(&dbus_error);

    /* Connect to the system bus. */
    dbus_conn = dbus_bus_get(bus, &dbus_error);
    if (dbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to connect to %s bus [%s]: %s\n",
              busname, dbus_error.name, dbus_error.message);
        ret = EIO;
        goto done;
    }

    if (name != NULL) {
        /* Request a well-known name. */
        ret = sbus_dbus_request_name(dbus_conn, name);
        if (ret != EOK) {
            dbus_connection_unref(dbus_conn);
            goto done;
        }
    }

    if (name == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Connected to %s bus as anonymous\n", busname);
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Connected to %s bus as %s\n", busname, name);
    }

    ret = EOK;

done:
    dbus_error_free(&dbus_error);

    if (ret != EOK) {
        return NULL;
    }

    return dbus_conn;
}

DBusConnection *
sbus_dbus_connect_address(const char *address, const char *name, bool init)
{
    DBusConnection *dbus_conn;
    DBusError dbus_error;
    dbus_bool_t dbret;
    errno_t ret;

    if (address == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Can not connect to an empty address!\n");
        return NULL;
    }

    dbus_error_init(&dbus_error);

    dbus_conn = dbus_connection_open(address, &dbus_error);
    if (dbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to connect to %s [%s]: %s\n",
              address, dbus_error.name, dbus_error.message);
        ret = EIO;
        goto done;
    }

    if (!init) {
        ret = EOK;
        goto done;
    }

    dbret = dbus_bus_register(dbus_conn, &dbus_error);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to register to %s [%s]: %s\n",
              address, dbus_error.name, dbus_error.message);
        ret = EIO;
        goto done;
    }

    /* Request a well-known name. */
    if (name != NULL) {
        ret = sbus_dbus_request_name(dbus_conn, name);
        if (ret != EOK) {
            goto done;
        }
    }

    if (name == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Connected to %s bus as anonymous\n", address);
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Connected to %s bus as %s\n", address, name);
    }

    ret = EOK;

done:
    dbus_error_free(&dbus_error);
    if (ret != EOK && dbus_conn != NULL) {
        dbus_connection_unref(dbus_conn);
        dbus_conn = NULL;
    }

    return dbus_conn;
}
