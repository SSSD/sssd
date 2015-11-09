/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include <talloc.h>
#include <dbus/dbus.h>
#include <dhash.h>

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_private.h"

static void
sbus_signal_name_owner_changed(struct sbus_incoming_signal *a_signal,
                               void *handler_data)
{
    hash_table_t *table = a_signal->conn->clients;
    hash_key_t *keys;
    unsigned long count;
    unsigned long i;
    int hret;

    DEBUG(SSSDBG_TRACE_FUNC, "Clearing UIDs cache\n");

    hret = hash_keys(table, &count, &keys);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to get hash keys\n");
        return;
    }

    for (i = 0; i < count; i++) {
        hret = hash_delete(table, &keys[i]);
        if (hret != HASH_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not delete key from hash\n");
            return;
        }
    }

    return;
}

struct signals_map {
    const char *iface;
    const char *signal;
    sbus_incoming_signal_fn handler_fn;
    int conn_type;
};

static struct signals_map signals_map[] = {
    { "org.freedesktop.DBus", "NameOwnerChanged",
      sbus_signal_name_owner_changed, SBUS_CONN_TYPE_SYSBUS },
    { NULL, NULL, NULL, 0 },
};

void sbus_register_common_signals(struct sbus_connection *conn, void *pvt)
{
    errno_t ret;
    int i;

    for (i = 0; signals_map[i].iface != NULL; i++) {
        if (signals_map[i].conn_type != conn->connection_type) {
            /* Skip this signal. */
            continue;
        }

        ret = sbus_signal_listen(conn, signals_map[i].iface,
                                 signals_map[i].signal,
                                 signals_map[i].handler_fn, conn);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Unable to register signal %s.%s\n",
                  signals_map[i].iface, signals_map[i].signal);
            continue;
        }
    }
}
