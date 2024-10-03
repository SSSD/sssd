/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#include "util/util.h"
#include "sbus/sbus_request.h"
#include "sbus/sbus_private.h"
#include "sbus/interface_dbus/sbus_dbus_server.h"

static errno_t
sbus_name_owner_changed(TALLOC_CTX *mem_ctx,
                        struct sbus_request *sbus_req,
                        struct sbus_connection *conn,
                        const char *name,
                        const char *new_owner,
                        const char *old_owner)
{
    DEBUG(SSSDBG_TRACE_ALL, "Name of owner %s has changed from "
          "[%s] to [%s]\n", name, old_owner, new_owner);

    /* Delete any existing sender information since it is now obsolete. */
    sbus_senders_delete(conn->senders, name);

    /* Terminate active request if the owner has disconnected. */
    if (new_owner == NULL || new_owner[0] == '\0') {
        sbus_connection_terminate_member_requests(sbus_req->conn, old_owner);
    }

    return EOK;
}

static errno_t
sbus_name_acquired(TALLOC_CTX *mem_ctx,
                   struct sbus_request *sbus_req,
                   struct sbus_connection *conn,
                   const char *name)
{
    DEBUG(SSSDBG_TRACE_FUNC, "D-Bus name acquired: %s\n", name);

    return EOK;
}

errno_t
sbus_register_standard_signals(struct sbus_connection *conn)
{
    struct sbus_listener listeners[] = SBUS_LISTENERS(
        SBUS_LISTEN_SYNC(org_freedesktop_DBus, NameOwnerChanged,
                         DBUS_PATH_DBUS, sbus_name_owner_changed, conn),
        SBUS_LISTEN_SYNC(org_freedesktop_DBus, NameAcquired,
                         DBUS_PATH_DBUS, sbus_name_acquired, conn)
    );

    return sbus_router_listen_map(conn, listeners);
}
