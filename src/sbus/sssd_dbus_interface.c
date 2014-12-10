/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_private.h"

DBusObjectPathVTable dbus_object_path_vtable =
    { NULL, sbus_message_handler, NULL, NULL, NULL, NULL };

static char *sbus_iface_get_reg_path(TALLOC_CTX *mem_ctx,
                                     const char *path,
                                     bool fallback)
{
    char *reg_path;

    reg_path = talloc_strdup(mem_ctx, path);
    if (reg_path == NULL) return NULL;

    if (fallback) {
        reg_path[strlen(path)-1] = '\0';
    }
    return reg_path;
}

static bool path_in_interface_list(struct sbus_interface_p *list,
                                   const char *path)
{
    struct sbus_interface_p *iter;

    if (!list || !path) {
        return false;
    }

    iter = list;
    while (iter != NULL) {
        if (strcmp(iter->intf->path, path) == 0) {
            return true;
        }
        iter = iter->next;
    }

    return false;
}

void sbus_unreg_object_paths(struct sbus_connection *conn)
{
    struct sbus_interface_p *iter = conn->intf_list;

    while (iter != NULL) {
        dbus_connection_unregister_object_path(conn->dbus.conn,
                                               iter->intf->path);
        iter = iter->next;
    }
}

static bool sbus_fb_path_has_prefix(const char *path, const char *prefix)
{
    /* strlen-1 because we don't want to match the trailing '*' */
    if (strncmp(path, prefix, strlen(prefix)-1) == 0) {
        return true;
    }

    return false;
}

static bool sbus_path_has_fallback(const char *path)
{
    char *wildcard;

    wildcard = strrchr(path, '*');
    if (wildcard != NULL) {
        /* This path was registered as fallback */
        if (*(wildcard + 1) != '\0') {
            /* Wildcard is only allowed as the last character in the path */
            return false;
        }
        return true;
    }

    return false;
}

bool sbus_iface_handles_path(struct sbus_interface_p *intf_p,
                             const char *path)
{
    if (sbus_path_has_fallback(intf_p->intf->path)) {
        return sbus_fb_path_has_prefix(path, intf_p->intf->path);
    }

    return strcmp(path, intf_p->intf->path) == 0;
}

static struct sbus_interface *
sbus_new_interface(TALLOC_CTX *mem_ctx,
                   const char *object_path,
                   struct sbus_vtable *iface_vtable,
                   void *instance_data)
{
    struct sbus_interface *intf;

    intf = talloc_zero(mem_ctx, struct sbus_interface);
    if (intf == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Cannot allocate a new sbus_interface.\n");
        return NULL;
    }

    intf->path = talloc_strdup(intf, object_path);
    if (intf->path == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Cannot duplicate object path.\n");
        talloc_free(intf);
        return NULL;
    }

    intf->vtable = iface_vtable;
    intf->instance_data = instance_data;
    return intf;
}

int sbus_conn_register_iface(struct sbus_connection *conn,
                             struct sbus_vtable *iface_vtable,
                             const char *object_path,
                             void *pvt)
{
    struct sbus_interface_p *intf_p;
    struct sbus_interface *intf;
    dbus_bool_t dbret;
    const char *path;
    bool fallback;

    intf = sbus_new_interface(conn, object_path, iface_vtable, pvt);
    if (intf == NULL) {
        return ENOMEM;
    }

    if (!conn || !intf->vtable || !intf->vtable->meta) {
        return EINVAL;
    }

    path = intf->path;
    fallback = sbus_path_has_fallback(path);

    if (path_in_interface_list(conn->intf_list, path)) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Cannot add method context with identical path.\n");
        return EINVAL;
    }

    intf_p = talloc_zero(conn, struct sbus_interface_p);
    if (!intf_p) {
        return ENOMEM;
    }
    intf_p->conn = conn;
    intf_p->intf = intf;
    intf_p->reg_path = sbus_iface_get_reg_path(intf_p, path, fallback);
    if (intf_p->reg_path == NULL) {
        return ENOMEM;
    }

    DLIST_ADD(conn->intf_list, intf_p);

    DEBUG(SSSDBG_TRACE_LIBS, "Will register path %s with%s fallback\n",
                             intf_p->reg_path, fallback ? "" : "out");

    if (fallback) {
        dbret = dbus_connection_register_fallback(conn->dbus.conn,
                                                  intf_p->reg_path,
                                                  &dbus_object_path_vtable,
                                                  intf_p);
    } else {
        dbret = dbus_connection_register_object_path(conn->dbus.conn,
                                                     intf_p->reg_path,
                                                     &dbus_object_path_vtable,
                                                     intf_p);
    }
    if (!dbret) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not register object path to the connection.\n");
        return ENOMEM;
    }

    return EOK;
}
