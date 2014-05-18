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

#include <dbus/dbus.h>
#include <string.h>

#include "lib/sifp/sss_sifp.h"
#include "lib/sifp/sss_sifp_private.h"

void *sss_sifp_alloc_zero(sss_sifp_ctx *ctx, size_t size, size_t num)
{
    void *addr = ctx->alloc_fn(size * num, ctx->alloc_pvt);

    if (addr == NULL) {
        return NULL;
    }

    memset(addr, '\0', size * num);

    return addr;
}

void sss_sifp_set_io_error(sss_sifp_ctx *ctx, DBusError *error)
{
    dbus_error_free(ctx->io_error);
    dbus_error_init(ctx->io_error);
    dbus_set_error(ctx->io_error, error->name, error->message);
}

const char *
sss_sifp_get_iface_for_object(const char *object_path)
{
    int i;
    const char *path;
    static struct {
        const char *path;
        const char *iface;
    } known_types[] = {
        {SSS_SIFP_PATH_IFP "/Components/", SSS_SIFP_IFACE_COMPONENTS},
        {SSS_SIFP_PATH_IFP "/Domains/", SSS_SIFP_IFACE_DOMAINS},
        {SSS_SIFP_PATH_IFP "/Services/", SSS_SIFP_IFACE_SERVICES},
        {SSS_SIFP_PATH_IFP "/Users/", SSS_SIFP_IFACE_USERS},
        {SSS_SIFP_PATH_IFP "/Groups/", SSS_SIFP_IFACE_GROUPS},
        {NULL, NULL}
    };

    for (i = 0; known_types[i].path != NULL; i++) {
        path = known_types[i].path;
        if (strncmp(path, object_path, strlen(path)) == 0) {
            return known_types[i].iface;
        }
    }

    return NULL;
}

char * sss_sifp_strdup(sss_sifp_ctx *ctx, const char *str)
{
    char *result = NULL;
    size_t str_len;

    if (str == NULL) {
        return NULL;
    }

    str_len = strlen(str);
    result = _alloc_zero(ctx, char, str_len + 1);
    if (result == NULL) {
        return NULL;
    }

    strncpy(result, str, str_len);

    return result;
}

char * sss_sifp_strcat(sss_sifp_ctx *ctx, const char *str1, const char *str2)
{
    char *result = NULL;

    if (str1 == NULL) {
        return sss_sifp_strdup(ctx, str2);
    }

    if (str2 == NULL) {
        return sss_sifp_strdup(ctx, str1);
    }

    size_t len = strlen(str1) + strlen(str2) + 1;

    result = _alloc_zero(ctx, char, len);
    if (result == NULL) {
        return NULL;
    }

    strcat(result, str1);
    strcat(result, str2);

    return result;
}
