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

#include "lib/sifp/sss_sifp.h"
#include "lib/sifp/sss_sifp_dbus.h"
#include "lib/sifp/sss_sifp_private.h"
#include "responder/ifp/ifp_iface/ifp_iface.h"

#define SSS_SIFP_ATTR_NAME "name"

static sss_sifp_error
sss_sifp_fetch_object_by_attr(sss_sifp_ctx *ctx,
                              const char *path,
                              const char *iface_find,
                              const char *iface_object,
                              const char *method,
                              int attr_type,
                              const void *attr,
                              sss_sifp_object **_object)
{
    sss_sifp_object *object = NULL;
    char *object_path = NULL;
    sss_sifp_error ret;

    if (method == NULL || attr == NULL || attr_type == DBUS_TYPE_INVALID) {
        return SSS_SIFP_INVALID_ARGUMENT;
    }

    ret = sss_sifp_invoke_find_ex(ctx, path, iface_find, method, &object_path,
                                  attr_type, attr, DBUS_TYPE_INVALID);
    if (ret != SSS_SIFP_OK) {
        goto done;
    }

    ret = sss_sifp_fetch_object(ctx, object_path, iface_object, &object);
    if (ret != SSS_SIFP_OK) {
        goto done;
    }

    *_object = object;

    ret = SSS_SIFP_OK;

done:
    sss_sifp_free_string(ctx, &object_path);

    return ret;
}

static sss_sifp_error
sss_sifp_fetch_object_by_name(sss_sifp_ctx *ctx,
                              const char *path,
                              const char *iface_find,
                              const char *iface_object,
                              const char *method,
                              const char *name,
                              sss_sifp_object **_object)
{
    return sss_sifp_fetch_object_by_attr(ctx, path, iface_find, iface_object,
                                         method, DBUS_TYPE_STRING, &name,
                                         _object);
}

sss_sifp_error
sss_sifp_list_domains(sss_sifp_ctx *ctx,
                      char ***_domains)
{
    sss_sifp_attr **attrs = NULL;
    char **object_paths = NULL;
    char **domains = NULL;
    const char *name = NULL;
    unsigned int size;
    unsigned int i;
    sss_sifp_error ret;

    if (_domains == NULL) {
        return SSS_SIFP_INVALID_ARGUMENT;
    }

    ret = sss_sifp_invoke_list_ex(ctx, IFP_PATH, "org.freedesktop.sssd.infopipe", "Domains",
                                  &object_paths, DBUS_TYPE_INVALID);
    if (ret != SSS_SIFP_OK) {
        goto done;
    }

    /* calculate number of paths acquired and allocate memory for domains */
    for (size = 0; object_paths[size] != NULL; size++);

    domains = _alloc_zero(ctx, char *, size + 1);
    if (domains == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    /* fetch domain name */
    for (i = 0; i < size; i++) {
        ret = sss_sifp_fetch_attr(ctx, object_paths[i], "org.freedesktop.sssd.infopipe.Domains",
                                  SSS_SIFP_ATTR_NAME, &attrs);
        if (ret != SSS_SIFP_OK) {
            goto done;
        }

        ret = sss_sifp_find_attr_as_string(attrs, SSS_SIFP_ATTR_NAME, &name);
        if (ret != SSS_SIFP_OK) {
            goto done;
        }

        domains[i] = sss_sifp_strdup(ctx, name);
        if (domains[i] == NULL) {
            ret = SSS_SIFP_OUT_OF_MEMORY;
            goto done;
        }

        sss_sifp_free_attrs(ctx, &attrs);
    }

    domains[i] = NULL;

    *_domains = domains;

    ret = SSS_SIFP_OK;

done:
    sss_sifp_free_attrs(ctx, &attrs);
    sss_sifp_free_string_array(ctx, &object_paths);

    if (ret != SSS_SIFP_OK) {
        sss_sifp_free_string_array(ctx, &domains);
    }

    return ret;
}

sss_sifp_error
sss_sifp_fetch_domain_by_name(sss_sifp_ctx *ctx,
                              const char *name,
                              sss_sifp_object **_domain)
{
    return sss_sifp_fetch_object_by_name(ctx, IFP_PATH, "org.freedesktop.sssd.infopipe",
                                         "org.freedesktop.sssd.infopipe.Domains", "DomainByName",
                                         name, _domain);
}

sss_sifp_error
sss_sifp_fetch_user_by_uid(sss_sifp_ctx *ctx,
                           uid_t uid,
                           sss_sifp_object **_user)
{
    uint64_t _uid = uid;

    return sss_sifp_fetch_object_by_attr(ctx, IFP_PATH_USERS, "org.freedesktop.sssd.infopipe.Users",
                                         "org.freedesktop.sssd.infopipe.Users.User", "ByID",
                                         DBUS_TYPE_UINT64, &_uid, _user);
}

sss_sifp_error
sss_sifp_fetch_user_by_name(sss_sifp_ctx *ctx,
                            const char *name,
                            sss_sifp_object **_user)
{
    return sss_sifp_fetch_object_by_name(ctx, IFP_PATH_USERS, "org.freedesktop.sssd.infopipe.Users",
                                         "org.freedesktop.sssd.infopipe.Users.User", "ByName",
                                         name, _user);
}
