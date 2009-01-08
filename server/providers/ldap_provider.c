/*
   SSSD

   Test LDAP Module

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#include <nss.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include "util/util.h"
#include "providers/dp_backend.h"

struct ldap_nss_ops {
    enum nss_status (*getpwnam_r)(const char *name, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getpwuid_r)(uid_t uid, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*setpwent)(void);
    enum nss_status (*getpwent_r)(struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*endpwent)(void);

    enum nss_status (*getgrnam_r)(const char *name, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getgrgid_r)(gid_t gid, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*setgrent)(void);
    enum nss_status (*getgrent_r)(struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*endgrent)(void);
    enum nss_status (*initgroups_dyn)(const char *user, gid_t group,
                                      long int *start, long int *size,
                                      gid_t **groups, long int limit,
                                      int *errnop);
};

struct ldap_ctx {
    struct ldap_nss_ops ops;
};

static int get_pw_name(struct be_ctx *be_ctx, struct ldap_ctx *ldap_ctx, char *name)
{
    struct ldap_nss_ops *ops = &ldap_ctx->ops;
    enum nss_status status;
    struct passwd result;
    char *buffer;
    int ret;

    buffer = talloc_size(NULL, 4096);
    if (!buffer) return ENOMEM;

    status = ops->getpwnam_r(name, &result, buffer, 4096, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:
        ret = dp_be_remove_account_posix(be_ctx, name);
        break;
    case NSS_STATUS_SUCCESS:
        ret = dp_be_store_account_posix(be_ctx, name, result.pw_passwd,
                                        result.pw_uid, result.pw_gid,
                                        result.pw_gecos, result.pw_dir,
                                        result.pw_shell);
        break;
    default:
        DEBUG(2, ("ldap->getpwnam_r failed for '%s' (%d)[%s]\n",
                  name, ret, strerror(ret)));
        talloc_free(buffer);
        return ret;
    }

    if (ret != EOK) {
        DEBUG(1, ("Failed to update LDB Cache for '%s' (%d) !?\n",
                   name, ret));
    }

    talloc_free(buffer);
    return ret;
}

static int ldap_check_online(struct be_ctx *be_ctx, int *reply)
{
    *reply = MOD_ONLINE;
    return EOK;
}

static int ldap_get_account_info(struct be_ctx *be_ctx,
                                 int entry_type, int attr_type,
                                 int filter_type, char *filter_value)
{
    struct ldap_ctx *ctx;

    ctx = talloc_get_type(be_ctx->pvt_data, struct ldap_ctx);

    switch (entry_type) {
    case BE_REQ_USER: /* user */
        switch (filter_type) {
        case BE_FILTER_NAME:
            switch (attr_type) {
            case BE_ATTR_CORE:
                if (strchr(filter_value, '*')) {
                    /* TODO */
                } else {
                    return get_pw_name(be_ctx, ctx, filter_value);
                }
                break;
            default:
                return EINVAL;
            }
            break;
        case BE_FILTER_IDNUM:
            break;
        default:
            return EINVAL;
        }
        break;

    case BE_REQ_GROUP: /* group */
        /* TODO */
        return EOK;

    default: /*fail*/
        return EINVAL;
    }

    return EOK;
}

struct be_mod_ops ldap_mod_ops = {
    .check_online = ldap_check_online,
    .get_account_info = ldap_get_account_info
};

int sssm_ldap_init(struct be_ctx *bectx, struct be_mod_ops **ops, void **pvt_data)
{
    struct ldap_ctx *ctx;
    void *handle;
    int ret;

    ctx = talloc(bectx, struct ldap_ctx);
    if (!ctx) {
        return ENOMEM;
    }

    handle = dlopen("/usr/lib64/libnss_ldap.so.2", RTLD_NOW);
    if (!handle) {
        DEBUG(0, ("Unable to load libnss_ldap module with path, error: %s\n", dlerror()));
        ret = ELIBACC;
        goto done;
    }

    ctx->ops.getpwnam_r = dlsym(handle, "_nss_ldap_getpwnam_r");
    if (!ctx->ops.getpwnam_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getpwuid_r = dlsym(handle, "_nss_ldap_getpwuid_r");
    if (!ctx->ops.getpwuid_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.setpwent = dlsym(handle, "_nss_ldap_setpwent");
    if (!ctx->ops.setpwent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getpwent_r = dlsym(handle, "_nss_ldap_getpwent_r");
    if (!ctx->ops.getpwent_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.endpwent = dlsym(handle, "_nss_ldap_endpwent");
    if (!ctx->ops.endpwent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrnam_r = dlsym(handle, "_nss_ldap_getgrnam_r");
    if (!ctx->ops.getgrnam_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrgid_r = dlsym(handle, "_nss_ldap_getgrgid_r");
    if (!ctx->ops.getgrgid_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.setgrent = dlsym(handle, "_nss_ldap_setgrent");
    if (!ctx->ops.setgrent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrent_r = dlsym(handle, "_nss_ldap_getgrent_r");
    if (!ctx->ops.getgrent_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.endgrent = dlsym(handle, "_nss_ldap_endgrent");
    if (!ctx->ops.endgrent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.initgroups_dyn = dlsym(handle, "_nss_ldap_initgroups_dyn");
    if (!ctx->ops.initgroups_dyn) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    *ops = &ldap_mod_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}
