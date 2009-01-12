/*
   SSSD

   Proxy Module

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
#include "db/sysdb.h"

struct proxy_nss_ops {
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

struct proxy_ctx {
    struct proxy_nss_ops ops;
};

static int get_pw_name(struct be_ctx *be_ctx, struct proxy_ctx *proxy_ctx, char *name)
{
    struct proxy_nss_ops *ops = &proxy_ctx->ops;
    enum nss_status status;
    struct passwd result;
    char *buffer;
    int ret;

    buffer = talloc_size(NULL, 4096);
    if (!buffer) return ENOMEM;

    status = ops->getpwnam_r(name, &result, buffer, 4096, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:
        ret = sysdb_remove_account_posix(be_ctx, be_ctx->sysdb,
                                         be_ctx->domain, name);
        break;
    case NSS_STATUS_SUCCESS:
        ret = sysdb_store_account_posix(be_ctx, be_ctx->sysdb, be_ctx->domain,
                                        result.pw_name, result.pw_passwd,
                                        result.pw_uid, result.pw_gid,
                                        result.pw_gecos, result.pw_dir,
                                        result.pw_shell);
        break;
    default:
        DEBUG(2, ("proxy -> getpwnam_r failed for '%s' (%d)[%s]\n",
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

static int get_pw_uid(struct be_ctx *be_ctx, struct proxy_ctx *proxy_ctx, uid_t uid)
{
    struct proxy_nss_ops *ops = &proxy_ctx->ops;
    enum nss_status status;
    struct passwd result;
    char *buffer;
    int ret;

    buffer = talloc_size(NULL, 4096);
    if (!buffer) return ENOMEM;

    status = ops->getpwuid_r(uid, &result, buffer, 4096, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:
        ret = sysdb_remove_account_posix_by_uid(be_ctx, be_ctx->sysdb,
                                                be_ctx->domain,uid);
        break;
    case NSS_STATUS_SUCCESS:
        ret = sysdb_store_account_posix(be_ctx, be_ctx->sysdb, be_ctx->domain,
                                        result.pw_name, result.pw_passwd,
                                        result.pw_uid, result.pw_gid,
                                        result.pw_gecos, result.pw_dir,
                                        result.pw_shell);
        break;
    default:
        DEBUG(2, ("proxy -> getpwuid_r failed for '%lu' (%d)[%s]\n",
                  (unsigned long)uid, ret, strerror(ret)));
        talloc_free(buffer);
        return ret;
    }

    if (ret != EOK) {
        DEBUG(1, ("Failed to update LDB Cache for '%lu' (%d) !?\n",
                   (unsigned long)uid, ret));
    }

    talloc_free(buffer);
    return ret;
}

static int proxy_check_online(struct be_ctx *be_ctx, int *reply)
{
    *reply = MOD_ONLINE;
    return EOK;
}

static int proxy_get_account_info(struct be_ctx *be_ctx,
                                 int entry_type, int attr_type,
                                 int filter_type, char *filter_value)
{
    struct proxy_ctx *ctx;
    uid_t uid;

    ctx = talloc_get_type(be_ctx->pvt_data, struct proxy_ctx);

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
            switch (attr_type) {
            case BE_ATTR_CORE:
                if (strchr(filter_value, '*')) {
                    return EINVAL;
                } else {
                    char *endptr;
                    errno = 0;
                    uid = (uid_t)strtol(filter_value, &endptr, 0);
                    if (errno || *endptr || (filter_value == endptr)) {
                        return EINVAL;
                    }
                    return get_pw_uid(be_ctx, ctx, uid);
                }
                break;
            default:
                return EINVAL;
            }
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

struct be_mod_ops proxy_mod_ops = {
    .check_online = proxy_check_online,
    .get_account_info = proxy_get_account_info
};

static void *proxy_dlsym(void *handle, const char *functemp, char *libname)
{
    char *funcname;
    void *funcptr;

    funcname = talloc_asprintf(NULL, functemp, libname);
    if (funcname == NULL) return NULL;

    funcptr = dlsym(handle, funcname);
    talloc_free(funcname);

    return funcptr;
}

int sssm_proxy_init(struct be_ctx *bectx, struct be_mod_ops **ops, void **pvt_data)
{
    struct proxy_ctx *ctx;
    char *libname;
    char *libpath;
    void *handle;
    int ret;

    ctx = talloc(bectx, struct proxy_ctx);
    if (!ctx) {
        return ENOMEM;
    }

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                           "libName", NULL, &libname);
    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                           "libPath", NULL, &libpath);
    if (ret != EOK) goto done;
    if (libpath == NULL || libname == NULL) {
        ret = ENOENT;
        goto done;
    }

    handle = dlopen(libpath, RTLD_NOW);
    if (!handle) {
        DEBUG(0, ("Unable to load %s module with path, error: %s\n",
                  libpath, dlerror()));
        ret = ELIBACC;
        goto done;
    }

    ctx->ops.getpwnam_r = proxy_dlsym(handle, "_nss_%s_getpwnam_r", libname);
    if (!ctx->ops.getpwnam_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getpwuid_r = proxy_dlsym(handle, "_nss_%s_getpwuid_r", libname);
    if (!ctx->ops.getpwuid_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.setpwent = proxy_dlsym(handle, "_nss_%s_setpwent", libname);
    if (!ctx->ops.setpwent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getpwent_r = proxy_dlsym(handle, "_nss_%s_getpwent_r", libname);
    if (!ctx->ops.getpwent_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.endpwent = proxy_dlsym(handle, "_nss_%s_endpwent", libname);
    if (!ctx->ops.endpwent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrnam_r = proxy_dlsym(handle, "_nss_%s_getgrnam_r", libname);
    if (!ctx->ops.getgrnam_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrgid_r = proxy_dlsym(handle, "_nss_%s_getgrgid_r", libname);
    if (!ctx->ops.getgrgid_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.setgrent = proxy_dlsym(handle, "_nss_%s_setgrent", libname);
    if (!ctx->ops.setgrent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.getgrent_r = proxy_dlsym(handle, "_nss_%s_getgrent_r", libname);
    if (!ctx->ops.getgrent_r) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.endgrent = proxy_dlsym(handle, "_nss_%s_endgrent", libname);
    if (!ctx->ops.endgrent) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    ctx->ops.initgroups_dyn = proxy_dlsym(handle, "_nss_%s_initgroups_dyn",
                                                  libname);
    if (!ctx->ops.initgroups_dyn) {
        DEBUG(0, ("Failed to load NSS fns, error: %s\n", dlerror()));
        ret = ELIBBAD;
        goto done;
    }

    *ops = &proxy_mod_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}
