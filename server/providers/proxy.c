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

static void proxy_reply(struct be_req *req, int error, const char *errstr)
{
    return req->fn(req, error, errstr);
}

static void get_pw_name(struct be_req *req, char *name)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct passwd result;
    char *buffer;
    int ret;

    ctx = talloc_get_type(req->be_ctx->pvt_data, struct proxy_ctx);

    buffer = talloc_size(req, 4096);
    if (!buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.getpwnam_r(name, &result, buffer, 4096, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:
        ret = sysdb_delete_user(req, req->be_ctx->sysdb,
                                req->be_ctx->domain, name);
        break;
    case NSS_STATUS_SUCCESS:
        ret = sysdb_legacy_store_user(req, req->be_ctx->sysdb,
                                     req->be_ctx->domain,
                                     result.pw_name, result.pw_passwd,
                                     result.pw_uid, result.pw_gid,
                                     result.pw_gecos, result.pw_dir,
                                     result.pw_shell);
        break;
    default:
        DEBUG(2, ("proxy -> getpwnam_r failed for '%s' (%d)[%s]\n",
                  name, ret, strerror(ret)));
        talloc_free(buffer);
        return proxy_reply(req, ret, "Operation failed");
    }

    if (ret != EOK) {
        DEBUG(1, ("Failed to update LDB Cache for '%s' (%d) !?\n",
                   name, ret));
        talloc_free(buffer);
        return proxy_reply(req, ret, "Operation failed");
    }

    talloc_free(buffer);
    return proxy_reply(req, EOK, NULL);
}

static void get_pw_uid(struct be_req *req, uid_t uid)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct passwd result;
    char *buffer;
    int ret;

    ctx = talloc_get_type(req->be_ctx->pvt_data, struct proxy_ctx);

    buffer = talloc_size(req, 4096);
    if (!buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.getpwuid_r(uid, &result, buffer, 4096, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:
        ret = sysdb_delete_user_by_uid(req, req->be_ctx->sysdb,
                                       req->be_ctx->domain,uid);
        break;
    case NSS_STATUS_SUCCESS:
        ret = sysdb_legacy_store_user(req, req->be_ctx->sysdb,
                                     req->be_ctx->domain,
                                     result.pw_name, result.pw_passwd,
                                     result.pw_uid, result.pw_gid,
                                     result.pw_gecos, result.pw_dir,
                                     result.pw_shell);
        break;
    default:
        DEBUG(2, ("proxy -> getpwuid_r failed for '%lu' (%d)[%s]\n",
                  (unsigned long)uid, ret, strerror(ret)));
        talloc_free(buffer);
        return proxy_reply(req, ret, "Operation failed");
    }

    if (ret != EOK) {
        DEBUG(1, ("Failed to update LDB Cache for '%lu' (%d) !?\n",
                   (unsigned long)uid, ret));
        talloc_free(buffer);
        return proxy_reply(req, ret, "Operation failed");
    }

    talloc_free(buffer);
    return proxy_reply(req, EOK, NULL);
}

#define MAX_BUF_SIZE 1024*1024 /* max 1MiB */

static void enum_users(struct be_req *req)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct passwd result;
    char *buffer, *newb;
    size_t buflen;
    const char *errstr;
    int ret;

    ctx = talloc_get_type(req->be_ctx->pvt_data, struct proxy_ctx);

    buflen = 4096;
    buffer = talloc_size(req, buflen);
    if (!buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.setpwent();
    if (status != NSS_STATUS_SUCCESS)
        return proxy_reply(req, EIO, "Operation failed");

    while (status == NSS_STATUS_SUCCESS) {

        status = ctx->ops.getpwent_r(&result, buffer, buflen, &ret);

        switch (status) {
        case NSS_STATUS_TRYAGAIN:
            /* buffer too small ? */
            if (buflen < MAX_BUF_SIZE) {
                buflen *= 2;
            }
            if (buflen > MAX_BUF_SIZE) {
                buflen = MAX_BUF_SIZE;
            }
            newb = talloc_realloc_size(NULL, buffer, buflen);
            if (!newb) {
                errstr = "Out of memory";
                ret = ENOMEM;
                goto done;
            }
            buffer = newb;
            status = NSS_STATUS_SUCCESS;
            break;

        case NSS_STATUS_NOTFOUND:
            /* we got last one */
            break;

        case NSS_STATUS_SUCCESS:
            ret = sysdb_legacy_store_user(req, req->be_ctx->sysdb,
                                         req->be_ctx->domain,
                                         result.pw_name, result.pw_passwd,
                                         result.pw_uid, result.pw_gid,
                                         result.pw_gecos, result.pw_dir,
                                         result.pw_shell);
            if (ret != EOK) {
                DEBUG(1, ("Failed to update LDB Cache for '%s' (%d)[%s] !?\n",
                           (unsigned long)result.pw_name, ret, strerror(ret)));
            }
            break;

        default:
            DEBUG(2, ("proxy -> getpwent_r failed (%d)[%s]\n",
                      ret, strerror(ret)));
            errstr = "Operation failed";
            goto done;
        }
    }

    errstr = NULL;
    ret = EOK;

done:
    talloc_free(buffer);
    ctx->ops.endpwent();
    return proxy_reply(req, ret, errstr);
}

static void get_gr_name(struct be_req *req, char *name)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct group result;
    char *buffer;
    int ret;

    ctx = talloc_get_type(req->be_ctx->pvt_data, struct proxy_ctx);

    buffer = talloc_size(NULL, 4096);
    if (!buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.getgrnam_r(name, &result, buffer, 4096, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:
        ret = sysdb_delete_group(req, req->be_ctx->sysdb,
                                 req->be_ctx->domain, name);
        break;
    case NSS_STATUS_SUCCESS:
        ret = sysdb_legacy_store_group(req, req->be_ctx->sysdb,
                                       req->be_ctx->domain, result.gr_name,
                                       result.gr_gid, result.gr_mem);
        break;
    default:
        DEBUG(2, ("proxy -> getgrnam_r failed for '%s' (%d)[%s]\n",
                  name, ret, strerror(ret)));
        talloc_free(buffer);
        return proxy_reply(req, ret, "Operation failed");
    }

    if (ret != EOK) {
        DEBUG(1, ("Failed to update LDB Cache for '%s' (%d) !?\n",
                   name, ret));
        talloc_free(buffer);
        return proxy_reply(req, ret, "Operation failed");
    }

    talloc_free(buffer);
    return proxy_reply(req, EOK, NULL);
}

static void get_gr_gid(struct be_req *req, gid_t gid)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct group result;
    char *buffer;
    int ret;

    ctx = talloc_get_type(req->be_ctx->pvt_data, struct proxy_ctx);

    buffer = talloc_size(req, 4096);
    if (!buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.getgrgid_r(gid, &result, buffer, 4096, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:
        ret = sysdb_delete_group_by_gid(req, req->be_ctx->sysdb,
                                        req->be_ctx->domain, gid);
        break;
    case NSS_STATUS_SUCCESS:
        ret = sysdb_legacy_store_group(req, req->be_ctx->sysdb,
                                       req->be_ctx->domain, result.gr_name,
                                       result.gr_gid, result.gr_mem);
        break;
    default:
        DEBUG(2, ("proxy -> getgrgid_r failed for '%lu' (%d)[%s]\n",
                  (unsigned long)gid, ret, strerror(ret)));
        talloc_free(buffer);
        return proxy_reply(req, ret, "Operation failed");
    }

    if (ret != EOK) {
        DEBUG(1, ("Failed to update LDB Cache for '%lu' (%d) !?\n",
                   (unsigned long)gid, ret));
        talloc_free(buffer);
        return proxy_reply(req, ret, "Operation failed");
    }

    talloc_free(buffer);
    return proxy_reply(req, EOK, NULL);
}

static void enum_groups(struct be_req *req)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct group result;
    char *buffer, *newb;
    size_t buflen;
    const char * errstr;
    int ret, c;

    ctx = talloc_get_type(req->be_ctx->pvt_data, struct proxy_ctx);

    buflen = 4096;
    buffer = talloc_size(req, buflen);
    if (!buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.setgrent();
    if (status != NSS_STATUS_SUCCESS)
        return proxy_reply(req, EIO, "Operation failed");

    c = 0;
    while (status == NSS_STATUS_SUCCESS) {

        status = ctx->ops.getgrent_r(&result, buffer, buflen, &ret);

        switch (status) {
        case NSS_STATUS_TRYAGAIN:
            DEBUG(20, ("Try Again\n"));

            if (ret != ERANGE) {
                DEBUG(2, ("getgrent_r failed (TRYAGAIN)(%d)[%s]\n",
                          ret, strerror(ret)));
                errstr = "Operation failed";
                goto done;
            }
            /* buffer too small ? */
            if (buflen < MAX_BUF_SIZE) {
                buflen *= 2;
            }
            if (buflen > MAX_BUF_SIZE) {
                buflen = MAX_BUF_SIZE;
            }
            newb = talloc_realloc_size(req, buffer, buflen);
            if (!newb) {
                DEBUG(4, ("Out of memory\n"));
                errstr = "Out of memory";
                ret = ENOMEM;
                goto done;
            }
            buffer = newb;
            status = NSS_STATUS_SUCCESS;
            break;

        case NSS_STATUS_NOTFOUND:
            DEBUG(6, ("No more entries\n"));
            /* we got last one */
            break;

        case NSS_STATUS_SUCCESS:
            c++;
            DEBUG(20, ("Storing group [%s](%d)\n", result.gr_name, c));
            ret = sysdb_legacy_store_group(req, req->be_ctx->sysdb,
                                           req->be_ctx->domain, result.gr_name,
                                           result.gr_gid, result.gr_mem);
            if (ret != EOK) {
                DEBUG(1, ("Failed to update LDB Cache for '%s' (%d)[%s] !?\n",
                           (unsigned long)result.gr_name, ret, strerror(ret)));
            }
            break;

        default:
            DEBUG(2, ("getgrent_r failed (%d)[%s]\n", ret, strerror(ret)));
            errstr = "Operation failed";
            goto done;
        }
    }

    errstr = NULL;
    ret = EOK;

done:
    talloc_free(buffer);
    ctx->ops.endgrent();
    return proxy_reply(req, ret, errstr);
}

static int save_initgroups(struct be_req *req, gid_t *gids, long int num)
{
    struct proxy_ctx *ctx;
    struct sysdb_ctx *sysdb;
    enum nss_status status;
    struct group result;
    char *buffer;
    int i, ret;

    ctx = talloc_get_type(req->be_ctx->pvt_data, struct proxy_ctx);
    sysdb = req->be_ctx->sysdb;

    buffer = talloc_size(req, 4096);
    if (!buffer) {
        return ENOMEM;
    }

    for (i = 0; i < num; i++) {

        status = ctx->ops.getgrgid_r(gids[i], &result, buffer, 4096, &ret);

        switch (status) {
            case NSS_STATUS_NOTFOUND:
                DEBUG(4, ("gid [%lu] not found, removing group\n"));
                ret = sysdb_delete_group_by_gid(req, sysdb,
                                                req->be_ctx->domain,
                                                gids[i]);
            break;

        case NSS_STATUS_SUCCESS:
                ret = sysdb_legacy_store_group(req, sysdb,
                                               req->be_ctx->domain,
                                               result.gr_name,
                                               result.gr_gid,
                                               result.gr_mem);
            break;

        default:
            DEBUG(2, ("proxy -> getgrgid_r failed for '%lu' (%d)[%s]\n",
                      (unsigned long)(gids[i]), ret, strerror(ret)));
            break;
        }
    }

    talloc_free(buffer);
    return EOK;
}

static void get_user_groups(struct be_req *req, char *name)
{
    struct proxy_ctx *ctx;
    enum nss_status status;
    struct passwd result;
    char *buffer;
    gid_t *groups;
    long int limit;
    long int start;
    long int size;
    long int num;
    int ret;

    ctx = talloc_get_type(req->be_ctx->pvt_data, struct proxy_ctx);

    buffer = talloc_size(req, 4096);
    if (!buffer)
        return proxy_reply(req, ENOMEM, "Out of memory");

    status = ctx->ops.getpwnam_r(name, &result, buffer, 4096, &ret);

    switch (status) {
    case NSS_STATUS_NOTFOUND:
        ret = sysdb_delete_user(req, req->be_ctx->sysdb,
                                req->be_ctx->domain, name);
        break;
    case NSS_STATUS_SUCCESS:
        ret = sysdb_legacy_store_user(req, req->be_ctx->sysdb,
                                     req->be_ctx->domain,
                                     result.pw_name, result.pw_passwd,
                                     result.pw_uid, result.pw_gid,
                                     result.pw_gecos, result.pw_dir,
                                     result.pw_shell);
        if (ret != EOK) break;

        /* FIXME: let's start with 4k entries */
        start = 0;
        limit = 4096;
        num = 4096;

        size = num*sizeof(gid_t);
        groups = talloc_size(req, size);
        if (!groups) {
            talloc_free(buffer);
            return proxy_reply(req, ENOMEM, "Out of memory");
        }

        status = ctx->ops.initgroups_dyn(result.pw_name, result.pw_gid,
                                         &start, &num, &groups, limit, &ret);
        switch (status) {
        case NSS_STATUS_SUCCESS:

            if (ret == EOK) {
                DEBUG(4, ("User [%s] appears to be member of %lu groups\n",
                          result.pw_name, start));
                /* start is moved up by the number of groups retrieved,
                 * therefore represents the number of users to pass on */
                ret = save_initgroups(req, groups, start);
            }

            break;

        default:
            DEBUG(2, ("proxy -> initgroups_dyn failed for '%s' (%d)[%s]\n",
                      name, ret, strerror(ret)));
            talloc_free(buffer);
            return proxy_reply(req, ret, "Operation failed");
        }
        break;

    default:
        DEBUG(2, ("proxy -> getpwnam_r failed for '%s' (%d)[%s]\n",
                  name, ret, strerror(ret)));
        talloc_free(buffer);
        return proxy_reply(req, ret, "Operation failed");
    }

    if (ret != EOK) {
        DEBUG(1, ("Failed to update LDB Cache for '%s' (%d) !?\n",
                   name, ret));
        talloc_free(buffer);
        return proxy_reply(req, ret, "Operation failed");
    }

    talloc_free(buffer);
    return proxy_reply(req, EOK, NULL);
}

/* TODO: actually do check something */
static void proxy_check_online(struct be_req *req)
{
    struct be_online_req *oreq;

    oreq = talloc_get_type(req->req_data, struct be_online_req);

    oreq->online = MOD_ONLINE;

    req->fn(req, EOK, NULL);
}

/* TODO: See if we can use async_req code */
static void proxy_get_account_info(struct be_req *req)
{
    struct be_acct_req *ar;
    uid_t uid;
    gid_t gid;

    ar = talloc_get_type(req->req_data, struct be_acct_req);

    switch (ar->entry_type) {
    case BE_REQ_USER: /* user */
        switch (ar->filter_type) {
        case BE_FILTER_NAME:
            switch (ar->attr_type) {
            case BE_ATTR_CORE:
                if (strchr(ar->filter_value, '*')) {
                    return enum_users(req);
                } else {
                    return get_pw_name(req, ar->filter_value);
                }
                break;
            default:
                return proxy_reply(req, EINVAL, "Invalid attr type");
            }
            break;
        case BE_FILTER_IDNUM:
            switch (ar->attr_type) {
            case BE_ATTR_CORE:
                if (strchr(ar->filter_value, '*')) {
                    return proxy_reply(req, EINVAL, "Invalid attr type");
                } else {
                    char *endptr;
                    errno = 0;
                    uid = (uid_t)strtol(ar->filter_value, &endptr, 0);
                    if (errno || *endptr || (ar->filter_value == endptr)) {
                        return proxy_reply(req, EINVAL, "Invalid attr type");
                    }
                    return get_pw_uid(req, uid);
                }
                break;
            default:
                return proxy_reply(req, EINVAL, "Invalid attr type");
            }
            break;
        default:
            return proxy_reply(req, EINVAL, "Invalid filter type");
        }
        break;

    case BE_REQ_GROUP: /* group */
        switch (ar->filter_type) {
        case BE_FILTER_NAME:
            switch (ar->attr_type) {
            case BE_ATTR_CORE:
                if (strchr(ar->filter_value, '*')) {
                    return enum_groups(req);
                } else {
                    return get_gr_name(req, ar->filter_value);
                }
                break;
            default:
                return proxy_reply(req, EINVAL, "Invalid attr type");
            }
            break;
        case BE_FILTER_IDNUM:
            switch (ar->attr_type) {
            case BE_ATTR_CORE:
                if (strchr(ar->filter_value, '*')) {
                    return proxy_reply(req, EINVAL, "Invalid attr type");
                } else {
                    char *endptr;
                    errno = 0;
                    gid = (gid_t)strtol(ar->filter_value, &endptr, 0);
                    if (errno || *endptr || (ar->filter_value == endptr)) {
                        return proxy_reply(req, EINVAL, "Invalid attr type");
                    }
                    return get_gr_gid(req, gid);
                }
                break;
            default:
                return proxy_reply(req, EINVAL, "Invalid attr type");
            }
            break;
        default:
            return proxy_reply(req, EINVAL, "Invalid filter type");
        }
        break;

    case BE_REQ_INITGROUPS: /* init groups for user */
        if (ar->filter_type != BE_FILTER_NAME) {
            return proxy_reply(req, EINVAL, "Invalid filter type");
        }
        if (ar->attr_type != BE_ATTR_CORE) {
            return proxy_reply(req, EINVAL, "Invalid attr type");
        }
        if (strchr(ar->filter_value, '*')) {
            return proxy_reply(req, EINVAL, "Invalid filter value");
        }
        return get_user_groups(req, ar->filter_value);

    default: /*fail*/
        return proxy_reply(req, EINVAL, "Invalid request type");
    }
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
