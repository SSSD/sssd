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
#include <tevent.h>
#include <string.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "util/strtonum.h"
#include "util/cert.h"
#include "sbus/sssd_dbus_errors.h"
#include "responder/common/responder.h"
#include "responder/common/responder_cache_req.h"
#include "responder/ifp/ifp_users.h"
#include "responder/ifp/ifp_groups.h"
#include "responder/ifp/ifp_cache.h"

char * ifp_users_build_path_from_msg(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     struct ldb_message *msg)
{
    const char *uid;

    uid = ldb_msg_find_attr_as_string(msg, SYSDB_UIDNUM, NULL);

    if (uid == NULL) {
        return NULL;
    }

    return sbus_opath_compose(mem_ctx, IFP_PATH_USERS, domain->name, uid);
}

static errno_t ifp_users_decompose_path(struct sss_domain_info *domains,
                                        const char *path,
                                        struct sss_domain_info **_domain,
                                        uid_t *_uid)
{
    char **parts = NULL;
    struct sss_domain_info *domain;
    uid_t uid;
    errno_t ret;

    ret = sbus_opath_decompose_exact(NULL, path, IFP_PATH_USERS, 2, &parts);
    if (ret != EOK) {
        return ret;
    }

    domain = find_domain_by_name(domains, parts[0], false);
    if (domain == NULL) {
        ret = ERR_DOMAIN_NOT_FOUND;
        goto done;
    }

    uid = strtouint32(parts[1], NULL, 10);
    ret = errno;
    if (ret != EOK) {
        goto done;
    }

    *_domain = domain;
    *_uid = uid;

done:
    talloc_free(parts);
    return ret;
}

static void ifp_users_find_by_name_done(struct tevent_req *req);

int ifp_users_find_by_name(struct sbus_request *sbus_req,
                           void *data,
                           const char *name)
{
    struct ifp_ctx *ctx;
    struct tevent_req *req;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return ERR_INTERNAL;
    }

    req = cache_req_user_by_name_send(sbus_req, ctx->rctx->ev, ctx->rctx,
                                      ctx->ncache, ctx->neg_timeout, 0,
                                      NULL, name);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, ifp_users_find_by_name_done, sbus_req);

    return EOK;
}

static void
ifp_users_find_by_name_done(struct tevent_req *req)
{
    DBusError *error;
    struct sbus_request *sbus_req;
    struct sss_domain_info *domain;
    struct ldb_result *result;
    char *object_path;
    errno_t ret;

    sbus_req = tevent_req_callback_data(req, struct sbus_request);

    ret = cache_req_user_by_name_recv(sbus_req, req, &result, &domain, NULL);
    talloc_zfree(req);
    if (ret == ENOENT) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                               "User not found");
        goto done;
    } else if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "user [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    object_path = ifp_users_build_path_from_msg(sbus_req, domain,
                                                result->msgs[0]);
    if (object_path == NULL) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                               "Failed to compose object path");
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    iface_ifp_users_FindByName_finish(sbus_req, object_path);
    return;
}

static void ifp_users_find_by_id_done(struct tevent_req *req);

int ifp_users_find_by_id(struct sbus_request *sbus_req,
                         void *data,
                         uint32_t id)
{
    struct ifp_ctx *ctx;
    struct tevent_req *req;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return ERR_INTERNAL;
    }

    req = cache_req_user_by_id_send(sbus_req, ctx->rctx->ev, ctx->rctx,
                                    ctx->ncache, ctx->neg_timeout, 0,
                                    NULL, id);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, ifp_users_find_by_id_done, sbus_req);

    return EOK;
}

static void
ifp_users_find_by_id_done(struct tevent_req *req)
{
    DBusError *error;
    struct sbus_request *sbus_req;
    struct sss_domain_info *domain;
    struct ldb_result *result;
    char *object_path;
    errno_t ret;

    sbus_req = tevent_req_callback_data(req, struct sbus_request);

    ret = cache_req_user_by_id_recv(sbus_req, req, &result, &domain);
    talloc_zfree(req);
    if (ret == ENOENT) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                               "User not found");
        goto done;
    } else if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "user [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    object_path = ifp_users_build_path_from_msg(sbus_req, domain,
                                                result->msgs[0]);
    if (object_path == NULL) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                               "Failed to compose object path");
        goto done;
    }

done:
    if (ret != EOK) {
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    iface_ifp_users_FindByID_finish(sbus_req, object_path);
    return;
}

static void ifp_users_find_by_cert_done(struct tevent_req *req);

int ifp_users_find_by_cert(struct sbus_request *sbus_req, void *data,
                           const char *pem_cert)
{
    struct ifp_ctx *ctx;
    struct tevent_req *req;
    int ret;
    char *derb64;
    DBusError *error;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return ERR_INTERNAL;
    }

    ret = sss_cert_pem_to_derb64(sbus_req, pem_cert, &derb64);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_cert_pem_to_derb64 failed.\n");

        if (ret == ENOMEM) {
            return ret;
        }

        error = sbus_error_new(sbus_req, DBUS_ERROR_INVALID_ARGS,
                               "Invalid certificate format");
        sbus_request_fail_and_finish(sbus_req, error);
        /* the connection is already terminated with an error message, hence
         * we have to return EOK to not terminate the connection twice. */
        return EOK;
    }

    req = cache_req_user_by_cert_send(sbus_req, ctx->rctx->ev, ctx->rctx,
                                      ctx->ncache, ctx->neg_timeout, 0,
                                      NULL, derb64);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, ifp_users_find_by_cert_done, sbus_req);

    return EOK;
}

static void ifp_users_find_by_cert_done(struct tevent_req *req)
{
    DBusError *error;
    struct sbus_request *sbus_req;
    struct sss_domain_info *domain;
    struct ldb_result *result;
    char *object_path;
    errno_t ret;

    sbus_req = tevent_req_callback_data(req, struct sbus_request);

    ret = cache_req_user_by_cert_recv(sbus_req, req, &result, &domain, NULL);
    talloc_zfree(req);
    if (ret == ENOENT) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                               "User not found");
        goto done;
    } else if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "user [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    object_path = ifp_users_build_path_from_msg(sbus_req, domain,
                                                result->msgs[0]);
    if (object_path == NULL) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                               "Failed to compose object path");
        goto done;
    }

done:
    if (ret != EOK) {
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    iface_ifp_users_FindByCertificate_finish(sbus_req, object_path);
    return;
}

static int ifp_users_list_copy(struct ifp_list_ctx *list_ctx,
                               struct ldb_result *result)
{
    size_t copy_count, i;

    copy_count = ifp_list_ctx_remaining_capacity(list_ctx, result->count);

    for (i = 0; i < copy_count; i++) {
        list_ctx->paths[list_ctx->path_count + i] = \
                             ifp_users_build_path_from_msg(list_ctx->paths,
                                                           list_ctx->dom,
                                                           result->msgs[i]);
        if (list_ctx->paths[list_ctx->path_count + i] == NULL) {
            return ENOMEM;
        }
    }

    list_ctx->path_count += copy_count;
    return EOK;
}

static int ifp_users_list_by_name_step(struct ifp_list_ctx *list_ctx);
static void ifp_users_list_by_name_done(struct tevent_req *req);
static void ifp_users_list_by_name_reply(struct ifp_list_ctx *list_ctx);

int ifp_users_list_by_name(struct sbus_request *sbus_req,
                           void *data,
                           const char *filter,
                           uint32_t limit)
{
    struct ifp_ctx *ctx;
    struct ifp_list_ctx *list_ctx;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return ERR_INTERNAL;
    }

    list_ctx = ifp_list_ctx_new(sbus_req, ctx, filter, limit);
    if (list_ctx == NULL) {
        return ENOMEM;
    }

    return ifp_users_list_by_name_step(list_ctx);
}

static int ifp_users_list_by_name_step(struct ifp_list_ctx *list_ctx)
{
    struct tevent_req *req;

    req = cache_req_user_by_filter_send(list_ctx,
                                        list_ctx->ctx->rctx->ev,
                                        list_ctx->ctx->rctx,
                                        list_ctx->dom->name,
                                        list_ctx->filter);
    if (req == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(req,
                            ifp_users_list_by_name_done, list_ctx);

    return EOK;
}

static void ifp_users_list_by_name_done(struct tevent_req *req)
{
    DBusError *error;
    struct ifp_list_ctx *list_ctx;
    struct sbus_request *sbus_req;
    struct ldb_result *result;
    struct sss_domain_info *domain;
    errno_t ret;

    list_ctx = tevent_req_callback_data(req, struct ifp_list_ctx);
    sbus_req = list_ctx->sbus_req;

    ret = cache_req_user_by_name_recv(sbus_req, req, &result, &domain, NULL);
    talloc_zfree(req);
    if (ret != EOK && ret != ENOENT) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "users by filter [%d]: %s\n", ret, sss_strerror(ret));
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    ret = ifp_users_list_copy(list_ctx, result);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                               "Failed to copy domain result");
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    list_ctx->dom = get_next_domain(list_ctx->dom, SSS_GND_DESCEND);
    if (list_ctx->dom == NULL) {
        return ifp_users_list_by_name_reply(list_ctx);
    }

    ret = ifp_users_list_by_name_step(list_ctx);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                               "Failed to start next-domain search");
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }
}

static void ifp_users_list_by_name_reply(struct ifp_list_ctx *list_ctx)
{
    iface_ifp_users_ListByName_finish(list_ctx->sbus_req,
                                      list_ctx->paths,
                                      list_ctx->path_count);
}

static void ifp_users_list_by_domain_and_name_done(struct tevent_req *req);

int ifp_users_list_by_domain_and_name(struct sbus_request *sbus_req,
                                      void *data,
                                      const char *domain,
                                      const char *filter,
                                      uint32_t limit)
{
    struct tevent_req *req;
    struct ifp_ctx *ctx;
    struct ifp_list_ctx *list_ctx;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return ERR_INTERNAL;
    }

    list_ctx = ifp_list_ctx_new(sbus_req, ctx, filter, limit);
    if (list_ctx == NULL) {
        return ENOMEM;
    }

    req = cache_req_user_by_filter_send(list_ctx, ctx->rctx->ev, ctx->rctx,
                                        domain, filter);
    if (req == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(req,
                            ifp_users_list_by_domain_and_name_done, list_ctx);

    return EOK;
}

static void ifp_users_list_by_domain_and_name_done(struct tevent_req *req)
{
    DBusError *error;
    struct ifp_list_ctx *list_ctx;
    struct sbus_request *sbus_req;
    struct ldb_result *result;
    struct sss_domain_info *domain;
    errno_t ret;
    size_t copy_count, i;

    list_ctx = tevent_req_callback_data(req, struct ifp_list_ctx);
    sbus_req = list_ctx->sbus_req;

    ret = cache_req_user_by_name_recv(sbus_req, req, &result, &domain, NULL);
    talloc_zfree(req);
    if (ret == ENOENT) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                               "User not found by filter");
        goto done;
    } else if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "users by filter [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    copy_count = ifp_list_ctx_remaining_capacity(list_ctx, result->count);

    for (i = 0; i < copy_count; i++) {
        list_ctx->paths[i] = ifp_users_build_path_from_msg(list_ctx->paths,
                                                           list_ctx->dom,
                                                           result->msgs[i]);
        if (list_ctx->paths[i] == NULL) {
            error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                                   "Failed to compose object path");
            goto done;
        }
    }

    list_ctx->path_count += copy_count;

done:
    if (ret != EOK) {
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    iface_ifp_users_ListByDomainAndName_finish(sbus_req,
                                               list_ctx->paths,
                                               list_ctx->path_count);
    return;
}

static errno_t
ifp_users_user_get(struct sbus_request *sbus_req,
                   struct ifp_ctx *ifp_ctx,
                   uid_t *_uid,
                   struct sss_domain_info **_domain,
                   struct ldb_message **_user)
{
    struct sss_domain_info *domain;
    struct ldb_result *res;
    uid_t uid;
    errno_t ret;

    ret = ifp_users_decompose_path(ifp_ctx->rctx->domains, sbus_req->path,
                                   &domain, &uid);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to decompose object path"
              "[%s] [%d]: %s\n", sbus_req->path, ret, sss_strerror(ret));
        return ret;
    }

    if (_user != NULL) {
        ret = sysdb_getpwuid_with_views(sbus_req, domain, uid, &res);
        if (ret == EOK && res->count == 0) {
            *_user = NULL;
            ret = ENOENT;
        }

        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup user %u@%s [%d]: %s\n",
                  uid, domain->name, ret, sss_strerror(ret));
        } else {
            *_user = res->msgs[0];
        }
    }

    if (ret == EOK || ret == ENOENT) {
        if (_uid != NULL) {
            *_uid = uid;
        }

        if (_domain != NULL) {
            *_domain = domain;
        }
    }

    return ret;
}

static void ifp_users_get_as_string(struct sbus_request *sbus_req,
                                    void *data,
                                    const char *attr,
                                    const char **_out)
{
    struct ifp_ctx *ifp_ctx;
    struct ldb_message *msg;
    struct sss_domain_info *domain;
    errno_t ret;

    *_out = NULL;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);
    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return;
    }

    if (!ifp_is_user_attr_allowed(ifp_ctx, attr)) {
        DEBUG(SSSDBG_TRACE_ALL, "Attribute %s is not allowed\n", attr);
        return;
    }

    ret = ifp_users_user_get(sbus_req, ifp_ctx, NULL, &domain, &msg);
    if (ret != EOK) {
        return;
    }

    *_out = sss_view_ldb_msg_find_attr_as_string(domain, msg, attr, NULL);

    return;
}

static void ifp_users_get_as_uint32(struct sbus_request *sbus_req,
                                    void *data,
                                    const char *attr,
                                    uint32_t *_out)
{
    struct ifp_ctx *ifp_ctx;
    struct ldb_message *msg;
    struct sss_domain_info *domain;
    errno_t ret;

    *_out = 0;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);
    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return;
    }

    if (!ifp_is_user_attr_allowed(ifp_ctx, attr)) {
        DEBUG(SSSDBG_TRACE_ALL, "Attribute %s is not allowed\n", attr);
        return;
    }

    ret = ifp_users_user_get(sbus_req, ifp_ctx, NULL, &domain, &msg);
    if (ret != EOK) {
        return;
    }

    *_out = sss_view_ldb_msg_find_attr_as_uint64(domain, msg, attr, 0);

    return;
}

static void ifp_users_user_update_groups_list_done(struct tevent_req *req);

int ifp_users_user_update_groups_list(struct sbus_request *sbus_req,
                                      void *data)
{
    struct tevent_req *req;
    struct ifp_ctx *ctx;
    struct sss_domain_info *domain;
    const char *username;
    struct ldb_message *user;
    errno_t ret;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return ERR_INTERNAL;
    }

    ret = ifp_users_user_get(sbus_req, data, NULL, &domain, &user);
    if (ret != EOK) {
        return ret;
    }

    username = ldb_msg_find_attr_as_string(user, SYSDB_NAME, NULL);
    if (username == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "User name is empty!\n");
        return ERR_INTERNAL;
    }

    req = cache_req_initgr_by_name_send(sbus_req, ctx->rctx->ev, ctx->rctx,
                                        ctx->ncache, ctx->neg_timeout, 0,
                                        domain->name, username);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, ifp_users_user_update_groups_list_done,
                            sbus_req);

    return EOK;
}

static void ifp_users_user_update_groups_list_done(struct tevent_req *req)
{
    DBusError *error;
    struct sbus_request *sbus_req;
    errno_t ret;

    sbus_req = tevent_req_callback_data(req, struct sbus_request);

    ret = cache_req_initgr_by_name_recv(sbus_req, req, NULL, NULL, NULL);
    talloc_zfree(req);
    if (ret == ENOENT) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                               "User not found");
        goto done;
    } else if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "user [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

done:
    if (ret != EOK) {
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    iface_ifp_users_user_UpdateGroupsList_finish(sbus_req);
    return;
}

void ifp_users_user_get_name(struct sbus_request *sbus_req,
                             void *data,
                             const char **_out)
{
    ifp_users_get_as_string(sbus_req, data, SYSDB_NAME, _out);
}

void ifp_users_user_get_uid_number(struct sbus_request *sbus_req,
                                   void *data,
                                   uint32_t *_out)
{
    ifp_users_get_as_uint32(sbus_req, data, SYSDB_UIDNUM, _out);
}

void ifp_users_user_get_gid_number(struct sbus_request *sbus_req,
                                   void *data,
                                   uint32_t *_out)
{
    ifp_users_get_as_uint32(sbus_req, data, SYSDB_GIDNUM, _out);
}

void ifp_users_user_get_gecos(struct sbus_request *sbus_req,
                              void *data,
                              const char **_out)
{
    ifp_users_get_as_string(sbus_req, data, SYSDB_GECOS, _out);
}

void ifp_users_user_get_home_directory(struct sbus_request *sbus_req,
                                       void *data,
                                       const char **_out)
{
    ifp_users_get_as_string(sbus_req, data, SYSDB_HOMEDIR, _out);
}

void ifp_users_user_get_login_shell(struct sbus_request *sbus_req,
                                    void *data,
                                    const char **_out)
{
    ifp_users_get_as_string(sbus_req, data, SYSDB_SHELL, _out);
}

void ifp_users_user_get_groups(struct sbus_request *sbus_req,
                               void *data,
                               const char ***_out,
                               int *_size)
{
    struct ifp_ctx *ifp_ctx;
    struct sss_domain_info *domain;
    const char *username;
    struct ldb_message *user;
    struct ldb_result *res;
    const char **out;
    int num_groups;
    gid_t gid;
    errno_t ret;
    int i;

    *_out = NULL;
    *_size = 0;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);
    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return;
    }

    if (!ifp_is_user_attr_allowed(ifp_ctx, "groups")) {
        DEBUG(SSSDBG_TRACE_ALL, "Attribute %s is not allowed\n",
              SYSDB_MEMBEROF);
        return;
    }

    ret = ifp_users_user_get(sbus_req, ifp_ctx, NULL, &domain, &user);
    if (ret != EOK) {
        return;
    }

    username = ldb_msg_find_attr_as_string(user, SYSDB_NAME, NULL);
    if (username == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "User name is empty!\n");
        return;
    }

    /* Run initgroups. */
    ret = sysdb_initgroups_with_views(sbus_req, domain, username, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get groups for %s@%s [%d]: %s\n",
              username, domain->name, ret, sss_strerror(ret));
        return;
    }

    if (res->count == 0) {
        return;
    }

    out = talloc_zero_array(sbus_req, const char *, res->count);
    if (out == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        return;
    }

    num_groups = 0;
    for (i = 0; i < res->count; i++) {
        gid = sss_view_ldb_msg_find_attr_as_uint64(domain, res->msgs[i],
                                                   SYSDB_GIDNUM, 0);
        if (gid == 0) {
            continue;
        }

        out[num_groups] = ifp_groups_build_path_from_msg(out,
                                                         domain,
                                                         res->msgs[i]);
        if (out[num_groups] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "ifp_groups_build_path() failed\n");
            return;
        }

        num_groups++;
    }

    *_out = out;
    *_size = num_groups;
}

void ifp_users_user_get_extra_attributes(struct sbus_request *sbus_req,
                                         void *data,
                                         hash_table_t **_out)
{
    struct ifp_ctx *ifp_ctx;
    struct sss_domain_info *domain;
    struct ldb_message **user;
    struct ldb_message_element *el;
    struct ldb_dn *basedn;
    size_t count;
    uid_t uid;
    const char *filter;
    const char **extra;
    hash_table_t *table;
    hash_key_t key;
    hash_value_t value;
    const char **values;
    errno_t ret;
    int hret;
    int i;

    *_out = NULL;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);
    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return;
    }

    extra = ifp_get_user_extra_attributes(sbus_req, ifp_ctx);
    if (extra == NULL || extra[0] == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "No extra attributes to return\n");
        return;
    }

    ret = ifp_users_user_get(sbus_req, data, &uid, &domain, NULL);
    if (ret != EOK) {
        return;
    }

    basedn = sysdb_user_base_dn(sbus_req, domain);
    if (basedn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_user_base_dn() failed\n");
        return;
    }

    filter = talloc_asprintf(sbus_req, "(&(%s=%s)(%s=%u))",
                             SYSDB_OBJECTCLASS, SYSDB_USER_CLASS,
                             SYSDB_UIDNUM, uid);
    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
        return;
    }

    ret = sysdb_search_entry(sbus_req, domain->sysdb, basedn,
                             LDB_SCOPE_ONELEVEL, filter,
                             extra, &count, &user);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup user [%d]: %s\n",
              ret, sss_strerror(ret));
        return;
    }

    if (count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "User %u not found!\n", uid);
        return;
    } else if (count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "More than one entry found!\n");
        return;
    }

    ret = sss_hash_create(sbus_req, 10, &table);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create hash table!\n");
        return;
    }

    /* Read each extra attribute. */
    for (i = 0; extra[i] != NULL; i++) {
        el = ldb_msg_find_element(user[0], extra[i]);
        if (el == NULL) {
            DEBUG(SSSDBG_TRACE_ALL, "Attribute %s not found, skipping...\n",
                  extra[i]);
            continue;
        }

        values = sss_ldb_el_to_string_list(table, el);
        if (values == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_ldb_el_to_string_list() failed\n");
            return;
        }

        key.type = HASH_KEY_STRING;
        key.str = talloc_strdup(table, extra[i]);
        if (key.str == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            return;
        }

        value.type = HASH_VALUE_PTR;
        value.ptr = values;

        hret = hash_enter(table, &key, &value);
        if (hret != HASH_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to insert entry "
                 "into hash table: %d\n", hret);
            return;
        }
    }

    *_out = table;
}

int ifp_cache_list_user(struct sbus_request *sbus_req,
                        void *data)
{
    return ifp_cache_list(sbus_req, data, IFP_CACHE_USER);
}

int ifp_cache_list_by_domain_user(struct sbus_request *sbus_req,
                                  void *data,
                                  const char *domain)
{
    return ifp_cache_list_by_domain(sbus_req, data, domain, IFP_CACHE_USER);
}

int ifp_cache_object_store_user(struct sbus_request *sbus_req,
                                void *data)
{
    DBusError *error;
    struct sss_domain_info *domain;
    struct ldb_message *user;
    errno_t ret;

    ret = ifp_users_user_get(sbus_req, data, NULL, &domain, &user);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "user [%d]: %s\n", ret, sss_strerror(ret));
        return sbus_request_fail_and_finish(sbus_req, error);
    }

    /* The request is finished inside. */
    return ifp_cache_object_store(sbus_req, domain, user->dn);
}

int ifp_cache_object_remove_user(struct sbus_request *sbus_req,
                                 void *data)
{
    DBusError *error;
    struct sss_domain_info *domain;
    struct ldb_message *user;
    errno_t ret;

    ret = ifp_users_user_get(sbus_req, data, NULL, &domain, &user);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "user [%d]: %s\n", ret, sss_strerror(ret));
        return sbus_request_fail_and_finish(sbus_req, error);
    }

    /* The request is finished inside. */
    return ifp_cache_object_remove(sbus_req, domain, user->dn);
}
