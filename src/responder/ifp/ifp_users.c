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
#include "responder/common/cache_req/cache_req.h"
#include "responder/ifp/ifp_users.h"
#include "responder/ifp/ifp_groups.h"
#include "responder/ifp/ifp_cache.h"

char * ifp_users_build_path_from_msg(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     struct ldb_message *msg)
{
    const char *key = NULL;

    switch (domain->type) {
    case DOM_TYPE_APPLICATION:
        key = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        break;
    case DOM_TYPE_POSIX:
        key = ldb_msg_find_attr_as_string(msg, SYSDB_UIDNUM, NULL);
        break;
    }


    if (key == NULL) {
        return NULL;
    }

    return sbus_opath_compose(mem_ctx, IFP_PATH_USERS, domain->name, key);
}

static errno_t ifp_users_decompose_path(TALLOC_CTX *mem_ctx,
                                        struct sss_domain_info *domains,
                                        const char *path,
                                        struct sss_domain_info **_domain,
                                        char **_key)
{
    char **parts = NULL;
    struct sss_domain_info *domain;
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

    *_domain = domain;
    *_key = talloc_steal(mem_ctx, parts[1]);

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
                                      ctx->rctx->ncache, 0,
                                      CACHE_REQ_ANY_DOM,
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
    struct cache_req_result *result;
    char *object_path;
    errno_t ret;

    sbus_req = tevent_req_callback_data(req, struct sbus_request);

    ret = cache_req_user_by_name_recv(sbus_req, req, &result);
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

    object_path = ifp_users_build_path_from_msg(sbus_req, result->domain,
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
                                    ctx->rctx->ncache, 0, NULL, id);
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
    struct cache_req_result *result;
    char *object_path;
    errno_t ret;

    sbus_req = tevent_req_callback_data(req, struct sbus_request);

    ret = cache_req_user_by_id_recv(sbus_req, req, &result);
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

    object_path = ifp_users_build_path_from_msg(sbus_req, result->domain,
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
                                      ctx->rctx->ncache, 0,
                                      CACHE_REQ_ANY_DOM, NULL,
                                      derb64);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, ifp_users_find_by_cert_done, sbus_req);

    return EOK;
}

#define SBUS_ERROR_MORE_THAN_ONE "org.freedesktop.sssd.Error.MoreThanOne"

static void ifp_users_find_by_cert_done(struct tevent_req *req)
{
    DBusError *error;
    struct sbus_request *sbus_req;
    struct cache_req_result *result;
    char *object_path;
    errno_t ret;

    sbus_req = tevent_req_callback_data(req, struct sbus_request);

    ret = cache_req_user_by_cert_recv(sbus_req, req, &result);
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

    if (result->count > 1) {
        ret = EINVAL;
        error = sbus_error_new(sbus_req, SBUS_ERROR_MORE_THAN_ONE,
                               "More than one user found. "
                               "Use ListByCertificate to get all.");
        goto done;
    }

    object_path = ifp_users_build_path_from_msg(sbus_req, result->domain,
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

static int ifp_users_list_by_cert_step(struct ifp_list_ctx *list_ctx);
static void ifp_users_list_by_cert_done(struct tevent_req *req);
static void ifp_users_list_by_name_reply(struct ifp_list_ctx *list_ctx);
static int ifp_users_list_copy(struct ifp_list_ctx *list_ctx,
                               struct ldb_result *result);

int ifp_users_list_by_cert(struct sbus_request *sbus_req, void *data,
                           const char *pem_cert, uint32_t limit)
{
    struct ifp_ctx *ctx;
    struct ifp_list_ctx *list_ctx;
    char *derb64;
    int ret;
    DBusError *error;

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

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return ERR_INTERNAL;
    }

    list_ctx = ifp_list_ctx_new(sbus_req, ctx, derb64, limit);
    if (list_ctx == NULL) {
        return ENOMEM;
    }

    return ifp_users_list_by_cert_step(list_ctx);
}

static int ifp_users_list_by_cert_step(struct ifp_list_ctx *list_ctx)
{
    struct tevent_req *req;

    req = cache_req_user_by_cert_send(list_ctx,
                                      list_ctx->ctx->rctx->ev,
                                      list_ctx->ctx->rctx,
                                      list_ctx->ctx->rctx->ncache,
                                      0,
                                      CACHE_REQ_ANY_DOM,
                                      list_ctx->dom->name,
                                      list_ctx->filter);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, ifp_users_list_by_cert_done, list_ctx);

    return EOK;
}

static void ifp_users_list_by_cert_done(struct tevent_req *req)
{
    DBusError *error;
    struct ifp_list_ctx *list_ctx;
    struct sbus_request *sbus_req;
    struct cache_req_result *result;
    errno_t ret;

    list_ctx = tevent_req_callback_data(req, struct ifp_list_ctx);
    sbus_req = list_ctx->sbus_req;

    ret = cache_req_user_by_cert_recv(sbus_req, req, &result);
    talloc_zfree(req);
    if (ret != EOK && ret != ENOENT) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED,
                               "Failed to fetch user [%d]: %s\n",
                               ret, sss_strerror(ret));
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    if (ret == EOK) {
        ret = ifp_users_list_copy(list_ctx, result->ldb_result);
        if (ret != EOK) {
            error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                                   "Failed to copy domain result");
            sbus_request_fail_and_finish(sbus_req, error);
            return;
        }
    }

    list_ctx->dom = get_next_domain(list_ctx->dom, SSS_GND_DESCEND);
    if (list_ctx->dom == NULL) {
        return ifp_users_list_by_name_reply(list_ctx);
    }

    ret = ifp_users_list_by_cert_step(list_ctx);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                               "Failed to start next-domain search");
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

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

struct name_and_cert_ctx {
    const char *name;
    char *derb64;
    struct sbus_request *sbus_req;
    char *user_opath;
    struct ifp_list_ctx *list_ctx;
};

static void ifp_users_find_by_name_and_cert_name_done(struct tevent_req *req);
static int ifp_users_find_by_name_and_cert_step(
                                   struct name_and_cert_ctx *name_and_cert_ctx);
static void ifp_users_find_by_name_and_cert_done(struct tevent_req *req);
static void ifp_users_find_by_name_and_cert_reply(
                                   struct name_and_cert_ctx *name_and_cert_ctx);

int ifp_users_find_by_name_and_cert(struct sbus_request *sbus_req, void *data,
                                    const char *name, const char *pem_cert)
{
    struct ifp_ctx *ctx;
    struct tevent_req *req;
    int ret;
    struct name_and_cert_ctx *name_and_cert_ctx = NULL;
    DBusError *error;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return ERR_INTERNAL;
    }

    if ((name == NULL || *name == '\0')
            && (pem_cert == NULL || *pem_cert == '\0')) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_INVALID_ARGS,
                               "Missing input");
        sbus_request_fail_and_finish(sbus_req, error);
        /* the connection is already terminated with an error message, hence
         * we have to return EOK to not terminate the connection twice. */
        return EOK;
    }

    name_and_cert_ctx = talloc_zero(sbus_req, struct name_and_cert_ctx);
    if (name_and_cert_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc failed.\n");
        return ENOMEM;
    }

    name_and_cert_ctx->sbus_req = sbus_req;

    if (name != NULL && *name != '\0') {
        name_and_cert_ctx->name = talloc_strdup(name_and_cert_ctx, name);
        if (name_and_cert_ctx->name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            return ENOMEM;
        }
    }

    if (pem_cert != NULL && *pem_cert != '\0') {
        ret = sss_cert_pem_to_derb64(name_and_cert_ctx, pem_cert,
                                     &(name_and_cert_ctx->derb64));
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

        /* FIXME: if unlimted searches with limit=0 will work please replace
         * 100 with 0. */
        name_and_cert_ctx->list_ctx = ifp_list_ctx_new(sbus_req, ctx,
                                                      name_and_cert_ctx->derb64,
                                                      100);
        if (name_and_cert_ctx->list_ctx == NULL) {
            return ENOMEM;
        }
    }

    if (name_and_cert_ctx->name != NULL) {
        req = cache_req_user_by_name_send(sbus_req, ctx->rctx->ev, ctx->rctx,
                                          ctx->rctx->ncache, 0,
                                          CACHE_REQ_ANY_DOM,
                                          NULL,
                                          name_and_cert_ctx->name);
        if (req == NULL) {
            return ENOMEM;
        }

        tevent_req_set_callback(req, ifp_users_find_by_name_and_cert_name_done,
                                name_and_cert_ctx);
    } else {
        ret = ifp_users_find_by_name_and_cert_step(name_and_cert_ctx);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

static void ifp_users_find_by_name_and_cert_name_done(struct tevent_req *req)
{
    DBusError *error;
    struct name_and_cert_ctx *name_and_cert_ctx = NULL;
    struct sbus_request *sbus_req;
    struct cache_req_result *result;
    errno_t ret;

    name_and_cert_ctx = tevent_req_callback_data(req, struct name_and_cert_ctx);
    sbus_req = name_and_cert_ctx->sbus_req;

    ret = cache_req_user_by_name_recv(name_and_cert_ctx, req, &result);
    talloc_zfree(req);
    if (ret == ENOENT) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                               "User not found");
        goto fail;
    } else if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED,
                               "Failed to fetch user [%d]: %s\n",
                               ret, sss_strerror(ret));
        goto fail;
    }

    name_and_cert_ctx->user_opath = ifp_users_build_path_from_msg(
                                                              name_and_cert_ctx,
                                                              result->domain,
                                                              result->msgs[0]);
    if (name_and_cert_ctx->user_opath == NULL) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                               "Failed to compose object path");
        goto fail;
    }

    if (name_and_cert_ctx->list_ctx != NULL) {
        ret = ifp_users_find_by_name_and_cert_step(name_and_cert_ctx);
        if (ret != EOK) {
            error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED,
                                   "Failed to fetch certificate [%d]: %s\n",
                                   ret, sss_strerror(ret));
            goto fail;
        }
    } else {
        ifp_users_find_by_name_and_cert_reply(name_and_cert_ctx);
    }

    return;

fail:
    sbus_request_fail_and_finish(sbus_req, error);
    return;
}

static int ifp_users_find_by_name_and_cert_step(
                                    struct name_and_cert_ctx *name_and_cert_ctx)
{
    struct tevent_req *req;
    struct ifp_list_ctx *list_ctx = name_and_cert_ctx->list_ctx;

    req = cache_req_user_by_cert_send(list_ctx,
                                      list_ctx->ctx->rctx->ev,
                                      list_ctx->ctx->rctx,
                                      list_ctx->ctx->rctx->ncache,
                                      0,
                                      CACHE_REQ_ANY_DOM,
                                      list_ctx->dom->name,
                                      list_ctx->filter);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, ifp_users_find_by_name_and_cert_done,
                            name_and_cert_ctx);

    return EOK;
}

static void ifp_users_find_by_name_and_cert_done(struct tevent_req *req)
{
    DBusError *error;
    struct name_and_cert_ctx *name_and_cert_ctx;
    struct ifp_list_ctx *list_ctx;
    struct sbus_request *sbus_req;
    struct cache_req_result *result;
    errno_t ret;

    name_and_cert_ctx = tevent_req_callback_data(req, struct name_and_cert_ctx);
    list_ctx = name_and_cert_ctx->list_ctx;
    sbus_req = list_ctx->sbus_req;

    ret = cache_req_user_by_cert_recv(name_and_cert_ctx, req, &result);
    talloc_zfree(req);
    if (ret != EOK && ret != ENOENT) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED,
                               "Failed to fetch user [%d]: %s\n",
                               ret, sss_strerror(ret));
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    if (ret == EOK) {
        ret = ifp_users_list_copy(list_ctx, result->ldb_result);
        if (ret != EOK) {
            error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                                   "Failed to copy domain result");
            sbus_request_fail_and_finish(sbus_req, error);
            return;
        }
    }

    list_ctx->dom = get_next_domain(list_ctx->dom, SSS_GND_DESCEND);
    if (list_ctx->dom == NULL) {
        return ifp_users_find_by_name_and_cert_reply(name_and_cert_ctx);
    }

    ret = ifp_users_find_by_name_and_cert_step(name_and_cert_ctx);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                               "Failed to start next-domain search");
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }
    return;
}

static void ifp_users_find_by_name_and_cert_reply(
                                    struct name_and_cert_ctx *name_and_cert_ctx)
{
    struct sbus_request *sbus_req = name_and_cert_ctx->sbus_req;
    struct ifp_list_ctx *list_ctx = name_and_cert_ctx->list_ctx;
    DBusError *error;
    size_t c;

    /* If no name was given check if there is only one user mapped to the
     * certificate and return its object path. Either no or more than one
     * mapped users are errors in this case.
     * The case where a given name could not be found is already handled in
     * ifp_users_find_by_name_and_cert_name_done(). */
    if (name_and_cert_ctx->user_opath == NULL) {
        if (list_ctx == NULL || list_ctx->path_count == 0) {
            error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                                   "User not found");
            sbus_request_fail_and_finish(sbus_req, error);
        } else if (list_ctx->path_count == 1) {
            iface_ifp_users_FindByNameAndCertificate_finish(sbus_req,
                                                           list_ctx->paths[0]);
        } else {
            error = sbus_error_new(sbus_req, SBUS_ERROR_MORE_THAN_ONE,
                                   "More than one user found. "
                                   "Use ListByCertificate to get all.");
            sbus_request_fail_and_finish(sbus_req, error);
        }
        return;
    }

    /* If there was no certficate given just return the object path of the
     * user found by name. If a certificate was given an no mapped user was
     * found return an error. */
    if (list_ctx == NULL || list_ctx->path_count == 0) {
        if (name_and_cert_ctx->derb64 == NULL) {
            iface_ifp_users_FindByNameAndCertificate_finish(sbus_req,
                                                 name_and_cert_ctx->user_opath);
        } else {
            error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                                   "No user matching name and certificate "
                                   "found");
            sbus_request_fail_and_finish(sbus_req, error);
        }
        return;
    }

    /* Check if the user found by name is one of the users mapped to the
     * certificate. */
    for (c = 0; c < list_ctx->path_count; c++) {
        if (strcmp(name_and_cert_ctx->user_opath, list_ctx->paths[c]) == 0) {
            iface_ifp_users_FindByNameAndCertificate_finish(sbus_req,
                                                 name_and_cert_ctx->user_opath);
            return;
        }
    }

    /* A user was found by name but the certificate is mapped to one or more
     * different users. */
    error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                           "No user matching name and certificate found");
    sbus_request_fail_and_finish(sbus_req, error);

    /* name_and_cert_ctx is already freed because sbus_req (the parent) is
     * already freed by the DBus finish calls */
    return;
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
                                        CACHE_REQ_ANY_DOM,
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
    struct cache_req_result *result = NULL;
    errno_t ret;

    list_ctx = tevent_req_callback_data(req, struct ifp_list_ctx);
    sbus_req = list_ctx->sbus_req;

    ret = cache_req_user_by_name_recv(sbus_req, req, &result);
    talloc_zfree(req);
    if (ret != EOK && ret != ENOENT) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "users by filter [%d]: %s\n", ret, sss_strerror(ret));
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    if (ret == EOK) {
        ret = ifp_users_list_copy(list_ctx, result->ldb_result);
        if (ret != EOK) {
            error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                                "Failed to copy domain result");
            sbus_request_fail_and_finish(sbus_req, error);
            return;
        }
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
                                        CACHE_REQ_ANY_DOM,
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
    struct cache_req_result *result;
    errno_t ret;
    size_t copy_count, i;

    list_ctx = tevent_req_callback_data(req, struct ifp_list_ctx);
    sbus_req = list_ctx->sbus_req;

    ret = cache_req_user_by_name_recv(sbus_req, req, &result);
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
ifp_users_get_from_cache(struct sbus_request *sbus_req,
                         struct sss_domain_info *domain,
                         const char *key,
                         struct ldb_message **_user)
{
    struct ldb_result *user_res;
    errno_t ret;
    uid_t uid;

    switch (domain->type) {
    case DOM_TYPE_POSIX:
        uid = strtouint32(key, NULL, 10);
        ret = errno;
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid UID value\n");
            return ret;
        }

        ret = sysdb_getpwuid_with_views(sbus_req, domain, uid, &user_res);
        if (ret == EOK && user_res->count == 0) {
            *_user = NULL;
            return ENOENT;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup user %u@%s [%d]: %s\n",
                  uid, domain->name, ret, sss_strerror(ret));
            return ret;
        }
        break;
    case DOM_TYPE_APPLICATION:
        ret = sysdb_getpwnam_with_views(sbus_req, domain, key, &user_res);
        if (ret == EOK && user_res->count == 0) {
            *_user = NULL;
            return ENOENT;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup user %s@%s [%d]: %s\n",
                  key, domain->name, ret, sss_strerror(ret));
            return ret;
        }
        break;
    }

    if (user_res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "More users matched by the single key\n");
        return EIO;
    }

    *_user = user_res->msgs[0];
    return EOK;
}

static errno_t
ifp_users_user_get(struct sbus_request *sbus_req,
                   struct ifp_ctx *ifp_ctx,
                   struct sss_domain_info **_domain,
                   struct ldb_message **_user)
{
    struct sss_domain_info *domain;
    char *key;
    errno_t ret;

    ret = ifp_users_decompose_path(sbus_req,
                                   ifp_ctx->rctx->domains, sbus_req->path,
                                   &domain, &key);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to decompose object path"
              "[%s] [%d]: %s\n", sbus_req->path, ret, sss_strerror(ret));
        return ret;
    }

    if (_user != NULL) {
        ret = ifp_users_get_from_cache(sbus_req, domain, key, _user);
    }

    if (ret == EOK || ret == ENOENT) {
        if (_domain != NULL) {
            *_domain = domain;
        }
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve user from cache\n");
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

    ret = ifp_users_user_get(sbus_req, ifp_ctx, &domain, &msg);
    if (ret != EOK) {
        return;
    }

    *_out = sss_view_ldb_msg_find_attr_as_string(domain, msg, attr, NULL);

    return;
}

static void ifp_users_get_name(struct sbus_request *sbus_req,
                               void *data,
                               const char *attr,
                               const char **_out)
{
    struct ifp_ctx *ifp_ctx;
    struct ldb_message *msg;
    struct sss_domain_info *domain;
    const char *in_name;
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

    ret = ifp_users_user_get(sbus_req, ifp_ctx, &domain, &msg);
    if (ret != EOK) {
        return;
    }

    in_name = sss_view_ldb_msg_find_attr_as_string(domain, msg, attr, NULL);
    if (in_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "No name?\n");
        return;
    }

    *_out = ifp_format_name_attr(sbus_req, ifp_ctx, in_name, domain);
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

    ret = ifp_users_user_get(sbus_req, ifp_ctx, &domain, &msg);
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

    ret = ifp_users_user_get(sbus_req, data, &domain, &user);
    if (ret != EOK) {
        return ret;
    }

    username = ldb_msg_find_attr_as_string(user, SYSDB_NAME, NULL);
    if (username == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "User name is empty!\n");
        return ERR_INTERNAL;
    }

    req = cache_req_initgr_by_name_send(sbus_req, ctx->rctx->ev, ctx->rctx,
                                        ctx->rctx->ncache, 0,
                                        CACHE_REQ_ANY_DOM, domain->name,
                                        username);
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

    ret = cache_req_initgr_by_name_recv(sbus_req, req, NULL);
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
    ifp_users_get_name(sbus_req, data, SYSDB_NAME, _out);
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

void ifp_users_user_get_unique_id(struct sbus_request *sbus_req,
                                  void *data,
                                  const char **_out)
{
    ifp_users_get_as_string(sbus_req, data, SYSDB_UUID, _out);
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

    ret = ifp_users_user_get(sbus_req, ifp_ctx, &domain, &user);
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
        if (gid == 0 && domain->type == DOM_TYPE_POSIX) {
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

void ifp_users_user_get_domain(struct sbus_request *sbus_req,
                               void *data,
                               const char **_out)
{
    const char *domainname;

    *_out = NULL;
    ifp_users_user_get_domainname(sbus_req, data, &domainname);

    if (domainname == NULL) {
        return;
    }

    *_out = sbus_opath_compose(sbus_req, IFP_PATH_DOMAINS,
                               domainname);
}

void ifp_users_user_get_domainname(struct sbus_request *sbus_req,
                                   void *data,
                                   const char **_out)
{
    struct ifp_ctx *ifp_ctx;
    struct sss_domain_info *domain;
    errno_t ret;

    *_out = NULL;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);
    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return;
    }

    if (!ifp_is_user_attr_allowed(ifp_ctx, "domainname")) {
        DEBUG(SSSDBG_TRACE_ALL, "Attribute domainname is not allowed\n");
        return;
    }

    ret = ifp_users_user_get(sbus_req, ifp_ctx, &domain, NULL);
    if (ret != EOK) {
        return;
    }

    *_out = domain->name;
}

void ifp_users_user_get_extra_attributes(struct sbus_request *sbus_req,
                                         void *data,
                                         hash_table_t **_out)
{
    struct ifp_ctx *ifp_ctx;
    struct sss_domain_info *domain;
    struct ldb_message *base_user;
    const char *name;
    struct ldb_message **user;
    struct ldb_message_element *el;
    struct ldb_dn *basedn;
    size_t count;
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

    ret = ifp_users_user_get(sbus_req, data, &domain, &base_user);
    if (ret != EOK) {
        return;
    }

    basedn = sysdb_user_base_dn(sbus_req, domain);
    if (basedn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_user_base_dn() failed\n");
        return;
    }

    name = ldb_msg_find_attr_as_string(base_user, SYSDB_NAME, NULL);
    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "A user with no name\n");
        return;
    }

    filter = talloc_asprintf(sbus_req, "(&(%s=%s)(%s=%s))",
                             SYSDB_OBJECTCLASS, SYSDB_USER_CLASS,
                             SYSDB_NAME, name);
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
        DEBUG(SSSDBG_TRACE_FUNC, "User %s not found!\n", name);
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

    ret = ifp_users_user_get(sbus_req, data, &domain, &user);
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

    ret = ifp_users_user_get(sbus_req, data, &domain, &user);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "user [%d]: %s\n", ret, sss_strerror(ret));
        return sbus_request_fail_and_finish(sbus_req, error);
    }

    /* The request is finished inside. */
    return ifp_cache_object_remove(sbus_req, domain, user->dn);
}
