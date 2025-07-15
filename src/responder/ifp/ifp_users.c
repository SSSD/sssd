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

#include <sys/wait.h>

#include <talloc.h>
#include <tevent.h>
#include <string.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "util/strtonum.h"
#include "util/cert.h"
#include "util/child_common.h"
#include "util/crypto/sss_crypto.h"
#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"
#include "responder/ifp/ifp_users.h"
#include "responder/ifp/ifp_groups.h"
#include "responder/ifp/ifp_cache.h"
#include "responder/ifp/ifp_iface/ifp_iface_async.h"

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

    ret = sbus_opath_decompose_expected(NULL, path, IFP_PATH_USERS, 2, &parts);
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

static int ifp_users_list_copy(struct ifp_list_ctx *list_ctx,
                               struct sss_domain_info *domain,
                               struct ldb_result *result)
{
    size_t copy_count, i;
    errno_t ret;

    ret = ifp_list_ctx_remaining_capacity(list_ctx, result->count, &copy_count);
    if (ret != EOK) {
        goto done;
    }

    for (i = 0; i < copy_count; i++) {
        list_ctx->paths[list_ctx->path_count + i] = \
                             ifp_users_build_path_from_msg(list_ctx->paths,
                                                           domain,
                                                           result->msgs[i]);
        if (list_ctx->paths[list_ctx->path_count + i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    list_ctx->path_count += copy_count;
    ret = EOK;

done:
    return ret;
}

struct ifp_users_find_by_name_state {
    const char *path;
};

static void ifp_users_find_by_name_done(struct tevent_req *subreq);

struct tevent_req *
ifp_users_find_by_name_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            const char *name)
{
    struct ifp_users_find_by_name_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ifp_users_find_by_name_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    subreq = cache_req_user_by_name_send(state, ctx->rctx->ev, ctx->rctx,
                                          ctx->rctx->ncache, 0,
                                          CACHE_REQ_ANY_DOM, NULL,
                                          name);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_users_find_by_name_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_users_find_by_name_done(struct tevent_req *subreq)
{
    struct ifp_users_find_by_name_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_users_find_by_name_state);

    ret = cache_req_user_by_name_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to find user [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->path = ifp_users_build_path_from_msg(state, result->domain,
                                                result->msgs[0]);
    if (state->path == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_users_find_by_name_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            const char **_path)
{
    struct ifp_users_find_by_name_state *state;
    state = tevent_req_data(req, struct ifp_users_find_by_name_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_path = talloc_steal(mem_ctx, state->path);

    return EOK;
}

struct ifp_users_find_by_id_state {
    const char *path;
};

static void ifp_users_find_by_id_done(struct tevent_req *subreq);

struct tevent_req *
ifp_users_find_by_id_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ctx,
                          uint32_t id)
{
    struct ifp_users_find_by_id_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_users_find_by_id_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    subreq = cache_req_user_by_id_send(state, ctx->rctx->ev, ctx->rctx,
                                       ctx->rctx->ncache, 0, NULL, id);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_users_find_by_id_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_users_find_by_id_done(struct tevent_req *subreq)
{
    struct ifp_users_find_by_id_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_users_find_by_id_state);

    ret = cache_req_user_by_id_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to find user [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->path = ifp_users_build_path_from_msg(state, result->domain,
                                                result->msgs[0]);
    if (state->path == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_users_find_by_id_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           const char **_path)
{
    struct ifp_users_find_by_id_state *state;
    state = tevent_req_data(req, struct ifp_users_find_by_id_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_path = talloc_steal(mem_ctx, state->path);

    return EOK;
}

struct ifp_users_find_by_cert_state {
    const char *path;
};

static void ifp_users_find_by_cert_done(struct tevent_req *subreq);

struct tevent_req *
ifp_users_find_by_cert_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            const char *pem_cert)
{
    struct ifp_users_find_by_cert_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    char *derb64;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_users_find_by_cert_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    ret = sss_cert_pem_to_derb64(state, pem_cert, &derb64);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_cert_pem_to_derb64 failed.\n");
        goto done;
    }

    subreq = cache_req_user_by_cert_send(state, ctx->rctx->ev, ctx->rctx,
                                         ctx->rctx->ncache, 0, CACHE_REQ_ANY_DOM,
                                         NULL, derb64);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_users_find_by_cert_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_users_find_by_cert_done(struct tevent_req *subreq)
{
    struct ifp_users_find_by_cert_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_users_find_by_cert_state);

    ret = cache_req_user_by_cert_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to find user [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (result->count > 1) {
         DEBUG(SSSDBG_CRIT_FAILURE, "More than one user found. "
               "Use ListByCertificate to get all.\n");
         tevent_req_error(req, EINVAL);
         return;
     }

    state->path = ifp_users_build_path_from_msg(state, result->domain,
                                                result->msgs[0]);
    if (state->path == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_users_find_by_cert_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            const char **_path)
{
    struct ifp_users_find_by_cert_state *state;
    state = tevent_req_data(req, struct ifp_users_find_by_cert_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_path = talloc_steal(mem_ctx, state->path);

    return EOK;
}

struct ifp_users_list_by_cert_state {
    struct ifp_ctx *ifp_ctx;
    struct ifp_list_ctx *list_ctx;
    char *derb64;
};

static errno_t ifp_users_list_by_cert_step(struct tevent_req *req);
static void ifp_users_list_by_cert_done(struct tevent_req *subreq);

struct tevent_req *
ifp_users_list_by_cert_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            const char *pem_cert,
                            uint32_t limit)
{
    struct ifp_users_list_by_cert_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_users_list_by_cert_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    ret = sss_cert_pem_to_derb64(state, pem_cert, &state->derb64);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_cert_pem_to_derb64 failed.\n");
        goto done;
    }

    state->ifp_ctx = ctx;
    state->list_ctx = ifp_list_ctx_new(state, ctx, NULL, state->derb64, limit);
    if (state->list_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ifp_users_list_by_cert_step(req);

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t
ifp_users_list_by_cert_step(struct tevent_req *req)
{
    struct ifp_users_list_by_cert_state *state;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct ifp_users_list_by_cert_state);

    if (state->list_ctx->dom == NULL) {
        return EOK;
    }

    subreq = cache_req_user_by_cert_send(state->list_ctx,
                                         state->ifp_ctx->rctx->ev,
                                         state->ifp_ctx->rctx,
                                         state->ifp_ctx->rctx->ncache,
                                         0,
                                         CACHE_REQ_ANY_DOM,
                                         state->list_ctx->dom->name,
                                         state->list_ctx->filter);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ifp_users_list_by_cert_done, req);

    state->list_ctx->dom = get_next_domain(state->list_ctx->dom,
                                           SSS_GND_DESCEND);

    return EAGAIN;
}

static void ifp_users_list_by_cert_done(struct tevent_req *subreq)
{
    struct ifp_users_list_by_cert_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_users_list_by_cert_state);

    ret = cache_req_user_by_cert_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret == EOK) {
        ret = ifp_users_list_copy(state->list_ctx, result->domain,
                                  result->ldb_result);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to copy domain result\n");
            tevent_req_error(req, ret);
            return;
        }
    } else if (ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to list groups [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = ifp_users_list_by_cert_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
}

errno_t
ifp_users_list_by_cert_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            const char ***_paths)
{
    struct ifp_users_list_by_cert_state *state;
    state = tevent_req_data(req, struct ifp_users_list_by_cert_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_paths = talloc_steal(mem_ctx, state->list_ctx->paths);

    return EOK;
}

struct ifp_users_find_by_name_and_cert_state {
    struct ifp_ctx *ifp_ctx;
    struct ifp_list_ctx *list_ctx;
    const char *name;
    const char *pem_cert;
    char *derb64;

    const char *user_opath;
};

static void ifp_users_find_by_name_and_cert_name_done(struct tevent_req *subreq);
static errno_t ifp_users_find_by_name_and_cert_step(struct tevent_req *req);
static void ifp_users_find_by_name_and_cert_done(struct tevent_req *subreq);

struct tevent_req *
ifp_users_find_by_name_and_cert_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct sbus_request *sbus_req,
                                     struct ifp_ctx *ctx,
                                     const char *name,
                                     const char *pem_cert)
{
    struct ifp_users_find_by_name_and_cert_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_users_find_by_name_and_cert_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->ifp_ctx = ctx;

    if (!SBUS_REQ_STRING_IS_EMPTY(name)) {
        state->name = talloc_strdup(state, name);
        if (state->name == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (!SBUS_REQ_STRING_IS_EMPTY(pem_cert)) {
        state->pem_cert = talloc_strdup(state, pem_cert);
        if (state->pem_cert == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = sss_cert_pem_to_derb64(state, pem_cert, &state->derb64);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_cert_pem_to_derb64 failed.\n");
            goto done;
        }

        /* FIXME: if unlimted searches with limit=0 will work please replace
         * 100 with 0. */
        state->list_ctx = ifp_list_ctx_new(state, ctx, NULL, state->derb64, 100);
        if (state->list_ctx == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (state->name == NULL && state->pem_cert == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Empty arguments!\n");
        ret = EINVAL;
        goto done;
    }

    if (state->name != NULL) {
        subreq = cache_req_user_by_name_send(state, ctx->rctx->ev, ctx->rctx,
                                             ctx->rctx->ncache, 0,
                                             CACHE_REQ_ANY_DOM,
                                             NULL, state->name);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
            ret = ENOMEM;
            goto done;
        }

        tevent_req_set_callback(subreq, ifp_users_find_by_name_and_cert_name_done, req);
    } else {
        ret = ifp_users_find_by_name_and_cert_step(req);
        goto done;
    }

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_users_find_by_name_and_cert_name_done(struct tevent_req *subreq)
{
    struct ifp_users_find_by_name_and_cert_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_users_find_by_name_and_cert_state);

    ret = cache_req_user_by_name_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    state->user_opath = ifp_users_build_path_from_msg(state,
                                                      result->domain,
                                                      result->msgs[0]);
    if (state->user_opath == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    ret = ifp_users_find_by_name_and_cert_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static errno_t
ifp_users_find_by_name_and_cert_step(struct tevent_req *req)
{
    struct ifp_users_find_by_name_and_cert_state *state;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct ifp_users_find_by_name_and_cert_state);

    if (state->list_ctx == NULL) {
        if (state->name == NULL) {
            return EINVAL;
        }

        /* Nothing to search for. */
        return EOK;
    }

    /* No more domains to try. */
    if (state->list_ctx->dom == NULL) {
        return EOK;
    }

    subreq = cache_req_user_by_cert_send(state->list_ctx,
                                         state->ifp_ctx->rctx->ev,
                                         state->ifp_ctx->rctx,
                                         state->ifp_ctx->rctx->ncache,
                                         0,
                                         CACHE_REQ_ANY_DOM,
                                         state->list_ctx->dom->name,
                                         state->list_ctx->filter);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ifp_users_find_by_name_and_cert_done, req);

    state->list_ctx->dom = get_next_domain(state->list_ctx->dom,
                                           SSS_GND_DESCEND);

    return EAGAIN;
}

static void ifp_users_find_by_name_and_cert_done(struct tevent_req *subreq)
{
    struct ifp_users_find_by_name_and_cert_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_users_find_by_name_and_cert_state);

    ret = cache_req_user_by_cert_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret == EOK) {
        ret = ifp_users_list_copy(state->list_ctx, result->domain,
                                  result->ldb_result);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to copy domain result\n");
            tevent_req_error(req, ret);
            return;
        }
    } else if (ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to list groups [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = ifp_users_find_by_name_and_cert_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

errno_t
ifp_users_find_by_name_and_cert_recv(TALLOC_CTX *mem_ctx,
                                     struct tevent_req *req,
                                     const char **_path)
{
    struct ifp_users_find_by_name_and_cert_state *state;
    size_t c;

    state = tevent_req_data(req, struct ifp_users_find_by_name_and_cert_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    /* If no name was given check if there is only one user mapped to the
     * certificate and return its object path. Either no or more than one
     * mapped users are errors in this case.
     * The case where a given name could not be found is already handled in
     * ifp_users_find_by_name_and_cert_name_done(). */
    if (state->user_opath == NULL) {
        if (state->list_ctx == NULL || state->list_ctx->path_count == 0) {
            return ENOENT;
        } else if (state->list_ctx->path_count == 1) {
            *_path = talloc_steal(mem_ctx, state->list_ctx->paths[0]);
            return EOK;
        } else {
            return EEXIST;
        }
    }

    /* If there was no certificate given just return the object path of the
     * user found by name. If a certificate was given an no mapped user was
     * found return an error. */
    if (state->pem_cert == NULL) {
        *_path = talloc_steal(mem_ctx, state->user_opath);
        return EOK;
    } else {
        for (c = 0; c < state->list_ctx->path_count; c++) {
            if (strcmp(state->user_opath, state->list_ctx->paths[c]) == 0) {
                *_path = talloc_steal(mem_ctx, state->user_opath);
                return EOK;
            }
        }
    }

    return ENOENT;
}

struct ifp_users_list_by_attr_state {
    struct ifp_ctx *ifp_ctx;
    struct ifp_list_ctx *list_ctx;
};

static errno_t ifp_users_list_by_attr_step(struct tevent_req *req);
static void ifp_users_list_by_attr_done(struct tevent_req *subreq);

struct tevent_req *
ifp_users_list_by_attr_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            const char *attr,
                            const char *filter,
                            uint32_t limit)
{
    struct ifp_users_list_by_attr_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_users_list_by_attr_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->ifp_ctx = ctx;
    state->list_ctx = ifp_list_ctx_new(state, ctx, attr, filter, limit);
    if (state->list_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ifp_users_list_by_attr_step(req);

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t
ifp_users_list_by_attr_step(struct tevent_req *req)
{
    struct ifp_users_list_by_attr_state *state;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct ifp_users_list_by_attr_state);

    if (state->list_ctx->dom == NULL) {
        return EOK;
    }

    subreq = cache_req_user_by_filter_send(state->list_ctx,
                                            state->ifp_ctx->rctx->ev,
                                            state->ifp_ctx->rctx,
                                            CACHE_REQ_ANY_DOM,
                                            state->list_ctx->dom->name,
                                            state->list_ctx->attr,
                                            state->list_ctx->filter);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ifp_users_list_by_attr_done, req);

    state->list_ctx->dom = get_next_domain(state->list_ctx->dom,
                                           SSS_GND_DESCEND);

    return EAGAIN;
}

static void ifp_users_list_by_attr_done(struct tevent_req *subreq)
{
    struct ifp_users_list_by_attr_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_users_list_by_attr_state);

    ret = cache_req_user_by_name_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret == EOK) {
        ret = ifp_users_list_copy(state->list_ctx, result->domain,
                                  result->ldb_result);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to copy domain result\n");
            tevent_req_error(req, ret);
            return;
        }
    } else if (ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to list users [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = ifp_users_list_by_attr_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
}

errno_t
ifp_users_list_by_attr_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            const char ***_paths)
{
    struct ifp_users_list_by_attr_state *state;
    state = tevent_req_data(req, struct ifp_users_list_by_attr_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_paths = talloc_steal(mem_ctx, state->list_ctx->paths);

    return EOK;
}

struct ifp_users_list_by_domain_and_name_state {
    struct ifp_list_ctx *list_ctx;
};

static void ifp_users_list_by_domain_and_name_done(struct tevent_req *subreq);

struct tevent_req *
ifp_users_list_by_domain_and_name_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sbus_request *sbus_req,
                                       struct ifp_ctx *ctx,
                                       const char *domain,
                                       const char *filter,
                                       uint32_t limit)
{
    struct ifp_users_list_by_domain_and_name_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_users_list_by_domain_and_name_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->list_ctx = ifp_list_ctx_new(state, ctx, NULL, filter, limit);
    if (state->list_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    subreq = cache_req_user_by_filter_send(state->list_ctx, ctx->rctx->ev,
                                            ctx->rctx, CACHE_REQ_ANY_DOM,
                                            domain, NULL, filter);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_users_list_by_domain_and_name_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_users_list_by_domain_and_name_done(struct tevent_req *subreq)
{
    struct ifp_users_list_by_domain_and_name_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_users_list_by_domain_and_name_state);

    ret = cache_req_user_by_name_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = ifp_users_list_copy(state->list_ctx, result->domain,
                              result->ldb_result);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to copy domain result\n");
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_users_list_by_domain_and_name_recv(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req,
                                       const char ***_paths)
{
    struct ifp_users_list_by_domain_and_name_state *state;
    state = tevent_req_data(req, struct ifp_users_list_by_domain_and_name_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_paths = talloc_steal(mem_ctx, state->list_ctx->paths);

    return EOK;
}

struct ifp_users_find_by_valid_cert_state {
    struct ifp_ctx *ifp_ctx;
    struct tevent_context *ev;
    const char *logfile;
    int timeout;
    char *ca_db;
    char *verify_opts;
    char *derb64;
    const char **extra_args;
    const char *path;
};

static void p11_child_timeout(struct tevent_context *ev,
                              struct tevent_timer *te,
                              struct timeval tv, void *pvt);
static void
ifp_users_find_by_valid_cert_step(int child_status,
                                  struct tevent_signal *sige,
                                  void *pvt);
static void ifp_users_find_by_valid_cert_done(struct tevent_req *subreq);

struct tevent_req *
ifp_users_find_by_valid_cert_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct sbus_request *sbus_req,
                                  struct ifp_ctx *ctx,
                                  const char *pem_cert)
{
    struct tevent_req *req;
    struct ifp_users_find_by_valid_cert_state *state;
    size_t arg_c = 0;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_users_find_by_valid_cert_state);
    if (req == NULL) {
        return NULL;
    }

    state->ifp_ctx = ctx;

    ret = confdb_get_string(ctx->rctx->cdb, state,
                            CONFDB_IFP_CONF_ENTRY, CONFDB_SSH_CA_DB,
                            CONFDB_DEFAULT_SSH_CA_DB, &state->ca_db);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Error reading CA DB from confdb (%d) [%s]\n",
              ret, strerror(ret));
        goto done;
    }

    ret = confdb_get_int(ctx->rctx->cdb, CONFDB_IFP_CONF_ENTRY,
                         CONFDB_PAM_P11_CHILD_TIMEOUT, -1,
                         &state->timeout);
    if (ret != EOK || state->timeout == -1) {
        /* check pam configuration as well or use default */
        ret = confdb_get_int(ctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
                             CONFDB_PAM_P11_CHILD_TIMEOUT,
                             P11_CHILD_TIMEOUT_DEFAULT,
                             &state->timeout);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to read p11_child_timeout from confdb: [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = confdb_get_string(ctx->rctx->cdb, state, CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_CERT_VERIFICATION, NULL,
                            &state->verify_opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to read '"CONFDB_MONITOR_CERT_VERIFICATION"' from confdb: [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    state->ev = ev;
    state->logfile = P11_CHILD_LOG_FILE;

    ret = sss_cert_pem_to_derb64(state, pem_cert, &state->derb64);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_cert_pem_to_derb64 failed.\n");
        goto done;
    }

    state->extra_args = talloc_zero_array(state, const char *, 10);
    if (state->extra_args == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
        ret = ENOMEM;
        goto done;
    }
    state->extra_args[arg_c++] = state->derb64;
    state->extra_args[arg_c++] = "--certificate";
    state->extra_args[arg_c++] = state->ca_db;
    state->extra_args[arg_c++] = "--ca_db";
    if (state->verify_opts != NULL) {
        state->extra_args[arg_c++] = state->verify_opts;
        state->extra_args[arg_c++] = "--verify";
    }
    state->extra_args[arg_c++] = "--verification";
    if (state->timeout > 0) {
        state->extra_args[arg_c++] = talloc_asprintf(state, "%d",
                                                     state->timeout);
        if (state->extra_args[arg_c - 1] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }
        state->extra_args[arg_c++] = "--timeout";
    }

    ret = sss_child_start(state, state->ev, P11_CHILD_PATH,
                          state->extra_args, false, state->logfile,
                          -1, /* ifp cares only about exit code, so no 'io' */
                          ifp_users_find_by_valid_cert_step, req,
                          state->timeout, p11_child_timeout, req, true,
                          NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_child_start failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void p11_child_timeout(struct tevent_context *ev,
                              struct tevent_timer *te,
                              struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);

    DEBUG(SSSDBG_CRIT_FAILURE, "p11_child timed out\n");
    tevent_req_error(req, ERR_P11_CHILD);
}

static void
ifp_users_find_by_valid_cert_step(int child_status,
                                  struct tevent_signal *sige,
                                  void *pvt)
{
    struct tevent_req *subreq;
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct ifp_users_find_by_valid_cert_state *state;
    errno_t ret;

    state = tevent_req_data(req, struct ifp_users_find_by_valid_cert_state);

    if (WIFEXITED(child_status)) {
        if (WEXITSTATUS(child_status) == CA_DB_NOT_FOUND_EXIT_CODE) {
            DEBUG(SSSDBG_OP_FAILURE,
                  P11_CHILD_PATH " failed [%d]: [%s].\n",
                  ERR_CA_DB_NOT_FOUND, sss_strerror(ERR_CA_DB_NOT_FOUND));
            tevent_req_error(req, ERR_CA_DB_NOT_FOUND);
            return;
        } else if (WEXITSTATUS(child_status) != 0) {
            DEBUG(SSSDBG_OP_FAILURE,
                  P11_CHILD_PATH " failed with status [%d]. Check p11_child"
                  " logs for more information.\n",
                  WEXITSTATUS(child_status));
            tevent_req_error(req, ERR_INVALID_CERT);
            return;
        }
    } else if (WIFSIGNALED(child_status)) {
        DEBUG(SSSDBG_OP_FAILURE,
              P11_CHILD_PATH " was terminated by signal [%d]. Check p11_child"
              " logs for more information.\n",
              WTERMSIG(child_status));
        tevent_req_error(req, ECHILD);
        return;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Certificate [%s] is valid.\n",
          state->extra_args[0]);

    subreq = cache_req_user_by_cert_send(state, state->ifp_ctx->rctx->ev,
                                         state->ifp_ctx->rctx,
                                         state->ifp_ctx->rctx->ncache, 0,
                                         CACHE_REQ_ANY_DOM, NULL,
                                         state->derb64);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_users_find_by_valid_cert_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, state->ifp_ctx->rctx->ev);
    }

    return;
}

static void ifp_users_find_by_valid_cert_done(struct tevent_req *subreq)
{
    struct ifp_users_find_by_valid_cert_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_users_find_by_valid_cert_state);

    ret = cache_req_user_by_cert_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to find user [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (result->count > 1) {
         DEBUG(SSSDBG_CRIT_FAILURE, "More than one user found. "
               "Use ListByCertificate to get all.\n");
         tevent_req_error(req, EINVAL);
         return;
    }

    state->path = ifp_users_build_path_from_msg(state, result->domain,
                                                result->msgs[0]);
    if (state->path == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_users_find_by_valid_cert_recv(TALLOC_CTX *mem_ctx,
                                  struct tevent_req *req,
                                  const char **_path)
{
    struct ifp_users_find_by_valid_cert_state *state;

    state = tevent_req_data(req, struct ifp_users_find_by_valid_cert_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_path = talloc_steal(mem_ctx, state->path);

    return EOK;
}

static errno_t
ifp_users_get_from_cache(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain,
                         const char *key,
                         struct ldb_message **_user)
{
    struct ldb_result *user_res = NULL;
    errno_t ret;
    uid_t uid;
    char *endptr;

    switch (domain->type) {
    case DOM_TYPE_POSIX:
        uid = strtouint32(key, &endptr, 10);
        if ((errno != 0) || *endptr || (key == endptr)) {
            ret = errno ? errno : EINVAL;
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid UID value\n");
            goto done;
        }

        ret = sysdb_getpwuid_with_views(mem_ctx, domain, uid, &user_res);
        if (ret == EOK && user_res->count == 0) {
            *_user = NULL;
            ret = ENOENT;
            goto done;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup user %u@%s [%d]: %s\n",
                  uid, domain->name, ret, sss_strerror(ret));
            goto done;
        }
        break;
    case DOM_TYPE_APPLICATION:
        ret = sysdb_getpwnam_with_views(mem_ctx, domain, key, &user_res);
        if (ret == EOK && user_res->count == 0) {
            *_user = NULL;
            ret = ENOENT;
            goto done;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup user %s@%s [%d]: %s\n",
                  key, domain->name, ret, sss_strerror(ret));
            goto done;
        }
        break;
    }

    if (user_res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "More users matched by the single key\n");
        ret = EIO;
        goto done;
    }

    *_user = talloc_steal(mem_ctx, user_res->msgs[0]);

    ret = EOK;

done:
    talloc_free(user_res);

    return ret;
}

static errno_t
ifp_users_user_get(TALLOC_CTX *mem_ctx,
                   struct sbus_request *sbus_req,
                   struct ifp_ctx *ifp_ctx,
                   struct sss_domain_info **_domain,
                   struct ldb_message **_user)
{
    struct sss_domain_info *domain;
    char *key;
    errno_t ret;

    ret = ifp_users_decompose_path(NULL,
                                   ifp_ctx->rctx->domains, sbus_req->path,
                                   &domain, &key);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to decompose object path"
              "[%s] [%d]: %s\n", sbus_req->path, ret, sss_strerror(ret));
        return ret;
    }

    if (_user != NULL) {
        ret = ifp_users_get_from_cache(mem_ctx, domain, key, _user);
    }

    talloc_free(key);

    if (ret == EOK || ret == ENOENT) {
        if (_domain != NULL) {
            *_domain = domain;
        }
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve user from cache\n");
    }

    return ret;
}

static errno_t
ifp_users_get_as_string(TALLOC_CTX *mem_ctx,
                        struct sbus_request *sbus_req,
                        struct ifp_ctx *ifp_ctx,
                        const char *attr,
                        const char **_out,
                        struct sss_domain_info **_domain)
{
    struct ldb_message *msg;
    struct sss_domain_info *domain;
    const char *out;
    errno_t ret;

    ret = ifp_users_user_get(NULL, sbus_req, ifp_ctx, &domain, &msg);
    if (ret != EOK) {
        return ret;
    }

    out = sss_view_ldb_msg_find_attr_as_string(domain, msg, attr, NULL);
    if (out == NULL) {
        talloc_free(msg);
        return ENOENT;
    }

    *_out = talloc_steal(mem_ctx, out);
    talloc_free(msg);

    if (_domain != NULL) {
        *_domain = domain;
    }

    return EOK;
}

static errno_t
ifp_users_get_name(TALLOC_CTX *mem_ctx,
                   struct sbus_request *sbus_req,
                   struct ifp_ctx *ifp_ctx,
                   const char *attr,
                   const char **_out)
{
    struct sss_domain_info *domain;
    const char *in_name;
    const char *out;
    errno_t ret;

    ret = ifp_users_get_as_string(NULL, sbus_req, ifp_ctx, attr,
                                  &in_name, &domain);
    if (ret != EOK) {
        return ret;
    }

    out = ifp_format_name_attr(mem_ctx, ifp_ctx, in_name, domain);
    talloc_free(discard_const(in_name));
    if (out == NULL) {
        return ENOMEM;
    }

    *_out = out;

    return EOK;
}

static errno_t
ifp_users_get_as_uint32(struct sbus_request *sbus_req,
                        struct ifp_ctx *ifp_ctx,
                        const char *attr,
                        uint32_t *_out)
{
    struct ldb_message *msg;
    struct sss_domain_info *domain;
    errno_t ret;

    ret = ifp_users_user_get(NULL, sbus_req, ifp_ctx, &domain, &msg);
    if (ret != EOK) {
        return ret;
    }

    *_out = sss_view_ldb_msg_find_attr_as_uint64(domain, msg, attr, 0);
    talloc_free(msg);

    return EOK;
}

struct ifp_users_user_update_groups_list_state {
    int dummy;
};

static void ifp_users_user_update_groups_list_done(struct tevent_req *subreq);

struct tevent_req *
ifp_users_user_update_groups_list_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sbus_request *sbus_req,
                                       struct ifp_ctx *ctx)
{
    struct ifp_users_user_update_groups_list_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    struct sss_domain_info *domain;
    struct ldb_message *user;
    const char *username;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_users_user_update_groups_list_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    ret = ifp_users_user_get(state, sbus_req, ctx, &domain, &user);
    if (ret != EOK) {
        goto done;
    }

    username = ldb_msg_find_attr_as_string(user, SYSDB_NAME, NULL);
    if (username == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "User name is empty!\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    subreq = cache_req_initgr_by_name_send(state, ctx->rctx->ev, ctx->rctx,
                                           ctx->rctx->ncache, 0,
                                           CACHE_REQ_ANY_DOM, domain->name,
                                           username);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_users_user_update_groups_list_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_users_user_update_groups_list_done(struct tevent_req *subreq)
{
    struct ifp_users_user_update_groups_list_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_users_user_update_groups_list_state);

    ret = cache_req_initgr_by_name_recv(state, subreq, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_users_user_update_groups_list_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

errno_t
ifp_users_user_get_name(TALLOC_CTX *mem_ctx,
                        struct sbus_request *sbus_req,
                        struct ifp_ctx *ctx,
                        const char **_out)
{
    return ifp_users_get_name(mem_ctx, sbus_req, ctx, SYSDB_NAME, _out);
}

errno_t
ifp_users_user_get_uid_number(TALLOC_CTX *mem_ctx,
                              struct sbus_request *sbus_req,
                              struct ifp_ctx *ctx,
                              uint32_t *_out)
{
    return ifp_users_get_as_uint32(sbus_req, ctx, SYSDB_UIDNUM, _out);
}

errno_t
ifp_users_user_get_gid_number(TALLOC_CTX *mem_ctx,
                              struct sbus_request *sbus_req,
                              struct ifp_ctx *ctx,
                              uint32_t *_out)
{
    return ifp_users_get_as_uint32(sbus_req, ctx, SYSDB_GIDNUM, _out);
}

errno_t
ifp_users_user_get_gecos(TALLOC_CTX *mem_ctx,
                        struct sbus_request *sbus_req,
                        struct ifp_ctx *ctx,
                        const char **_out)
{
    return ifp_users_get_as_string(mem_ctx, sbus_req, ctx, SYSDB_GECOS, _out, NULL);
}

errno_t
ifp_users_user_get_home_directory(TALLOC_CTX *mem_ctx,
                                  struct sbus_request *sbus_req,
                                  struct ifp_ctx *ctx,
                                  const char **_out)
{
    return ifp_users_get_as_string(mem_ctx, sbus_req, ctx, SYSDB_HOMEDIR, _out, NULL);
}

errno_t
ifp_users_user_get_login_shell(TALLOC_CTX *mem_ctx,
                               struct sbus_request *sbus_req,
                               struct ifp_ctx *ctx,
                               const char **_out)
{
    return ifp_users_get_as_string(mem_ctx, sbus_req, ctx, SYSDB_SHELL, _out, NULL);
}

errno_t
ifp_users_user_get_unique_id(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             struct ifp_ctx *ctx,
                             const char **_out)
{
    return ifp_users_get_as_string(mem_ctx, sbus_req, ctx, SYSDB_UUID, _out, NULL);
}

errno_t
ifp_users_user_get_groups(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ifp_ctx,
                          const char ***_out)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_domain_info *domain;
    const char *username;
    struct ldb_message *user;
    struct ldb_result *res;
    const char **out;
    int num_groups;
    gid_t gid;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    ret = ifp_users_user_get(tmp_ctx, sbus_req, ifp_ctx, &domain, &user);
    if (ret != EOK) {
        return ret;
    }

    username = ldb_msg_find_attr_as_string(user, SYSDB_NAME, NULL);
    if (username == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "User name is empty!\n");
        return ERR_INTERNAL;
    }

    /* Run initgroups. */
    ret = sysdb_initgroups_with_views(tmp_ctx, domain, username, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get groups for %s@%s [%d]: %s\n",
              username, domain->name, ret, sss_strerror(ret));
        goto done;
    }

    if (res->count == 0) {
        *_out = NULL;
        ret = EOK;
        goto done;
    }

    out = talloc_zero_array(tmp_ctx, const char *, res->count + 1);
    if (out == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        ret = ENOMEM;
        goto done;
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
            ret = ENOMEM;
            goto done;
        }

        num_groups++;
    }

    *_out = talloc_steal(mem_ctx, out);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ifp_users_user_get_domainname(TALLOC_CTX *mem_ctx,
                              struct sbus_request *sbus_req,
                              struct ifp_ctx *ifp_ctx,
                              const char **_out)
{
    struct sss_domain_info *domain;
    errno_t ret;

    ret = ifp_users_user_get(mem_ctx, sbus_req, ifp_ctx, &domain, NULL);
    if (ret != EOK) {
        return ret;
    }

    *_out = domain->name;

    return EOK;
}

errno_t
ifp_users_user_get_domain(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ctx,
                          const char **_out)
{
    const char *name;
    const char *out;
    errno_t ret;

    ret = ifp_users_user_get_domainname(NULL, sbus_req, ctx, &name);
    if (ret != EOK) {
        return ret;
    }

    out = sbus_opath_compose(mem_ctx, IFP_PATH_DOMAINS, name);
    if (out == NULL) {
        return ENOMEM;
    }

    *_out = out;

    return EOK;
}

errno_t
ifp_users_user_get_extra_attributes(TALLOC_CTX *mem_ctx,
                                    struct sbus_request *sbus_req,
                                    struct ifp_ctx *ifp_ctx,
                                    hash_table_t **_out)
{
    TALLOC_CTX *tmp_ctx;
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

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    extra = ifp_get_user_extra_attributes(tmp_ctx, ifp_ctx);
    if (extra == NULL || extra[0] == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "No extra attributes to return\n");
        *_out = NULL;
        ret = EOK;
        goto done;
    }

    ret = ifp_users_user_get(tmp_ctx, sbus_req, ifp_ctx, &domain, &base_user);
    if (ret != EOK) {
        goto done;
    }

    basedn = sysdb_user_base_dn(tmp_ctx, domain);
    if (basedn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_user_base_dn() failed\n");
        ret = ENOMEM;
        goto done;
    }

    name = ldb_msg_find_attr_as_string(base_user, SYSDB_NAME, NULL);
    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "A user with no name\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, "(&(%s=%s)(%s=%s))",
                             SYSDB_OBJECTCATEGORY, SYSDB_USER_CLASS,
                             SYSDB_NAME, name);
    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, basedn,
                             LDB_SCOPE_SUBTREE, filter,
                             extra, &count, &user);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup user [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "User %s not found!\n", name);
        ret = ENOENT;
        goto done;
    } else if (count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "More than one entry found!\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    ret = sss_hash_create(tmp_ctx, 0, &table);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create hash table!\n");
        goto done;
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
            ret = ENOMEM;
            goto done;
        }

        key.type = HASH_KEY_STRING;
        key.str = talloc_strdup(table, extra[i]);
        if (key.str == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            ret = ENOMEM;
            goto done;
        }

        value.type = HASH_VALUE_PTR;
        value.ptr = values;

        hret = hash_enter(table, &key, &value);
        if (hret != HASH_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to insert entry "
                 "into hash table: %d\n", hret);
            ret = EIO;
            goto done;
        }
    }

    *_out = talloc_steal(mem_ctx, table);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
ifp_cache_list_user(TALLOC_CTX *mem_ctx,
                    struct sbus_request *sbus_req,
                    struct ifp_ctx *ctx,
                    const char ***_out)
{
    return ifp_cache_list(mem_ctx, ctx, IFP_CACHE_USER, _out);
}

errno_t
ifp_cache_list_by_domain_user(TALLOC_CTX *mem_ctx,
                              struct sbus_request *sbus_req,
                              struct ifp_ctx *ctx,
                              const char *domain,
                              const char ***_out)
{
    return ifp_cache_list_by_domain(mem_ctx, ctx, domain, IFP_CACHE_USER, _out);
}

errno_t
ifp_cache_object_store_user(TALLOC_CTX *mem_ctx,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            bool *_result)
{
    struct sss_domain_info *domain;
    struct ldb_message *user;
    errno_t ret;

    ret = ifp_users_user_get(NULL, sbus_req, ctx, &domain, &user);
    if (ret != EOK) {
        return ret;
    }

    ret = ifp_cache_object_store(domain, user->dn);
    talloc_free(user);

    if (ret == EOK) {
        *_result = true;
    }

    return ret;
}

errno_t
ifp_cache_object_remove_user(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             struct ifp_ctx *ctx,
                             bool *_result)
{
    struct sss_domain_info *domain;
    struct ldb_message *user;
    errno_t ret;

    ret = ifp_users_user_get(NULL, sbus_req, ctx, &domain, &user);
    if (ret != EOK) {
        return ret;
    }

    ret = ifp_cache_object_remove(domain, user->dn);
    talloc_free(user);

    if (ret == EOK) {
        *_result = true;
    }

    return ret;
}

struct tevent_req *
ifp_users_list_by_name_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            const char *filter,
                            uint32_t limit)
{
    return ifp_users_list_by_attr_send(mem_ctx, ev, sbus_req, ctx, NULL,
                                       filter, limit);
}
