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

#include "util/util.h"
#include "db/sysdb.h"
#include "util/strtonum.h"
#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"
#include "responder/ifp/ifp_groups.h"
#include "responder/ifp/ifp_users.h"
#include "responder/ifp/ifp_cache.h"
#include "responder/ifp/ifp_iface/ifp_iface_async.h"

char * ifp_groups_build_path_from_msg(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      struct ldb_message *msg)
{
    const char *key = NULL;

    switch (domain->type) {
    case DOM_TYPE_APPLICATION:
        key = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        break;
    case DOM_TYPE_POSIX:
        key = ldb_msg_find_attr_as_string(msg, SYSDB_GIDNUM, NULL);
        break;
    }


    if (key == NULL) {
        return NULL;
    }

    return sbus_opath_compose(mem_ctx, IFP_PATH_GROUPS, domain->name, key);
}

static errno_t ifp_groups_decompose_path(TALLOC_CTX *mem_ctx,
                                         struct sss_domain_info *domains,
                                         const char *path,
                                         struct sss_domain_info **_domain,
                                         char **_key)
{
    char **parts = NULL;
    struct sss_domain_info *domain;
    errno_t ret;

    ret = sbus_opath_decompose_expected(NULL, path, IFP_PATH_GROUPS, 2, &parts);
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

static int ifp_groups_list_copy(struct ifp_list_ctx *list_ctx,
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
            ifp_groups_build_path_from_msg(list_ctx->paths, domain,
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

struct ifp_groups_find_by_name_state {
    const char *path;
};

static void ifp_groups_find_by_name_done(struct tevent_req *subreq);

struct tevent_req *
ifp_groups_find_by_name_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sbus_request *sbus_req,
                             struct ifp_ctx *ctx,
                             const char *name)
{
    struct ifp_groups_find_by_name_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ifp_groups_find_by_name_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    subreq = cache_req_group_by_name_send(state, ctx->rctx->ev, ctx->rctx,
                                          ctx->rctx->ncache, 0,
                                          CACHE_REQ_ANY_DOM, NULL,
                                          name);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_groups_find_by_name_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_groups_find_by_name_done(struct tevent_req *subreq)
{
    struct ifp_groups_find_by_name_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_groups_find_by_name_state);

    ret = cache_req_group_by_name_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to find group [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->path = ifp_groups_build_path_from_msg(state, result->domain,
                                                 result->msgs[0]);
     if (state->path == NULL) {
         tevent_req_error(req, ENOMEM);
         return;
     }

    tevent_req_done(req);
    return;
}

errno_t
ifp_groups_find_by_name_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             const char **_path)
{
    struct ifp_groups_find_by_name_state *state;
    state = tevent_req_data(req, struct ifp_groups_find_by_name_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_path = talloc_steal(mem_ctx, state->path);

    return EOK;
}

struct ifp_groups_find_by_id_state {
    const char *path;
};

static void ifp_groups_find_by_id_done(struct tevent_req *subreq);

struct tevent_req *
ifp_groups_find_by_id_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           uint32_t id)
{
    struct ifp_groups_find_by_id_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_groups_find_by_id_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    subreq = cache_req_group_by_id_send(state, ctx->rctx->ev, ctx->rctx,
                                        ctx->rctx->ncache, 0, NULL, id);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_groups_find_by_id_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_groups_find_by_id_done(struct tevent_req *subreq)
{
    struct ifp_groups_find_by_id_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_groups_find_by_id_state);

    ret = cache_req_group_by_id_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to find group [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->path = ifp_groups_build_path_from_msg(state, result->domain,
                                                 result->msgs[0]);
    if (state->path == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_groups_find_by_id_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           const char **_path)
{
    struct ifp_groups_find_by_id_state *state;
    state = tevent_req_data(req, struct ifp_groups_find_by_id_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_path = talloc_steal(mem_ctx, state->path);

    return EOK;
}

struct ifp_groups_list_by_name_state {
    struct ifp_ctx *ifp_ctx;
    struct ifp_list_ctx *list_ctx;
};

static errno_t ifp_groups_list_by_name_step(struct tevent_req *req);
static void ifp_groups_list_by_name_done(struct tevent_req *subreq);

struct tevent_req *
ifp_groups_list_by_name_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sbus_request *sbus_req,
                             struct ifp_ctx *ctx,
                             const char *filter,
                             uint32_t limit)
{
    struct ifp_groups_list_by_name_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_groups_list_by_name_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->ifp_ctx = ctx;
    state->list_ctx = ifp_list_ctx_new(state, ctx, NULL, filter, limit);
    if (state->list_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ifp_groups_list_by_name_step(req);

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
ifp_groups_list_by_name_step(struct tevent_req *req)
{
    struct ifp_groups_list_by_name_state *state;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct ifp_groups_list_by_name_state);

    if (state->list_ctx->dom == NULL) {
        return EOK;
    }

    subreq = cache_req_group_by_filter_send(state->list_ctx,
                                            state->ifp_ctx->rctx->ev,
                                            state->ifp_ctx->rctx,
                                            CACHE_REQ_ANY_DOM,
                                            state->list_ctx->dom->name,
                                            state->list_ctx->filter);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ifp_groups_list_by_name_done, req);

    state->list_ctx->dom = get_next_domain(state->list_ctx->dom,
                                           SSS_GND_DESCEND);

    return EAGAIN;
}

static void ifp_groups_list_by_name_done(struct tevent_req *subreq)
{
    struct ifp_groups_list_by_name_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_groups_list_by_name_state);

    ret = cache_req_group_by_name_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret == EOK) {
        ret = ifp_groups_list_copy(state->list_ctx, result->domain,
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

    ret = ifp_groups_list_by_name_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
}

errno_t
ifp_groups_list_by_name_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             const char ***_paths)
{
    struct ifp_groups_list_by_name_state *state;
    state = tevent_req_data(req, struct ifp_groups_list_by_name_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_paths = talloc_steal(mem_ctx, state->list_ctx->paths);

    return EOK;
}

struct ifp_groups_list_by_domain_and_name_state {
    struct ifp_list_ctx *list_ctx;
};

static void ifp_groups_list_by_domain_and_name_done(struct tevent_req *subreq);

struct tevent_req *
ifp_groups_list_by_domain_and_name_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sbus_request *sbus_req,
                                        struct ifp_ctx *ctx,
                                        const char *domain,
                                        const char *filter,
                                        uint32_t limit)
{
    struct ifp_groups_list_by_domain_and_name_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_groups_list_by_domain_and_name_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->list_ctx = ifp_list_ctx_new(state, ctx, NULL, filter, limit);
    if (state->list_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    subreq = cache_req_group_by_filter_send(state->list_ctx, ctx->rctx->ev,
                                            ctx->rctx, CACHE_REQ_ANY_DOM,
                                            domain, filter);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_groups_list_by_domain_and_name_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_groups_list_by_domain_and_name_done(struct tevent_req *subreq)
{
    struct ifp_groups_list_by_domain_and_name_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_groups_list_by_domain_and_name_state);

    ret = cache_req_group_by_filter_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = ifp_groups_list_copy(state->list_ctx, result->domain,
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
ifp_groups_list_by_domain_and_name_recv(TALLOC_CTX *mem_ctx,
                                        struct tevent_req *req,
                                        const char ***_paths)
{
    struct ifp_groups_list_by_domain_and_name_state *state;
    state = tevent_req_data(req, struct ifp_groups_list_by_domain_and_name_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_paths = talloc_steal(mem_ctx, state->list_ctx->paths);

    return EOK;
}

static errno_t
ifp_groups_get_from_cache(TALLOC_CTX *mem_ctx,
                          struct sss_domain_info *domain,
                          const char *key,
                          struct ldb_message **_group)
{
    struct ldb_result *group_res = NULL;
    errno_t ret;
    gid_t gid;
    char *endptr;

    switch (domain->type) {
    case DOM_TYPE_POSIX:
        gid = strtouint32(key, &endptr, 10);
        if ((errno != 0) || *endptr || (key == endptr)) {
            ret = errno ? errno : EINVAL;
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid GID value\n");
            return ret;
        }

        ret = sysdb_getgrgid_with_views(NULL, domain, gid, &group_res);
        if (ret == EOK && group_res->count == 0) {
            *_group = NULL;
            ret = ENOENT;
            goto done;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup group %u@%s [%d]: %s\n",
                  gid, domain->name, ret, sss_strerror(ret));
            goto done;
        }
        break;
    case DOM_TYPE_APPLICATION:
        ret = sysdb_getgrnam_with_views(NULL, domain, key, &group_res);
        if (ret == EOK && group_res->count == 0) {
            *_group = NULL;
            ret = ENOENT;
            goto done;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup group %s@%s [%d]: %s\n",
                  key, domain->name, ret, sss_strerror(ret));
            goto done;
        }
        break;
    }

    if (group_res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "More groups matched by the single key\n");
        return EIO;
    }

    *_group = talloc_steal(mem_ctx, group_res->msgs[0]);

    ret = EOK;

done:
    talloc_free(group_res);

    return ret;
}

static errno_t
ifp_groups_group_get(TALLOC_CTX *mem_ctx,
                     struct sbus_request *sbus_req,
                     struct ifp_ctx *ctx,
                     struct sss_domain_info **_domain,
                     struct ldb_message **_group)
{
    struct sss_domain_info *domain;
    char *key;
    errno_t ret;

    ret = ifp_groups_decompose_path(NULL, ctx->rctx->domains, sbus_req->path,
                                    &domain, &key);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to decompose object path"
              "[%s] [%d]: %s\n", sbus_req->path, ret, sss_strerror(ret));
        return ret;
    }

    if (_group != NULL) {
        ret = ifp_groups_get_from_cache(mem_ctx, domain, key, _group);
    }

    talloc_free(key);

    if (ret == EOK || ret == ENOENT) {
        if (_domain != NULL) {
            *_domain = domain;
        }
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve group from cache\n");
    }

    return ret;
}

struct resolv_ghosts_state {
    struct tevent_context *ev;
    struct sbus_request *sbus_req;
    struct ifp_ctx *ctx;

    struct sss_domain_info *domain;
    const char **ghosts;
    int index;
};

static void resolv_ghosts_group_done(struct tevent_req *subreq);
static errno_t resolv_ghosts_step(struct tevent_req *req);
static void resolv_ghosts_done(struct tevent_req *subreq);

static struct tevent_req *resolv_ghosts_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sbus_request *sbus_req,
                                             struct ifp_ctx *ctx)
{
    struct resolv_ghosts_state *state;
    struct sss_domain_info *domain;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ldb_message *group;
    const char *name;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct resolv_ghosts_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->sbus_req = sbus_req;
    state->ctx = ctx;

    ret = ifp_groups_group_get(state, sbus_req, ctx, &domain, &group);
    if (ret != EOK) {
        goto immediately;
    }

    name = ldb_msg_find_attr_as_string(group, SYSDB_NAME, NULL);
    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Group name is empty!\n");
        ret = ERR_INTERNAL;
        goto immediately;
    }

    subreq = cache_req_group_by_name_send(state, ev, ctx->rctx,
                                          ctx->rctx->ncache, 0,
                                          CACHE_REQ_ANY_DOM,
                                          domain->name,
                                          name);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, resolv_ghosts_group_done, req);

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static void resolv_ghosts_group_done(struct tevent_req *subreq)
{
    struct resolv_ghosts_state *state;
    struct ldb_message *group = NULL;
    struct ldb_message_element *el;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct resolv_ghosts_state);

    ret = ifp_groups_group_get(state, state->sbus_req, state->ctx,
                               &state->domain, &group);
    if (ret != EOK) {
        goto done;
    }

    el = ldb_msg_find_element(group, SYSDB_GHOST);
    if (el == NULL || el->num_values == 0) {
        ret = EOK;
        goto done;
    }

    state->ghosts = sss_ldb_el_to_string_list(state, el);
    if (state->ghosts == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->index = 0;
    ret = resolv_ghosts_step(req);

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
}

errno_t resolv_ghosts_step(struct tevent_req *req)
{
    struct resolv_ghosts_state *state;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct resolv_ghosts_state);

    if (state->ghosts[state->index] == NULL) {
        return EOK;
    }

    subreq = cache_req_user_by_name_send(state, state->ev, state->ctx->rctx,
                                         state->ctx->rctx->ncache, 0,
                                         CACHE_REQ_ANY_DOM,
                                         state->domain->name,
                                         state->ghosts[state->index]);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, resolv_ghosts_done, req);

    state->index++;

    return EAGAIN;
}

static void resolv_ghosts_done(struct tevent_req *subreq)
{
    struct resolv_ghosts_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct resolv_ghosts_state);

    ret = cache_req_user_by_name_recv(state, subreq, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    ret = resolv_ghosts_step(req);

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
}

static errno_t resolv_ghosts_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ifp_groups_group_update_member_list_state {
    int dummy;
};

static void ifp_groups_group_update_member_list_done(struct tevent_req *subreq);

struct tevent_req *
ifp_groups_group_update_member_list_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sbus_request *sbus_req,
                                         struct ifp_ctx *ctx)
{
    struct ifp_groups_group_update_member_list_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_groups_group_update_member_list_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    subreq = resolv_ghosts_send(state, ev, sbus_req, ctx);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_groups_group_update_member_list_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_groups_group_update_member_list_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = resolv_ghosts_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to resolve ghost members [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_groups_group_update_member_list_recv(TALLOC_CTX *mem_ctx,
                                         struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

errno_t
ifp_groups_group_get_name(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ctx,
                          const char **_out)
{
    struct sss_domain_info *domain;
    struct ldb_message *msg;
    const char *in_name;
    const char *out;
    errno_t ret;

    ret = ifp_groups_group_get(mem_ctx, sbus_req, ctx, &domain, &msg);
    if (ret != EOK) {
        return ret;
    }

    in_name = sss_view_ldb_msg_find_attr_as_string(domain, msg,
                                                   SYSDB_NAME, NULL);
    if (in_name == NULL) {
        talloc_zfree(msg);
        DEBUG(SSSDBG_OP_FAILURE, "No name?\n");
        return ERR_INTERNAL;
    }

    out = ifp_format_name_attr(mem_ctx, ctx, in_name, domain);
    talloc_zfree(msg);
    if (out == NULL) {
        return ENOMEM;
    }

    *_out = out;

    return EOK;
}

errno_t
ifp_groups_group_get_gid_number(TALLOC_CTX *mem_ctx,
                                struct sbus_request *sbus_req,
                                struct ifp_ctx *ctx,
                                uint32_t *_out)
{
    struct ldb_message *msg;
    struct sss_domain_info *domain;
    errno_t ret;

    ret = ifp_groups_group_get(mem_ctx, sbus_req, ctx, &domain, &msg);
    if (ret != EOK) {
        return ret;
    }

    *_out = sss_view_ldb_msg_find_attr_as_uint64(domain, msg, SYSDB_GIDNUM, 0);
    talloc_zfree(msg);

    return EOK;
}

errno_t
ifp_groups_group_get_unique_id(TALLOC_CTX *mem_ctx,
                                struct sbus_request *sbus_req,
                                struct ifp_ctx *ctx,
                                const char **_out)
{
    struct ldb_message *msg;
    struct sss_domain_info *domain;
    const char *uuid;
    errno_t ret;

    ret = ifp_groups_group_get(mem_ctx, sbus_req, ctx, &domain, &msg);
    if (ret != EOK) {
        return ret;
    }

    uuid = sss_view_ldb_msg_find_attr_as_string(domain, msg, SYSDB_UUID, NULL);
    if (uuid == NULL) {
        talloc_zfree(msg);
        return ENOENT;
    }

    uuid = talloc_strdup(mem_ctx, uuid);
    talloc_zfree(msg);
    if (uuid == NULL) {
        return ENOMEM;
    }

    *_out = uuid;

    return EOK;
}

static errno_t
ifp_groups_group_get_members(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             struct ifp_ctx *ctx,
                             const char ***_users,
                             const char ***_groups)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_domain_info *domain;
    struct ldb_message *group;
    struct ldb_message **members;
    size_t num_members;
    const char *class;
    const char **users;
    const char **groups;
    int num_users;
    int num_groups;
    int i;
    errno_t ret;
    const char *attrs[] = {SYSDB_OBJECTCATEGORY, SYSDB_UIDNUM,
                           SYSDB_GIDNUM, NULL};

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = ifp_groups_group_get(tmp_ctx, sbus_req, ctx, &domain, &group);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_asq_search(tmp_ctx, domain, group->dn, NULL, SYSDB_MEMBER,
                           attrs, &num_members, &members);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to perform ASQ search [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (num_members == 0) {
        users = NULL;
        groups = NULL;
        ret = EOK;
        goto done;
    }

    users = talloc_zero_array(tmp_ctx, const char *, num_members + 1);
    if (users == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        ret = ENOMEM;
        goto done;
    }

    groups = talloc_zero_array(tmp_ctx, const char *, num_members + 1);
    if (groups == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        ret = ENOMEM;
        goto done;
    }

    num_users = 0;
    num_groups = 0;
    for (i = 0; i < num_members; i++) {
        class = ldb_msg_find_attr_as_string(members[i], SYSDB_OBJECTCATEGORY,
                                            NULL);
        if (class == NULL) {
            ret = ERR_INTERNAL;
            goto done;
        }

        if (strcmp(class, SYSDB_USER_CLASS) == 0) {
            users[num_users] = ifp_users_build_path_from_msg(users, domain,
                                                             members[i]);
            if (users[num_users] == NULL) {
                ret = ENOMEM;
                goto done;
            }

            num_users++;
        } else if (strcmp(class, SYSDB_GROUP_CLASS) == 0) {
            groups[num_groups] = ifp_groups_build_path_from_msg(groups,
                                                         domain, members[i]);
            if (groups[num_groups] == NULL) {
                ret = ENOMEM;
                goto done;
            }

            num_groups++;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected object class %s\n", class);
            ret = ERR_INTERNAL;
            goto done;
        }
    }

    ret = EOK;

done:
    if (ret == EOK) {
        if (_users != NULL) {
            *_users = talloc_steal(mem_ctx, users);
        }

        if (_groups != NULL) {
            *_groups = talloc_steal(mem_ctx, groups);
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ifp_groups_group_get_users(TALLOC_CTX *mem_ctx,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           const char ***_out)
{
    errno_t ret;

    ret = ifp_groups_group_get_members(mem_ctx, sbus_req, ctx, _out, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to acquire groups members\n");
        return ret;
    }

    return EOK;
}

errno_t
ifp_groups_group_get_groups(TALLOC_CTX *mem_ctx,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           const char ***_out)
{
    errno_t ret;

    ret = ifp_groups_group_get_members(mem_ctx, sbus_req, ctx, NULL, _out);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to acquire groups members\n");
        return ret;
    }

    return EOK;
}

errno_t
ifp_cache_list_group(TALLOC_CTX *mem_ctx,
                     struct sbus_request *sbus_req,
                     struct ifp_ctx *ctx,
                     const char ***_out)
{
    return ifp_cache_list(mem_ctx, ctx, IFP_CACHE_GROUP, _out);
}

errno_t
ifp_cache_list_by_domain_group(TALLOC_CTX *mem_ctx,
                               struct sbus_request *sbus_req,
                               struct ifp_ctx *ctx,
                               const char *domain,
                               const char ***_out)
{
    return ifp_cache_list_by_domain(mem_ctx, ctx, domain, IFP_CACHE_GROUP, _out);
}

errno_t
ifp_cache_object_store_group(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             struct ifp_ctx *ctx,
                             bool *_result)
{
    struct sss_domain_info *domain;
    struct ldb_message *group;
    errno_t ret;

    ret = ifp_groups_group_get(NULL, sbus_req, ctx, &domain, &group);
    if (ret != EOK) {
        return ret;
    }

    ret = ifp_cache_object_store(domain, group->dn);
    talloc_free(group);

    if (ret == EOK) {
        *_result = true;
    }

    return ret;
}

errno_t
ifp_cache_object_remove_group(TALLOC_CTX *mem_ctx,
                              struct sbus_request *sbus_req,
                              struct ifp_ctx *ctx,
                              bool *_result)
{
    struct sss_domain_info *domain;
    struct ldb_message *group;
    errno_t ret;

    ret = ifp_groups_group_get(NULL, sbus_req, ctx, &domain, &group);
    if (ret != EOK) {
        return ret;
    }

    ret = ifp_cache_object_remove(domain, group->dn);
    talloc_free(group);

    if (ret == EOK) {
        *_result = true;
    }

    return ret;
}
