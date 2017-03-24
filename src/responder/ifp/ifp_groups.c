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
#include "sbus/sssd_dbus_errors.h"
#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"
#include "responder/ifp/ifp_groups.h"
#include "responder/ifp/ifp_users.h"
#include "responder/ifp/ifp_cache.h"

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

    ret = sbus_opath_decompose_exact(NULL, path, IFP_PATH_GROUPS, 2, &parts);
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
                                struct ldb_result *result)
{
    size_t copy_count, i;

    copy_count = ifp_list_ctx_remaining_capacity(list_ctx, result->count);

    for (i = 0; i < copy_count; i++) {
        list_ctx->paths[list_ctx->path_count + i] = \
            ifp_groups_build_path_from_msg(list_ctx->paths,
                                           list_ctx->dom,
                                           result->msgs[i]);
        if (list_ctx->paths[list_ctx->path_count + i] == NULL) {
            return ENOMEM;
        }
    }

    list_ctx->path_count += copy_count;
    return EOK;
}

static void ifp_groups_find_by_name_done(struct tevent_req *req);

int ifp_groups_find_by_name(struct sbus_request *sbus_req,
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

    req = cache_req_group_by_name_send(sbus_req, ctx->rctx->ev, ctx->rctx,
                                       ctx->rctx->ncache, 0,
                                       CACHE_REQ_ANY_DOM, NULL,
                                       name);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, ifp_groups_find_by_name_done, sbus_req);

    return EOK;
}

static void
ifp_groups_find_by_name_done(struct tevent_req *req)
{
    DBusError *error;
    struct sbus_request *sbus_req;
    struct cache_req_result *result;
    char *object_path;
    errno_t ret;

    sbus_req = tevent_req_callback_data(req, struct sbus_request);

    ret = cache_req_group_by_name_recv(sbus_req, req, &result);
    talloc_zfree(req);
    if (ret == ENOENT) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                               "Group not found");
        goto done;
    } else if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "group [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    object_path = ifp_groups_build_path_from_msg(sbus_req, result->domain,
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

    iface_ifp_groups_FindByName_finish(sbus_req, object_path);
    return;
}

static void ifp_groups_find_by_id_done(struct tevent_req *req);

int ifp_groups_find_by_id(struct sbus_request *sbus_req,
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

    req = cache_req_group_by_id_send(sbus_req, ctx->rctx->ev, ctx->rctx,
                                     ctx->rctx->ncache, 0, NULL, id);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, ifp_groups_find_by_id_done, sbus_req);

    return EOK;
}

static void
ifp_groups_find_by_id_done(struct tevent_req *req)
{
    DBusError *error;
    struct sbus_request *sbus_req;
    struct cache_req_result *result;
    char *object_path;
    errno_t ret;

    sbus_req = tevent_req_callback_data(req, struct sbus_request);

    ret = cache_req_group_by_id_recv(sbus_req, req, &result);
    talloc_zfree(req);
    if (ret == ENOENT) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                               "Group not found");
        goto done;
    } else if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "group [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    object_path = ifp_groups_build_path_from_msg(sbus_req, result->domain,
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

    iface_ifp_groups_FindByID_finish(sbus_req, object_path);
    return;
}

static int ifp_groups_list_by_name_step(struct ifp_list_ctx *list_ctx);
static void ifp_groups_list_by_name_done(struct tevent_req *req);
static void ifp_groups_list_by_name_reply(struct ifp_list_ctx *list_ctx);

int ifp_groups_list_by_name(struct sbus_request *sbus_req,
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

    return ifp_groups_list_by_name_step(list_ctx);
}

static int ifp_groups_list_by_name_step(struct ifp_list_ctx *list_ctx)
{
    struct tevent_req *req;

    req = cache_req_group_by_filter_send(list_ctx,
                                        list_ctx->ctx->rctx->ev,
                                        list_ctx->ctx->rctx,
                                        CACHE_REQ_ANY_DOM,
                                        list_ctx->dom->name,
                                        list_ctx->filter);
    if (req == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(req,
                            ifp_groups_list_by_name_done, list_ctx);

    return EOK;
}

static void ifp_groups_list_by_name_done(struct tevent_req *req)
{
    DBusError *error;
    struct ifp_list_ctx *list_ctx;
    struct sbus_request *sbus_req;
    struct cache_req_result *result;
    errno_t ret;

    list_ctx = tevent_req_callback_data(req, struct ifp_list_ctx);
    sbus_req = list_ctx->sbus_req;

    ret = cache_req_group_by_name_recv(sbus_req, req, &result);
    talloc_zfree(req);
    if (ret != EOK && ret != ENOENT) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "groups by filter [%d]: %s\n", ret, sss_strerror(ret));
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    ret = ifp_groups_list_copy(list_ctx, result->ldb_result);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                               "Failed to copy domain result");
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    list_ctx->dom = get_next_domain(list_ctx->dom, SSS_GND_DESCEND);
    if (list_ctx->dom == NULL) {
        return ifp_groups_list_by_name_reply(list_ctx);
    }

    ret = ifp_groups_list_by_name_step(list_ctx);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                               "Failed to start next-domain search");
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }
}

static void ifp_groups_list_by_name_reply(struct ifp_list_ctx *list_ctx)
{
    iface_ifp_groups_ListByDomainAndName_finish(list_ctx->sbus_req,
                                               list_ctx->paths,
                                               list_ctx->path_count);
}

static void ifp_groups_list_by_domain_and_name_done(struct tevent_req *req);

int ifp_groups_list_by_domain_and_name(struct sbus_request *sbus_req,
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

    req = cache_req_group_by_filter_send(list_ctx, ctx->rctx->ev, ctx->rctx,
                                         CACHE_REQ_ANY_DOM,
                                         domain, filter);
    if (req == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(req,
                            ifp_groups_list_by_domain_and_name_done, list_ctx);

    return EOK;
}

static void ifp_groups_list_by_domain_and_name_done(struct tevent_req *req)
{
    DBusError *error;
    struct ifp_list_ctx *list_ctx;
    struct sbus_request *sbus_req;
    struct cache_req_result *result;
    errno_t ret;

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
                               "groups by filter [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = ifp_groups_list_copy(list_ctx, result->ldb_result);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                               "Failed to copy domain result");
        goto done;
    }

done:
    if (ret != EOK) {
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    iface_ifp_groups_ListByDomainAndName_finish(sbus_req,
                                                list_ctx->paths,
                                                list_ctx->path_count);
    return;
}

static errno_t
ifp_groups_get_from_cache(struct sbus_request *sbus_req,
                         struct sss_domain_info *domain,
                         const char *key,
                         struct ldb_message **_group)
{
    struct ldb_result *group_res;
    errno_t ret;
    gid_t gid;

    switch (domain->type) {
    case DOM_TYPE_POSIX:
        gid = strtouint32(key, NULL, 10);
        ret = errno;
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid UID value\n");
            return ret;
        }

        ret = sysdb_getgrgid_with_views(sbus_req, domain, gid, &group_res);
        if (ret == EOK && group_res->count == 0) {
            *_group = NULL;
            return ENOENT;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup group %u@%s [%d]: %s\n",
                  gid, domain->name, ret, sss_strerror(ret));
            return ret;
        }
        break;
    case DOM_TYPE_APPLICATION:
        ret = sysdb_getgrnam_with_views(sbus_req, domain, key, &group_res);
        if (ret == EOK && group_res->count == 0) {
            *_group = NULL;
            return ENOENT;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup group %s@%s [%d]: %s\n",
                  key, domain->name, ret, sss_strerror(ret));
            return ret;
        }
        break;
    }

    if (group_res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "More groups matched by the single key\n");
        return EIO;
    }

    *_group = group_res->msgs[0];
    return EOK;
}

static errno_t
ifp_groups_group_get(struct sbus_request *sbus_req,
                     void *data,
                     struct sss_domain_info **_domain,
                     struct ldb_message **_group)
{
    struct ifp_ctx *ctx;
    struct sss_domain_info *domain;
    char *key;
    errno_t ret;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return ERR_INTERNAL;
    }

    ret = ifp_groups_decompose_path(sbus_req,
                                    ctx->rctx->domains, sbus_req->path,
                                    &domain, &key);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to decompose object path"
              "[%s] [%d]: %s\n", sbus_req->path, ret, sss_strerror(ret));
        return ret;
    }

    if (_group != NULL) {
        ret = ifp_groups_get_from_cache(sbus_req, domain, key, _group);
    }

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
    void *data;

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
                                             void *data)
{
    struct resolv_ghosts_state *state;
    struct sss_domain_info *domain;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ldb_message *group;
    struct ifp_ctx *ctx;
    const char *name;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct resolv_ghosts_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        ret = ERR_INTERNAL;
        goto immediately;
    }

    state->ev = ev;
    state->sbus_req = sbus_req;
    state->ctx = ctx;
    state->data = data;

    ret = ifp_groups_group_get(sbus_req, data, &domain, &group);
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
    struct ldb_message_element *el;
    struct ldb_message *group;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct resolv_ghosts_state);

    ret = ifp_groups_group_get(state->sbus_req, state->data,
                               &state->domain, &group);
    if (ret != EOK) {
        goto done;
    }

    el = ldb_msg_find_element(group, SYSDB_GHOST);
    if (el == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (el->num_values == 0) {
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

static void ifp_groups_group_update_member_list_done(struct tevent_req *req);

int ifp_groups_group_update_member_list(struct sbus_request *sbus_req,
                                        void *data)
{
    struct tevent_req *subreq;
    struct ifp_ctx *ctx;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return ERR_INTERNAL;
    }

    subreq = resolv_ghosts_send(sbus_req, ctx->rctx->ev, sbus_req, data);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ifp_groups_group_update_member_list_done,
                            sbus_req);

    return EOK;
}

static void ifp_groups_group_update_member_list_done(struct tevent_req *subreq)
{
    DBusError *error;
    struct sbus_request *sbus_req;
    errno_t ret;

    sbus_req = tevent_req_callback_data(subreq, struct sbus_request);

    ret = resolv_ghosts_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED,
                               "Unable to resolve ghost members [%d]: %s\n",
                               ret, sss_strerror(ret));
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    iface_ifp_groups_group_UpdateMemberList_finish(sbus_req);
    return;
}

void ifp_groups_group_get_name(struct sbus_request *sbus_req,
                               void *data,
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

    ret = ifp_groups_group_get(sbus_req, data, &domain, &msg);
    if (ret != EOK) {
        *_out = NULL;
        return;
    }

    in_name = sss_view_ldb_msg_find_attr_as_string(domain, msg,
                                                   SYSDB_NAME, NULL);
    if (in_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "No name?\n");
        return;
    }

    *_out = ifp_format_name_attr(sbus_req, ifp_ctx, in_name, domain);
    return;
}

void ifp_groups_group_get_gid_number(struct sbus_request *sbus_req,
                                     void *data,
                                     uint32_t *_out)
{
    struct ldb_message *msg;
    struct sss_domain_info *domain;
    errno_t ret;

    ret = ifp_groups_group_get(sbus_req, data, &domain, &msg);
    if (ret != EOK) {
        *_out = 0;
        return;
    }

    *_out = sss_view_ldb_msg_find_attr_as_uint64(domain, msg, SYSDB_GIDNUM, 0);

    return;
}

void ifp_groups_group_get_unique_id(struct sbus_request *sbus_req,
                                    void *data,
                                    const char **_out)
{
    struct ldb_message *msg;
    struct sss_domain_info *domain;
    errno_t ret;

    ret = ifp_groups_group_get(sbus_req, data, &domain, &msg);
    if (ret != EOK) {
        *_out = 0;
        return;
    }

    *_out = sss_view_ldb_msg_find_attr_as_string(domain, msg, SYSDB_UUID, 0);

    return;
}

static errno_t
ifp_groups_group_get_members(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             void *data,
                             const char ***_users,
                             int *_num_users,
                             const char ***_groups,
                             int *_num_groups)
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
    const char *attrs[] = {SYSDB_OBJECTCLASS, SYSDB_UIDNUM,
                           SYSDB_GIDNUM, NULL};

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = ifp_groups_group_get(sbus_req, data, &domain, &group);
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
        num_users = 0;
        num_groups = 0;
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
        class = ldb_msg_find_attr_as_string(members[i], SYSDB_OBJECTCLASS,
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

        if (_num_users != NULL) {
            *_num_users = num_users;
        }

        if (_groups != NULL) {
            *_groups = talloc_steal(mem_ctx, groups);
        }

        if (_num_groups != NULL) {
            *_num_groups = num_groups;
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

void ifp_groups_group_get_users(struct sbus_request *sbus_req,
                                void *data,
                                const char ***_out,
                                int *_size)
{
    errno_t ret;

    *_out = NULL;
    *_size = 0;

    ret = ifp_groups_group_get_members(sbus_req, sbus_req, data, _out, _size,
                                       NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to acquire groups members\n");
    }
}

void ifp_groups_group_get_groups(struct sbus_request *sbus_req,
                                void *data,
                                const char ***_out,
                                int *_size)
{
    errno_t ret;

    *_out = NULL;
    *_size = 0;

    ret = ifp_groups_group_get_members(sbus_req, sbus_req, data, NULL, NULL,
                                       _out, _size);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to acquire groups members\n");
    }
}

int ifp_cache_list_group(struct sbus_request *sbus_req,
                         void *data)
{
    return ifp_cache_list(sbus_req, data, IFP_CACHE_GROUP);
}

int ifp_cache_list_by_domain_group(struct sbus_request *sbus_req,
                                   void *data,
                                   const char *domain)
{
    return ifp_cache_list_by_domain(sbus_req, data, domain, IFP_CACHE_GROUP);
}

int ifp_cache_object_store_group(struct sbus_request *sbus_req,
                                 void *data)
{
    DBusError *error;
    struct sss_domain_info *domain;
    struct ldb_message *group;
    errno_t ret;

    ret = ifp_groups_group_get(sbus_req, data, &domain, &group);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "group [%d]: %s\n", ret, sss_strerror(ret));
        return sbus_request_fail_and_finish(sbus_req, error);
    }

    /* The request is finished inside. */
    return ifp_cache_object_store(sbus_req, domain, group->dn);
}

int ifp_cache_object_remove_group(struct sbus_request *sbus_req,
                                  void *data)
{
    DBusError *error;
    struct sss_domain_info *domain;
    struct ldb_message *group;
    errno_t ret;

    ret = ifp_groups_group_get(sbus_req, data, &domain, &group);
    if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "group [%d]: %s\n", ret, sss_strerror(ret));
        return sbus_request_fail_and_finish(sbus_req, error);
    }

    /* The request is finished inside. */
    return ifp_cache_object_remove(sbus_req, domain, group->dn);
}
