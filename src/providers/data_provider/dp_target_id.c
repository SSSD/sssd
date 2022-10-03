/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include "sbus/sbus_request.h"
#include "sss_iface/sss_iface_async.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/backend.h"
#include "util/util.h"

#define FILTER_TYPE(str, type) {str "=", sizeof(str "=") - 1, type}

static bool check_and_parse_filter(struct dp_id_data *data,
                                   const char *filter,
                                   const char *extra)
{
    /* We will use sizeof() to determine the length of a string so we don't
     * call strlen over and over again with each request. Not a bottleneck,
     * but unnecessary and simple to avoid. */
    static struct {
        const char *name;
        size_t lenght;
        uint32_t type;
    } types[] = {FILTER_TYPE("name", BE_FILTER_NAME),
                 FILTER_TYPE("idnumber", BE_FILTER_IDNUM),
                 FILTER_TYPE(DP_SEC_ID, BE_FILTER_SECID),
                 FILTER_TYPE(DP_CERT, BE_FILTER_CERT),
                 FILTER_TYPE(DP_WILDCARD, BE_FILTER_WILDCARD),
                 {0, 0, 0}};
    int i;

    if (SBUS_REQ_STRING_IS_EMPTY(filter)) {
        return false;
    }

    for (i = 0; types[i].name != NULL; i++) {
        if (strncmp(filter, types[i].name, types[i].lenght) == 0) {
            data->filter_type = types[i].type;
            data->filter_value = SBUS_REQ_STRING(&filter[types[i].lenght]);
            data->extra_value = SBUS_REQ_STRING(extra);
            return true;
        }
    }

    if (strcmp(filter, ENUM_INDICATOR) == 0) {
        data->filter_type = BE_FILTER_ENUM;
        data->filter_value = NULL;
        data->extra_value = NULL;
        return true;
    }

    return false;
}

struct dp_initgr_ctx {
    const char *domain;
    struct sss_domain_info *domain_info;
    const char *filter_value;
    const char *username;
    uint32_t gnum;
    uint32_t *groups;
};

static errno_t
dp_create_initgroups_ctx(TALLOC_CTX *mem_ctx,
                         struct be_ctx *be_ctx,
                         struct dp_id_data *data,
                         struct dp_initgr_ctx **_ctx)
{
    struct sss_domain_info *domain;
    struct dp_initgr_ctx *ctx;
    struct ldb_result *res;
    const char *username;
    unsigned int i;
    errno_t ret;

    if (data->domain == NULL) {
        domain = be_ctx->domain;
    } else {
        domain = find_domain_by_name(be_ctx->domain, data->domain, true);
        if (domain == NULL) {
            return ERR_DOMAIN_NOT_FOUND;
        }
    }

    ctx = talloc_zero(mem_ctx, struct dp_initgr_ctx);
    if (ctx == NULL) {
        return ENOMEM;
    }

    ctx->domain = data->domain;
    ctx->filter_value = data->filter_value;
    ctx->domain_info = domain;

    ret = sysdb_initgroups(ctx, domain, data->filter_value, &res);
    if (ret == ENOENT || (ret == EOK && res->count == 0)) {
        *_ctx = ctx;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get initgroups [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Copy original username */
    username = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    if (username == NULL) {
        ret = EINVAL;
        goto done;
    }

    ctx->username = talloc_strdup(ctx, username);
    if (ctx->username == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Copy group IDs */
    ctx->groups = talloc_zero_array(mem_ctx, uint32_t, res->count + 1);
    if (ctx->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* The first GID is the primary so it might be duplicated
     * later in the list. */
    for (ctx->gnum = 0, i = 0; i < res->count; i++) {
        ctx->groups[ctx->gnum] = ldb_msg_find_attr_as_uint(res->msgs[i],
                                                           SYSDB_GIDNUM, 0);
        /* If 0 it may be a non-POSIX group, so we skip it. */
        if (ctx->groups[ctx->gnum] != 0) {
            ctx->gnum++;
        }
    }

    *_ctx = ctx;
    talloc_free(res);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }

    return ret;
}

static void dp_req_initgr_pp_sr_overlay(struct data_provider *provider,
                                        struct dp_initgr_ctx *ctx)
{
    bool enabled = false;
    struct be_ctx *be = provider->be_ctx;
    struct ldb_result *res;
    struct ldb_message *msg;
    const char *name;
    char *output_name;
    char **conf_user;
    char **conf_group;
    char **conf_exclude_user;
    char **conf_exclude_group;
    size_t i;
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    struct ldb_message_element el = { 0, SYSDB_SESSION_RECORDING, 0, NULL };
    struct sysdb_attrs del_attrs = { 1, &el };
    struct sysdb_attrs *add_attrs;

    /* Only proceed if scope is applicable: 'some' or 'all' */
    if (be->sr_conf.scope == SESSION_RECORDING_SCOPE_NONE) {
        goto done;
    }

    /* Default to enabled when scope is 'all' */
    enabled = be->sr_conf.scope == SESSION_RECORDING_SCOPE_ALL ? true : false;

    /* Allocate temporary talloc context */
    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed creating temporary talloc context\n");
        goto done;
    }

    /* Get updated initgroups data with overrides */
    ret = sysdb_initgroups_with_views(tmp_ctx, ctx->domain_info,
                                      ctx->filter_value, &res);
    if (ret == ENOENT || (ret == EOK && res->count == 0)) {
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get initgroups: %s\n",
              sss_strerror(ret));
        goto done;
    }

    /* Delete sessionRecording attribute so we know when we failed */
    ret = sysdb_set_entry_attr(ctx->domain_info->sysdb, res->msgs[0]->dn,
                               &del_attrs, SYSDB_MOD_DEL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed removing %s attribute: %s\n",
              SYSDB_SESSION_RECORDING, sss_strerror(ret));
        goto done;
    }

    /* Format output username */
    name = sss_get_name_from_msg(ctx->domain_info, res->msgs[0]);
    ret = sss_output_fqname(tmp_ctx, ctx->domain_info, name,
                            be->override_space, &output_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed formatting output username from \"%s\": %s\n",
              name, sss_strerror(ret));
        goto done;
    }

    /* For each user name in session recording config */
    conf_user = be->sr_conf.users;
    if (conf_user != NULL) {
        for (; *conf_user != NULL && !enabled; conf_user++) {
            /* If it matches the requested user name */
            if (strcmp(*conf_user, output_name) == 0) {
                enabled = true;
            }
        }
    }

    /* For each exclude user name in session recording config */
    conf_exclude_user = be->sr_conf.exclude_users;
    if (conf_exclude_user != NULL &&
            be->sr_conf.scope == SESSION_RECORDING_SCOPE_ALL) {
        for (; *conf_exclude_user != NULL && enabled; conf_exclude_user++) {
            if (strcmp(*conf_exclude_user, output_name) == 0) {
                enabled = false;
            }
        }
    }

    /* If we have groups in config and are not yet enabled */
    if ((be->sr_conf.scope == SESSION_RECORDING_SCOPE_SOME &&
        be->sr_conf.groups != NULL &&
        be->sr_conf.groups[0] != NULL &&
        !enabled) ||
        /* Or if we have exclude_groups in config and are enabled */
        (be->sr_conf.scope == SESSION_RECORDING_SCOPE_ALL &&
        be->sr_conf.exclude_groups != NULL &&
        be->sr_conf.exclude_groups[0] != NULL &&
        enabled)) {
        /* For each group in response */
        for (i = 0; i < res->count; i++) {
            /* Get the group msg */
            if (i == 0) {
                gid_t gid;
                struct ldb_result *group_res;

                /* Get the primary group */
                gid = sss_view_ldb_msg_find_attr_as_uint64(ctx->domain_info,
                                                           res->msgs[i],
                                                           SYSDB_GIDNUM, 0);
                if (gid == 0) {
                    continue;
                }
                ret = sysdb_getgrgid_with_views(tmp_ctx, ctx->domain_info,
                                                gid, &group_res);
                if (ret == ENOENT) {
                    continue;
                } else if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Failed retrieving group #%llu: %s\n",
                          (unsigned long long)gid, sss_strerror(ret));
                    goto done;
                } else if (group_res->count == 0) {
                    continue;
                }
                msg = group_res->msgs[0];
            } else {
                msg = res->msgs[i];
            }
            /* Get the group's output name */
            name = sss_get_name_from_msg(ctx->domain_info, msg);
            if (name == NULL) {
                continue;
            }
            ret = sss_output_fqname(tmp_ctx, ctx->domain_info,
                                    name, be->override_space,
                                    &output_name);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed formatting output group name from \"%s\": %s\n",
                      name, sss_strerror(ret));
                goto done;
            }
            /* For each group in configuration */
            if (be->sr_conf.scope == SESSION_RECORDING_SCOPE_SOME) {
                for (conf_group = be->sr_conf.groups;
                     *conf_group != NULL && !enabled;
                     conf_group++) {
                    if (strcmp(*conf_group, output_name) == 0) {
                        enabled = true;
                    }
                }
            /* For each exclude group in configuration */
            } else if (be->sr_conf.scope == SESSION_RECORDING_SCOPE_ALL) {
                for (conf_exclude_group = be->sr_conf.exclude_groups;
                     *conf_exclude_group != NULL && enabled;
                     conf_exclude_group++) {
                    if (strcmp(*conf_exclude_group, output_name) == 0) {
                        enabled = false;
                    }
                }
            }

            /* Found a matched group */
            if ((be->sr_conf.scope == SESSION_RECORDING_SCOPE_SOME
                && enabled) ||
                (be->sr_conf.scope == SESSION_RECORDING_SCOPE_ALL
                && !enabled)) {
                break;
            }
        }
    }

    /* Set sessionRecording attribute to enabled value */
    add_attrs = sysdb_new_attrs(tmp_ctx);
    if (add_attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed creating attributes\n");
        goto done;
    }
    ret = sysdb_attrs_add_bool(add_attrs, SYSDB_SESSION_RECORDING, enabled);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed setting %s attribute: %s\n",
              SYSDB_SESSION_RECORDING, sss_strerror(ret));
        goto done;
    }
    ret = sysdb_set_entry_attr(ctx->domain_info->sysdb, res->msgs[0]->dn,
                               add_attrs, SYSDB_MOD_ADD);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed storing %s attribute: %s\n",
              SYSDB_SESSION_RECORDING, sss_strerror(ret));
        goto done;
    }

done:
    talloc_free(tmp_ctx);
}

errno_t dp_add_sr_attribute(struct be_ctx *be_ctx)
{
    int ret;
    struct dp_initgr_ctx *dp_initgr_ctx = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    struct dp_id_data *data;
    size_t msgs_count;
    struct ldb_message **msgs = NULL;
    const char *attrs[] = {SYSDB_NAME, NULL};
    size_t c;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = sysdb_search_users(tmp_ctx, be_ctx->domain, "("SYSDB_NAME "=*)", attrs,
                            &msgs_count, &msgs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_users failed.\n");
        goto done;
    }

    data = talloc_zero(tmp_ctx, struct dp_id_data);
    if (data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    data->entry_type = BE_REQ_INITGROUPS;
    data->filter_type = BE_FILTER_NAME;
    data->filter_value = NULL;
    data->extra_value = NULL;
    data->domain = be_ctx->domain->name;

    for (c = 0; c < msgs_count; c++) {
        data->filter_value = ldb_msg_find_attr_as_string(msgs[c], SYSDB_NAME,
                                                         NULL);
        if (data->filter_value == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cache object [%s] does not have a name, skipping.\n",
                  ldb_dn_get_linearized(msgs[c]->dn));
            continue;
        }

        talloc_free(dp_initgr_ctx);
        ret = dp_create_initgroups_ctx(tmp_ctx, be_ctx, data, &dp_initgr_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "dp_create_initgroups_ctx failed.\n");
            goto done;
        }

        dp_req_initgr_pp_sr_overlay(be_ctx->provider, dp_initgr_ctx);
    }

done:
    talloc_free(tmp_ctx);

    return ret;
}

static void dp_req_initgr_pp_set_initgr_timestamp(struct dp_initgr_ctx *ctx,
                                                  struct dp_reply_std *reply)
{
    errno_t ret;

    if (reply->dp_error != DP_ERR_OK || reply->error != EOK) {
        /* Only bump the timestamp on successful lookups */
        return;
    }

    ret = sysdb_set_initgr_expire_timestamp(ctx->domain_info,
                                            ctx->filter_value);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to set initgroups expiration for [%s]\n",
              ctx->filter_value);
    }
}


struct dp_sr_resolve_groups_state {
    struct data_provider *provider;
    struct dp_initgr_ctx *initgroups_ctx;
    struct dp_reply_std reply;

    uint32_t *resolve_gids; /* Groups needing resolution */
    int resolve_gnum;
    int num_iter;
    uint32_t gnum;
};

static errno_t dp_sr_resolve_groups_check(struct dp_sr_resolve_groups_state *state);
static errno_t dp_sr_resolve_groups_next(struct tevent_req *req);
static void dp_sr_resolve_groups_done(struct tevent_req *subreq);

struct tevent_req *
dp_sr_resolve_groups_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct dp_reply_std reply,
                          struct data_provider *provider,
                          struct dp_initgr_ctx *initgr_ctx)
{

    struct dp_sr_resolve_groups_state *state;
    struct tevent_req *req;
    int ret;
    struct session_recording_conf sr_conf;

    req = tevent_req_create(mem_ctx, &state, struct dp_sr_resolve_groups_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    if (initgr_ctx->username == NULL) {
        ret = EOK;
        goto done;
    }

    sr_conf = provider->be_ctx->sr_conf;

    /* Only proceed if scope is applicable: 'some' or 'all' with groups to resolve */
    if ((sr_conf.scope == SESSION_RECORDING_SCOPE_SOME && sr_conf.groups != NULL)
         || (sr_conf.scope == SESSION_RECORDING_SCOPE_ALL && sr_conf.exclude_groups != NULL)) {
        state->provider = provider;
        state->initgroups_ctx = initgr_ctx;
        state->reply = reply;
        state->gnum = initgr_ctx->gnum;

        /* Check if group is intermediate(has gidNumber and isPosix == False) */
        state->resolve_gids = talloc_zero_array(state, uint32_t, initgr_ctx->gnum + 1);
        if (state->resolve_gids == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = dp_sr_resolve_groups_check(state);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed checking groups to resolve\n");
            goto done;
        }

        state->num_iter = 0;
        ret = dp_sr_resolve_groups_next(req);
        if (ret == EAGAIN) {
            /* async processing */
            return req;
        }
    } else {
        ret = EOK;
        goto done;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t dp_sr_resolve_groups_next(struct tevent_req *req)
{
    struct dp_sr_resolve_groups_state *state;
    struct tevent_req *subreq;
    struct dp_id_data *ar;
    uint32_t gid;

    state = tevent_req_data(req, struct dp_sr_resolve_groups_state);

    if (state->num_iter >= state->resolve_gnum) {
        return EOK;
    }

    gid = state->resolve_gids[state->num_iter];

    ar = talloc_zero(state, struct dp_id_data);
    if (ar == NULL) {
        return ENOMEM;
    }

    ar->entry_type = BE_REQ_GROUP;
    ar->filter_type = BE_FILTER_IDNUM;
    ar->filter_value = talloc_asprintf(ar, "%llu", (unsigned long long) gid);
    ar->domain = talloc_strdup(ar, state->initgroups_ctx->domain_info->name);
    if (!ar->domain || !ar->filter_value) {
        return ENOMEM;
    }

    subreq = dp_req_send(state, state->provider, ar->domain,
                         "DP Resolve Group", 0, NULL,
                         DPT_ID, DPM_ACCOUNT_HANDLER, 0, ar, NULL);
    if (!subreq) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, dp_sr_resolve_groups_done, req);

    state->num_iter++;
    return EAGAIN;
}

static void dp_sr_resolve_groups_done(struct tevent_req *subreq)
{
    struct dp_sr_resolve_groups_state *state;
    struct tevent_req *req;
    struct dp_reply_std *reply;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct dp_sr_resolve_groups_state);

    ret = dp_req_recv_ptr(state, subreq, struct dp_reply_std, &reply);
    talloc_free(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Try next group */
    ret = dp_sr_resolve_groups_next(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

errno_t dp_sr_resolve_groups_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req)
{

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static errno_t
dp_sr_resolve_groups_check(struct dp_sr_resolve_groups_state *state)
{
    errno_t ret;
    struct ldb_message *group;
    struct ldb_result *res;
    struct sss_domain_info *domain_info;
    const char *group_attrs[] = { SYSDB_NAME, SYSDB_POSIX,
                                  SYSDB_GIDNUM, NULL };
    uint32_t gid;
    const char *name;
    const char *val;

    domain_info = state->initgroups_ctx->domain_info;

    ret = sysdb_initgroups(state, domain_info, state->initgroups_ctx->username, &res);
    if (ret == ENOENT || (ret == EOK && res->count == 0)) {
        return EOK;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get initgroups [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    /* Get GID */
    for (int i = 0; i < res->count; i++) {
        gid = sss_view_ldb_msg_find_attr_as_uint64(domain_info,
                                                   res->msgs[i],
                                                   SYSDB_GIDNUM, 0);
        if (gid == 0) {
            continue;
        }
        DEBUG(SSSDBG_TRACE_ALL, "Checking if group needs to be resolved: [%d]\n",
                                gid);

        /* Check the cache by GID again and fetch the name */
        ret = sysdb_search_group_by_gid(state, state->initgroups_ctx->domain_info, gid,
                                        group_attrs, &group);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Could not look up group by gid [%"SPRIgid"]: [%d][%s]\n",
                  gid, ret, sss_strerror(ret));
            continue;
        }

        name = ldb_msg_find_attr_as_string(group, SYSDB_NAME, NULL);
        if (!name) {
            DEBUG(SSSDBG_OP_FAILURE, "No group name\n");
            continue;
        }

        val = ldb_msg_find_attr_as_string(group, SYSDB_POSIX, NULL);

        /* Group needs to be resolved */
        if ((strcasecmp(val, "FALSE") == 0) && gid > 0) {
            state->resolve_gids[state->resolve_gnum] = gid;
            state->resolve_gnum++;
        }
    }

    return EOK;
}


struct dp_get_account_info_state {
    const char *request_name;
    bool initgroups;

    struct tevent_context *ev;
    struct data_provider *provider;
    struct dp_id_data *data;
    struct dp_reply_std reply;
    struct dp_initgr_ctx *initgr_ctx;
};

static void dp_get_account_info_request_done(struct tevent_req *subreq);
static errno_t dp_get_account_info_initgroups_step(struct tevent_req *req);
static void dp_get_account_info_initgroups_resolv_done(struct tevent_req *subreq);
static void dp_get_account_info_done(struct tevent_req *subreq);

struct tevent_req *
dp_get_account_info_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sbus_request *sbus_req,
                         struct data_provider *provider,
                         uint32_t dp_flags,
                         uint32_t entry_type,
                         const char *filter,
                         const char *domain,
                         const char *extra,
                         uint32_t cli_id)
{
    struct dp_get_account_info_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct dp_get_account_info_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->data = talloc_zero(state, struct dp_id_data);
    if (state->data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->ev = ev;
    state->provider = provider;
    state->request_name = "Account";
    state->initgroups = false;
    state->data->entry_type = entry_type;
    state->data->domain = domain;

    if (!check_and_parse_filter(state->data, filter, extra)) {
        ret = EINVAL;
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "Got request for [%#"PRIx32"][%s][%s]\n",
          state->data->entry_type, be_req2str(state->data->entry_type),
          filter);

    if ((state->data->entry_type & BE_REQ_TYPE_MASK) == BE_REQ_INITGROUPS) {
        state->request_name = "Initgroups";
        state->initgroups = true;

        ret = dp_create_initgroups_ctx(state, provider->be_ctx, state->data,
                                       &state->initgr_ctx);
        if (ret != EOK) {
            goto done;
        }
    }

    subreq = dp_req_send(state, provider, domain, state->request_name,
                         cli_id, sbus_req->sender->name, DPT_ID,
                         DPM_ACCOUNT_HANDLER, dp_flags, state->data,
                         &state->request_name);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, dp_get_account_info_request_done, req);

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

static void dp_get_account_info_request_done(struct tevent_req *subreq)
{
    struct dp_get_account_info_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct dp_get_account_info_state);

    ret = dp_req_recv(state, subreq, struct dp_reply_std, &state->reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = dp_get_account_info_initgroups_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
}

static errno_t dp_get_account_info_initgroups_step(struct tevent_req *req)
{
    struct dp_get_account_info_state *state;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct dp_get_account_info_state);

    if (state->initgroups == false) {
        return EOK;
    }

    /* Create subrequest to handle SR data */
    subreq = dp_sr_resolve_groups_send(state, state->ev, state->reply,
                                       state->provider, state->initgr_ctx);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, dp_get_account_info_initgroups_resolv_done, req);

    return EAGAIN;
}


static void dp_get_account_info_initgroups_resolv_done(struct tevent_req *subreq)
{
    struct dp_get_account_info_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct dp_get_account_info_state);

    ret = dp_sr_resolve_groups_recv(state, subreq);
    talloc_free(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    dp_req_initgr_pp_set_initgr_timestamp(state->initgr_ctx, &state->reply);
    dp_req_initgr_pp_sr_overlay(state->provider, state->initgr_ctx);

    if (state->initgr_ctx->username != NULL) {
        /* There is no point in contacting NSS responder if user did
         * not exist before this request. */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Ordering NSS responder to update memory cache\n");

        subreq = sbus_call_nss_memcache_UpdateInitgroups_send(state,
                     state->provider->sbus_conn, SSS_BUS_NSS, SSS_BUS_PATH,
                     state->initgr_ctx->username, state->initgr_ctx->domain,
                     state->initgr_ctx->groups);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
            ret = ENOMEM;
            tevent_req_error(req, ret);
            return;
        }

        tevent_req_set_callback(subreq, dp_get_account_info_done, req);
    } else {
        tevent_req_done(req);
    }
}

static void dp_get_account_info_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sbus_call_nss_memcache_UpdateInitgroups_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Error sending sbus message [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
dp_get_account_info_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         uint16_t *_dp_error,
                         uint32_t *_error,
                         const char **_err_msg)
{
    struct dp_get_account_info_state *state;
    state = tevent_req_data(req, struct dp_get_account_info_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    dp_req_reply_std(state->request_name, &state->reply,
                     _dp_error, _error, _err_msg);

    return EOK;
}

static bool
check_and_parse_acct_domain_filter(struct dp_get_acct_domain_data *data,
                                   const char *filter)
{
    /* We will use sizeof() to determine the length of a string so we don't
     * call strlen over and over again with each request. Not a bottleneck,
     * but unnecessary and simple to avoid. */
    static struct {
        const char *name;
        size_t lenght;
        uint32_t type;
    } types[] = {FILTER_TYPE("idnumber", BE_FILTER_IDNUM),
                 FILTER_TYPE(DP_SEC_ID, BE_FILTER_SECID),
                 {0, 0, 0}};
    int i;

    if (SBUS_REQ_STRING_IS_EMPTY(filter)) {
        return false;
    }

    for (i = 0; types[i].name != NULL; i++) {
        if (strncmp(filter, types[i].name, types[i].lenght) == 0) {
            data->filter_type = types[i].type;
            data->filter_value = SBUS_REQ_STRING(&filter[types[i].lenght]);
            return true;
        }
    }

    if (strcmp(filter, ENUM_INDICATOR) == 0) {
        data->filter_type = BE_FILTER_ENUM;
        data->filter_value = NULL;
        return true;
    }

    return false;
}

struct dp_get_account_domain_state {
    struct dp_get_acct_domain_data *data;
    struct dp_reply_std reply;
    const char *request_name;
};

static void dp_get_account_domain_done(struct tevent_req *subreq);

struct tevent_req *
dp_get_account_domain_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sbus_request *sbus_req,
                           struct data_provider *provider,
                           uint32_t dp_flags,
                           uint32_t entry_type,
                           const char *filter,
                           uint32_t cli_id)
{
    struct dp_get_account_domain_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct dp_get_account_domain_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->data = talloc_zero(state, struct dp_get_acct_domain_data);
    if (state->data == NULL) {
        ret = ENOMEM;
        goto done;
    }
    state->data->entry_type = entry_type;

    if (!check_and_parse_acct_domain_filter(state->data, filter)) {
        ret = EINVAL;
        goto done;
    }

    subreq = dp_req_send(state, provider, NULL, "AccountDomain", cli_id,
                         sbus_req->sender->name, DPT_ID, DPM_ACCT_DOMAIN_HANDLER,
                         dp_flags, state->data, &state->request_name);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, dp_get_account_domain_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void dp_get_account_domain_done(struct tevent_req *subreq)
{
    struct dp_get_account_domain_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct dp_get_account_domain_state);

    ret = dp_req_recv(state, subreq, struct dp_reply_std, &state->reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
dp_get_account_domain_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           uint16_t *_dp_error,
                           uint32_t *_error,
                           const char **_err_msg)
{
    struct dp_get_account_domain_state *state;
    state = tevent_req_data(req, struct dp_get_account_domain_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    dp_req_reply_std(state->request_name, &state->reply,
                     _dp_error, _error, _err_msg);

    return EOK;
}

struct default_account_domain_state {
    struct dp_reply_std reply;
};

struct tevent_req *
default_account_domain_send(TALLOC_CTX *mem_ctx,
                            void *unused_ctx,
                            struct dp_get_acct_domain_data *data,
                            struct dp_req_params *params)
{
    struct default_account_domain_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct default_account_domain_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    dp_reply_std_set(&state->reply,
                     DP_ERR_DECIDE, ERR_GET_ACCT_DOM_NOT_SUPPORTED,
                     NULL);
    tevent_req_done(req);
    tevent_req_post(req, params->ev);
    return req;
}

errno_t default_account_domain_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct dp_reply_std *data)
{
    struct default_account_domain_state *state = NULL;

    state = tevent_req_data(req, struct default_account_domain_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}
