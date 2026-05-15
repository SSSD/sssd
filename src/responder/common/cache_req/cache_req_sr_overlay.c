/*
    Authors:
        Nikolai Kondrashov <Nikolai.Kondrashov@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include "db/sysdb.h"
#include "responder/common/cache_req/cache_req_private.h"

struct cache_req_sr_overlay_state {
    /* Input data */
    struct tevent_context *ev;
    struct cache_req *cr;
    struct cache_req_result **results;
    size_t num_results;
    /* Work data */
    size_t res_idx;
    size_t msg_idx;
};

static errno_t cache_req_sr_overlay_match_users(
                                struct cache_req_sr_overlay_state *state);

static errno_t cache_req_sr_overlay_match_users(
                                struct cache_req_sr_overlay_state *state);

static struct tevent_req *cache_req_sr_overlay_match_all_step_send(
                                struct cache_req_sr_overlay_state *state);

static void cache_req_sr_overlay_match_all_step_done(
                                struct tevent_req *subreq);

struct tevent_req *cache_req_sr_overlay_send(
                                TALLOC_CTX *mem_ctx,
                                struct tevent_context *ev,
                                struct cache_req *cr,
                                struct cache_req_result **results,
                                size_t num_results)
{
    errno_t ret = EOK;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct cache_req_sr_overlay_state *state;
    struct resp_ctx *rctx = cr->rctx;

    req = tevent_req_create(mem_ctx, &state,
                            struct cache_req_sr_overlay_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->cr = cr;
    state->results = results;
    state->num_results = num_results;

    /* If session recording is selective */
    if (rctx->sr_conf.scope != SESSION_RECORDING_SCOPE_NONE) {
        /* If it's a request for a user/users */
        switch (cr->data->type) {
        case CACHE_REQ_USER_BY_NAME:
        case CACHE_REQ_USER_BY_UPN:
        case CACHE_REQ_USER_BY_ID:
        case CACHE_REQ_ENUM_USERS:
            /* If we have group names to match against */
            if ((rctx->sr_conf.groups != NULL &&
                 rctx->sr_conf.groups[0] != NULL) ||
                (rctx->sr_conf.exclude_groups != NULL &&
                 rctx->sr_conf.exclude_groups[0] != NULL)) {
                /* Pull and match group and user names for each user entry */
                subreq = cache_req_sr_overlay_match_all_step_send(state);
                if (subreq == NULL) {
                    CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, state->cr,
                                    "Failed allocating a session recording "
                                    "user overlay request\n");
                    ret = ENOMEM;
                    goto done;
                }
                tevent_req_set_callback(
                    subreq, cache_req_sr_overlay_match_all_step_done, req);
                ret = EAGAIN;
            } else {
                /* Only match user names for each user entry */
                ret = cache_req_sr_overlay_match_users(state);
            }
            break;
        default:
            break;
        }
    }

done:
    if (ret != EAGAIN) {
        if (ret == EOK) {
            tevent_req_done(req);
        } else {
            tevent_req_error(req, ret);
        }
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t cache_req_sr_overlay_match_users(
                                struct cache_req_sr_overlay_state *state)
{
    struct cache_req *cr;
    struct resp_ctx *rctx;
    errno_t ret;
    int lret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct cache_req_result *result;
    struct ldb_message *msg;
    const char *name;
    char *output_name;
    char **conf_user;
    char **conf_exclude_user;
    bool enabled;
    char *enabled_str;

    cr = state->cr;
    rctx = cr->rctx;

    /* Create per-message talloc context */
    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                        "Failed creating temporary talloc context\n");
        ret = ENOMEM;
        goto done;
    }

    /* For each result */
    for (state->res_idx = 0;
         state->res_idx < state->num_results;
         state->res_idx++) {
        result = state->results[state->res_idx];

        /* For each message */
        for (state->msg_idx = 0;
             state->msg_idx < result->count;
             state->msg_idx++) {
            msg = result->msgs[state->msg_idx];

            /* Format output username */
            name = sss_get_name_from_msg(result->domain, msg);
            ret = sss_output_fqname(tmp_ctx, result->domain, name,
                                    rctx->override_space,
                                    &output_name);
            if (ret != EOK) {
                CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                                "Failed formatting output username from %s: %s\n",
                                name, sss_strerror(ret));
                goto done;
            }

            /* For each user name in session recording config */
            enabled = false;
            conf_user = rctx->sr_conf.users;
            if (rctx->sr_conf.scope == SESSION_RECORDING_SCOPE_SOME) {
                if (conf_user != NULL) {
                    for (; *conf_user != NULL; conf_user++) {
                        /* If it matches the requested user name */
                        if (strcmp(*conf_user, output_name) == 0) {
                            enabled = true;
                            break;
                        }
                    }
                }
            /* For each exclude user name in session recording config */
            } else if (rctx->sr_conf.scope == SESSION_RECORDING_SCOPE_ALL) {
                enabled = true;
                conf_exclude_user = rctx->sr_conf.exclude_users;
                if (conf_exclude_user != NULL) {
                    for (; *conf_exclude_user != NULL; conf_exclude_user++) {
                        /* If it matches the requested user name */
                        if (strcmp(*conf_exclude_user, output_name) == 0) {
                            enabled = false;
                            break;
                        }
                    }
                }
            }

            /* Set sessionRecording attribute to enabled value */
            ldb_msg_remove_attr(msg, SYSDB_SESSION_RECORDING);
            enabled_str = talloc_strdup(tmp_ctx, enabled ? "TRUE" : "FALSE");
            if (enabled_str == NULL) {
                CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                                "Failed to allocate a %s attribute value\n",
                                SYSDB_SESSION_RECORDING);
                ret = ENOMEM;
                goto done;
            }
            lret = ldb_msg_add_string(msg, SYSDB_SESSION_RECORDING, enabled_str);
            if (lret != LDB_SUCCESS) {
                ret = sss_ldb_error_to_errno(lret);
                CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, cr,
                                "Failed adding %s attribute: %s\n",
                                SYSDB_SESSION_RECORDING, sss_strerror(ret));
                goto done;
            }
            talloc_steal(msg, enabled_str);

            /* Free per-message allocations */
            talloc_free_children(tmp_ctx);
        }
    }

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static struct tevent_req *cache_req_sr_overlay_match_all_step_send(
                                struct cache_req_sr_overlay_state *state)
{
    struct cache_req *cr = state->cr;
    struct cache_req_result *result =
                                state->results[state->res_idx];
    const char *name;

    name = ldb_msg_find_attr_as_string(result->msgs[state->msg_idx],
                                       SYSDB_NAME, NULL);
    return cache_req_initgr_by_name_send(state, state->ev, cr->rctx, cr->ncache,
                                         cr->midpoint, CACHE_REQ_ANY_DOM,
                                         NULL, name);
}

static void cache_req_sr_overlay_match_all_step_done(
                                struct tevent_req *subreq)
{
    int lret;
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct tevent_req *req;
    struct cache_req_sr_overlay_state *state;
    struct cache_req_result *result;
    struct ldb_message *msg;
    const char *enabled;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct cache_req_sr_overlay_state);
    msg = state->results[state->res_idx]->
                    msgs[state->msg_idx];

    /* Create temporary allocation context */
    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, state->cr,
                        "Failed creating temporary talloc context\n");
        ret = ENOMEM;
        goto done;
    }

    /* Get initgroups result */
    ret = cache_req_initgr_by_name_recv(tmp_ctx, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, state->cr,
                        "Failed retrieving initgr request results: %s\n",
                        sss_strerror(ret));
        goto done;
    }

    /* Overwrite sessionRecording attribute */
    ldb_msg_remove_attr(msg, SYSDB_SESSION_RECORDING);
    enabled = ldb_msg_find_attr_as_string(result->msgs[0],
                                          SYSDB_SESSION_RECORDING, NULL);
    if (enabled != NULL) {
        char *enabled_copy;
        enabled_copy = talloc_strdup(tmp_ctx, enabled);
        if (enabled_copy == NULL) {
            CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, state->cr,
                            "Failed to allocate a copy of %s attribute\n",
                            SYSDB_SESSION_RECORDING);
            ret = ENOMEM;
            goto done;
        }
        lret = ldb_msg_add_string(msg, SYSDB_SESSION_RECORDING, enabled_copy);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, state->cr,
                            "Failed adding %s attribute: %s\n",
                            SYSDB_SESSION_RECORDING, sss_strerror(ret));
            goto done;
        }
        talloc_steal(msg, enabled_copy);
    }

    /* Move onto next entry, if any */
    state->msg_idx++;
    if (state->msg_idx >=
            state->results[state->res_idx]->count) {
        state->res_idx++;
        if (state->res_idx >= state->num_results) {
            ret = EOK;
            goto done;
        }
        state->msg_idx = 0;
    }

    /* Schedule next entry overlay */
    subreq = cache_req_sr_overlay_match_all_step_send(state);
    if (subreq == NULL) {
        ret = ENOMEM;
        CACHE_REQ_DEBUG(SSSDBG_CRIT_FAILURE, state->cr,
                        "Failed allocating a session recording "
                        "user overlay request\n");
        goto done;
    }
    tevent_req_set_callback(subreq,
                            cache_req_sr_overlay_match_all_step_done, req);
    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
    talloc_free(tmp_ctx);
}

errno_t cache_req_sr_overlay_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}
