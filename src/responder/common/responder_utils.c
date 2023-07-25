
/*
   SSSD

   Common Responder utility functions

   Copyright (C) Sumit Bose <sbose@redhat.com> 2014

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

#include "db/sysdb.h"
#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"
#include "util/util.h"

static inline bool
attr_in_list(const char **list, size_t nlist, const char *str)
{
    return string_in_list_size(str, list, nlist, false);
}

const char **parse_attr_list_ex(TALLOC_CTX *mem_ctx, const char *conf_str,
                                const char **defaults)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char **list = NULL;
    const char **res = NULL;
    int list_size;
    char **conf_list = NULL;
    int conf_list_size = 0;
    const char **allow = NULL;
    const char **deny = NULL;
    int ai = 0, di = 0, li = 0;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    if (conf_str) {
        ret = split_on_separator(tmp_ctx, conf_str, ',', true, true,
                                 &conf_list, &conf_list_size);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot parse attribute ACL list  %s: %d\n", conf_str, ret);
            goto done;
        }

        allow = talloc_zero_array(tmp_ctx, const char *, conf_list_size);
        deny = talloc_zero_array(tmp_ctx, const char *, conf_list_size);
        if (allow == NULL || deny == NULL) {
            goto done;
        }
    }

    for (i = 0; i < conf_list_size; i++) {
        switch (conf_list[i][0]) {
            case '+':
                allow[ai] = conf_list[i] + 1;
                ai++;
                continue;
            case '-':
                deny[di] = conf_list[i] + 1;
                di++;
                continue;
            default:
                DEBUG(SSSDBG_CRIT_FAILURE, "ACL values must start with "
                      "either '+' (allow) or '-' (deny), got '%s'\n",
                      conf_list[i]);
                goto done;
        }
    }

    /* Assume the output will have to hold defaults and all the configured,
     * values, resize later
     */
    list_size = 0;
    if (defaults != NULL) {
        while (defaults[list_size]) {
            list_size++;
        }
    }
    list_size += conf_list_size;

    list = talloc_zero_array(tmp_ctx, const char *, list_size + 1);
    if (list == NULL) {
        goto done;
    }

    /* Start by copying explicitly allowed attributes */
    for (i = 0; i < ai; i++) {
        /* if the attribute is explicitly denied, skip it */
        if (attr_in_list(deny, di, allow[i])) {
            continue;
        }

        /* If the attribute is already in the list, skip it */
        if (attr_in_list(list, li, allow[i])) {
            continue;
        }

        list[li] = talloc_strdup(list, allow[i]);
        if (list[li] == NULL) {
            goto done;
        }
        li++;

        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Added allowed attr %s to whitelist\n", allow[i]);
    }

    /* Add defaults */
    if (defaults != NULL) {
        for (i = 0; defaults[i]; i++) {
            /* if the attribute is explicitly denied, skip it */
            if (attr_in_list(deny, di, defaults[i])) {
                continue;
            }

            /* If the attribute is already in the list, skip it */
            if (attr_in_list(list, li, defaults[i])) {
                continue;
            }

            list[li] = talloc_strdup(list, defaults[i]);
            if (list[li] == NULL) {
                goto done;
            }
            li++;

            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Added default attr %s to whitelist\n", defaults[i]);
        }
    }

    res = talloc_steal(mem_ctx, list);
done:
    talloc_free(tmp_ctx);
    return res;
}

char *sss_resp_create_fqname(TALLOC_CTX *mem_ctx,
                             struct resp_ctx *rctx,
                             struct sss_domain_info *dom,
                             bool name_is_upn,
                             const char *orig_name)
{
    TALLOC_CTX *tmp_ctx;
    char *name;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    name = sss_get_cased_name(tmp_ctx, orig_name, dom->case_sensitive);
    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_get_cased_name failed\n");
        talloc_free(tmp_ctx);
        return NULL;
    }

    name = sss_reverse_replace_space(tmp_ctx, name, rctx->override_space);
    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_reverse_replace_space failed\n");
        talloc_free(tmp_ctx);
        return NULL;
    }


    if (name_is_upn == false) {
        name = sss_create_internal_fqname(tmp_ctx, name, dom->name);
        if (name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_create_internal_fqname failed\n");
            talloc_free(tmp_ctx);
            return NULL;
        }
    }

    name = talloc_steal(mem_ctx, name);
    talloc_free(tmp_ctx);
    return name;
}

struct resp_resolve_group_names_state {
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    struct sss_domain_info *dom;
    struct ldb_result *initgr_res;

    bool needs_refresh;
    unsigned int group_iter;
    bool is_original_primary_group_request;

    struct ldb_result *initgr_named_res;
};

static void resp_resolve_group_done(struct tevent_req *subreq);
static errno_t resp_resolve_group_next(struct tevent_req *req);
static errno_t resp_resolve_group_trigger_request(struct tevent_req *req, const char *attr_name);
static errno_t resp_resolve_group_reread_names(struct resp_resolve_group_names_state *state);

struct tevent_req *resp_resolve_group_names_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct resp_ctx *rctx,
                                                 struct sss_domain_info *dom,
                                                 struct ldb_result *initgr_res)
{
    struct resp_resolve_group_names_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct resp_resolve_group_names_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }
    state->ev = ev;
    state->rctx = rctx;
    state->dom = dom;
    state->initgr_res = initgr_res;
    state->is_original_primary_group_request = true;

    ret = resp_resolve_group_next(req);
    if (ret == EOK) {
        goto immediate;
    } else if (ret != EAGAIN) {
        goto immediate;
    }

    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static bool
resp_resolve_group_needs_refresh(struct resp_resolve_group_names_state *state)
{
    /* Refresh groups that have a non-zero GID,
     * but are marked as non-POSIX
     */
    bool is_posix;
    uint64_t gid;
    struct ldb_message *group_msg;

    group_msg = state->initgr_res->msgs[state->group_iter];

    is_posix = ldb_msg_find_attr_as_bool(group_msg, SYSDB_POSIX, false);
    gid = ldb_msg_find_attr_as_uint64(group_msg, SYSDB_GIDNUM, 0);

    if (is_posix == false && gid != 0) {
        return true;
    }

    return false;
}

static errno_t resp_resolve_group_next(struct tevent_req *req)
{
    struct resp_resolve_group_names_state *state;
    errno_t ret;

    state = tevent_req_data(req, struct resp_resolve_group_names_state);

    while (state->group_iter < state->initgr_res->count
           && !resp_resolve_group_needs_refresh(state)) {
        state->group_iter++;
    }

    if (state->group_iter >= state->initgr_res->count) {
        /* All groups were refreshed */
        return EOK;
    }

    if(state->group_iter == 0 &&
       state->is_original_primary_group_request == true) {
        ret = resp_resolve_group_trigger_request(req,
                                                 SYSDB_PRIMARY_GROUP_GIDNUM);

        /* If auto_private_groups is disabled then
         * resp_resolve_group_trigger_request will return EINVAL, but this
         * doesn't mean a failure. Thus, the search should continue with the
         * next element.
         */
        if(ret == EINVAL) {
            state->is_original_primary_group_request = false;
            return resp_resolve_group_trigger_request(req, SYSDB_GIDNUM);
        } else {
            return ret;
        }
    } else {
        return resp_resolve_group_trigger_request(req, SYSDB_GIDNUM);
    }
}

static errno_t resp_resolve_group_trigger_request(struct tevent_req *req,
                                                  const char *attr_name)
{
    struct cache_req_data *data;
    uint64_t gid;
    struct tevent_req *subreq;
    struct resp_resolve_group_names_state *state;

    state = tevent_req_data(req, struct resp_resolve_group_names_state);

    gid = ldb_msg_find_attr_as_uint64(state->initgr_res->msgs[state->group_iter],
                                      attr_name, 0);
    if (gid == 0) {
        return EINVAL;
    }

    data = cache_req_data_id_attrs(state, CACHE_REQ_GROUP_BY_ID, gid, NULL);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set cache request data!\n");
        return ENOMEM;
    }

    subreq = cache_req_send(state,
                            state->ev,
                            state->rctx,
                            state->rctx->ncache,
                            0,
                            CACHE_REQ_ANY_DOM,
                            NULL,
                            data);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send cache request!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, resp_resolve_group_done, req);
    return EAGAIN;
}

static void resp_resolve_group_done(struct tevent_req *subreq)
{
    struct resp_resolve_group_names_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct resp_resolve_group_names_state);

    ret = cache_req_single_domain_recv(state, subreq, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to refresh group\n");
        /* Try to refresh the others on error */
    }

    if(state->group_iter == 0 &&
       state->is_original_primary_group_request == true) {
        state->is_original_primary_group_request = false;
    } else {
        state->group_iter++;
    }
    state->needs_refresh = true;

    ret = resp_resolve_group_next(req);
    if (ret == EOK) {
        ret = resp_resolve_group_reread_names(state);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
        DEBUG(SSSDBG_TRACE_FUNC, "All groups are refreshed, done\n");
        tevent_req_done(req);
        return;
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        return;
    }

    /* Continue refreshing.. */
}

static errno_t
resp_resolve_group_reread_names(struct resp_resolve_group_names_state *state)
{
    errno_t ret;
    const char *username;

    /* re-read reply in case any groups were renamed */
    /* msgs[0] is the user entry */
    username = sss_view_ldb_msg_find_attr_as_string(state->dom,
                                                    state->initgr_res->msgs[0],
                                                    SYSDB_NAME,
                                                    NULL);
    if (username == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "A user with no name?\n");
        return EINVAL;
    }

    ret = sysdb_initgroups_with_views(state,
                                      state->dom,
                                      username,
                                      &state->initgr_named_res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot re-read the group names\n");
        return ret;
    }

    return EOK;
}

int resp_resolve_group_names_recv(TALLOC_CTX *mem_ctx,
                                  struct tevent_req *req,
                                  struct ldb_result **_initgr_named_res)
{
    struct resp_resolve_group_names_state *state = NULL;
    state = tevent_req_data(req, struct resp_resolve_group_names_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_initgr_named_res = talloc_steal(mem_ctx, state->initgr_named_res);
    return EOK;
}

const char *
sss_resp_get_shell_override(struct ldb_message *msg,
                            struct resp_ctx *rctx,
                            struct sss_domain_info *domain)
{
    const char *shell;
    int i;

    /* Here we skip the files provider as it should always return *only*
     * what's in the files and nothing else. */
    if (!is_files_provider(domain)) {
        /* Check whether we are unconditionally overriding
         * the server for the login shell. */
        if (domain->override_shell) {
            return domain->override_shell;
        } else if (rctx->override_shell) {
            return rctx->override_shell;
        }
    }

    shell = sss_view_ldb_msg_find_attr_as_string(domain, msg, SYSDB_SHELL,
                                                 NULL);
    if (shell == NULL) {
        /* Check whether there is a default shell specified */
        if (domain->default_shell) {
            return domain->default_shell;
        } else if (rctx->default_shell) {
            return rctx->default_shell;
        }

        return "";
    }

    if (rctx->allowed_shells == NULL && rctx->vetoed_shells == NULL) {
        return shell;
    }

    if (rctx->vetoed_shells) {
        for (i = 0; rctx->vetoed_shells[i]; i++) {
            if (strcmp(rctx->vetoed_shells[i], shell) == 0) {
                DEBUG(SSSDBG_FUNC_DATA,
                      "The shell '%s' is vetoed. Using fallback.\n",
                      shell);
                return rctx->shell_fallback;
            }
        }
    }

    if (rctx->etc_shells) {
        for (i = 0; rctx->etc_shells[i]; i++) {
            if (strcmp(shell, rctx->etc_shells[i]) == 0) {
                DEBUG(SSSDBG_TRACE_ALL,
                      "Shell %s found in /etc/shells\n", shell);
                break;
            }
        }

        if (rctx->etc_shells[i]) {
            DEBUG(SSSDBG_TRACE_ALL, "Using original shell '%s'\n", shell);
            return shell;
        }
    }

    if (rctx->allowed_shells) {
        if (strcmp(rctx->allowed_shells[0], "*") == 0) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "The shell '%s' is allowed but does not exist. "
                  "Using fallback\n", shell);
            return rctx->shell_fallback;
        } else {
            for (i = 0; rctx->allowed_shells[i]; i++) {
                if (strcmp(rctx->allowed_shells[i], shell) == 0) {
                    DEBUG(SSSDBG_FUNC_DATA,
                          "The shell '%s' is allowed but does not exist. "
                          "Using fallback\n", shell);
                    return rctx->shell_fallback;
                }
            }
        }
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "The shell '%s' is not allowed and does not exist.\n", shell);

    return NOLOGIN_SHELL;
}
