/*
   SSSD

   Simple access control

   Copyright (C) Sumit Bose <sbose@redhat.com> 2010

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

#include <security/pam_modules.h>

#include "providers/simple/simple_access.h"
#include "providers/simple/simple_access_pvt.h"
#include "util/sss_utf8.h"
#include "providers/backend.h"
#include "db/sysdb.h"

#define CONFDB_SIMPLE_ALLOW_USERS "simple_allow_users"
#define CONFDB_SIMPLE_DENY_USERS "simple_deny_users"

#define CONFDB_SIMPLE_ALLOW_GROUPS "simple_allow_groups"
#define CONFDB_SIMPLE_DENY_GROUPS "simple_deny_groups"

#define TIMEOUT_OF_REFRESH_FILTER_LISTS 5

static errno_t simple_access_parse_names(TALLOC_CTX *mem_ctx,
                                         struct be_ctx *be_ctx,
                                         char **list,
                                         char ***_out)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char **out = NULL;
    size_t size;
    size_t i;
    errno_t ret;
    char *domname = NULL;
    char *shortname = NULL;
    struct sss_domain_info *domain;

    if (list == NULL) {
        *_out = NULL;
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        ret = ENOMEM;
        goto done;
    }

    for (size = 0; list[size] != NULL; size++) {
        /* count size */
    }

    out = talloc_zero_array(tmp_ctx, char*, size + 1);
    if (out == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        ret = ENOMEM;
        goto done;
    }

    /* Since this is access provider, we should fail on any error so we don't
     * allow unauthorized access. */
    for (i = 0; i < size; i++) {
        ret = sss_parse_name(tmp_ctx, be_ctx->domain->names, list[i],
                             &domname, &shortname);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_parse_name failed [%d]: %s\n",
                ret, sss_strerror(ret));
            goto done;
        }

        if (domname != NULL) {
            domain = find_domain_by_name(be_ctx->domain, domname, true);
            if (domain == NULL) {
                ret = ERR_DOMAIN_NOT_FOUND;
                goto done;
            }
        } else {
            domain = be_ctx->domain;
        }

        out[i] = sss_create_internal_fqname(out, shortname, domain->name);
        if (out[i] == NULL) {
            ret = EIO;
            goto done;
        }
    }

    *_out = talloc_steal(mem_ctx, out);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int simple_access_obtain_filter_lists(struct simple_ctx *ctx)
{
    struct be_ctx *bectx = ctx->be_ctx;
    int ret;
    int i;
    struct {
        const char *name;
        const char *option;
        char **orig_list;
        char **ctx_list;
    } lists[] = {{"Allow users", CONFDB_SIMPLE_ALLOW_USERS, NULL, NULL},
                 {"Deny users", CONFDB_SIMPLE_DENY_USERS, NULL, NULL},
                 {"Allow groups", CONFDB_SIMPLE_ALLOW_GROUPS, NULL, NULL},
                 {"Deny groups", CONFDB_SIMPLE_DENY_GROUPS, NULL, NULL},
                 {NULL, NULL, NULL, NULL}};


    ret = sysdb_master_domain_update(bectx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_FUNC_DATA, "Update of master domain failed [%d]: %s.\n",
                                 ret, sss_strerror(ret));
        goto failed;
    }

    for (i = 0; lists[i].name != NULL; i++) {
        ret = confdb_get_string_as_list(bectx->cdb, ctx, bectx->conf_path,
                                        lists[i].option, &lists[i].orig_list);
        if (ret == ENOENT) {
            DEBUG(SSSDBG_FUNC_DATA, "%s list is empty.\n", lists[i].name);
            continue;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "confdb_get_string_as_list failed.\n");
            goto failed;
        }

        ret = simple_access_parse_names(ctx, bectx, lists[i].orig_list,
                                        &lists[i].ctx_list);
        talloc_free(lists[i].orig_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse %s list [%d]: %s\n",
                                        lists[i].name, ret, sss_strerror(ret));
            goto failed;
        }
    }

    talloc_free(ctx->allow_users);
    ctx->allow_users = talloc_steal(ctx, lists[0].ctx_list);

    talloc_free(ctx->deny_users);
    ctx->deny_users = talloc_steal(ctx, lists[1].ctx_list);

    talloc_free(ctx->allow_groups);
    ctx->allow_groups = talloc_steal(ctx, lists[2].ctx_list);

    talloc_free(ctx->deny_groups);
    ctx->deny_groups = talloc_steal(ctx, lists[3].ctx_list);

    if (!ctx->allow_users &&
            !ctx->allow_groups &&
            !ctx->deny_users &&
            !ctx->deny_groups) {
        DEBUG(SSSDBG_OP_FAILURE,
              "No rules supplied for simple access provider. "
               "Access will be granted for all users.\n");
    }


    return EOK;

failed:
    for (i = 0; lists[i].name != NULL; i++) {
        talloc_free(lists[i].ctx_list);
    }

    return ret;
}

struct simple_access_handler_state {
    struct pam_data *pd;
};

static void simple_access_handler_done(struct tevent_req *subreq);

struct tevent_req *
simple_access_handler_send(TALLOC_CTX *mem_ctx,
                           struct simple_ctx *simple_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params)
{
    struct simple_access_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;
    time_t now;

    req = tevent_req_create(mem_ctx, &state,
                            struct simple_access_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;

    pd->pam_status = PAM_SYSTEM_ERR;
    if (pd->cmd != SSS_PAM_ACCT_MGMT) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "simple access does not handle pam task %d.\n", pd->cmd);
        pd->pam_status = PAM_MODULE_UNKNOWN;
        goto immediately;
    }

    now = time(NULL);
    if ((now - simple_ctx->last_refresh_of_filter_lists)
        > TIMEOUT_OF_REFRESH_FILTER_LISTS) {

        ret = simple_access_obtain_filter_lists(simple_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to refresh filter lists, denying all access\n");
            pd->pam_status = PAM_PERM_DENIED;
            goto immediately;
        }
        simple_ctx->last_refresh_of_filter_lists = now;
    }

    subreq = simple_access_check_send(state, params->ev, simple_ctx, pd->user);
    if (subreq == NULL) {
        pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;
    }

    tevent_req_set_callback(subreq, simple_access_handler_done, req);

    return req;

immediately:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void simple_access_handler_done(struct tevent_req *subreq)
{
    struct simple_access_handler_state *state;
    struct tevent_req *req;
    bool access_granted;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct simple_access_handler_state);

    ret = simple_access_check_recv(subreq, &access_granted);
    talloc_free(subreq);
    if (ret != EOK) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    if (access_granted) {
        state->pd->pam_status = PAM_SUCCESS;
    } else {
        state->pd->pam_status = PAM_PERM_DENIED;
    }

done:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

errno_t
simple_access_handler_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct pam_data **_data)
{
    struct simple_access_handler_state *state = NULL;

    state = tevent_req_data(req, struct simple_access_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}

errno_t sssm_simple_access_init(TALLOC_CTX *mem_ctx,
                                struct be_ctx *be_ctx,
                                void *module_data,
                                struct dp_method *dp_methods)
{
    struct simple_ctx *ctx;
    int ret;
    int i;
    char *simple_list_values = NULL;
    const char *simple_access_lists[] = {CONFDB_SIMPLE_ALLOW_USERS,
                                         CONFDB_SIMPLE_DENY_USERS,
                                         CONFDB_SIMPLE_ALLOW_GROUPS,
                                         CONFDB_SIMPLE_DENY_GROUPS,
                                         NULL};

    ctx = talloc_zero(mem_ctx, struct simple_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed.\n");
        return ENOMEM;
    }

    for (i = 0; simple_access_lists[i] != NULL; i++) {
        ret = confdb_get_string(be_ctx->cdb, mem_ctx, be_ctx->conf_path,
                                simple_access_lists[i], NULL,
                                &simple_list_values);

        if (simple_list_values == NULL) {
            continue;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "confdb_get_string failed.\n");
            return ret;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "%s values: [%s]\n",
                                     simple_access_lists[i],
                                     simple_list_values);
    }

    ctx->domain = be_ctx->domain;
    ctx->be_ctx = be_ctx;
    ctx->last_refresh_of_filter_lists = 0;

    dp_set_method(dp_methods, DPM_ACCESS_HANDLER,
                  simple_access_handler_send, simple_access_handler_recv, ctx,
                  struct simple_ctx, struct pam_data, struct pam_data *);

    return EOK;
}
