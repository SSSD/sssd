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
#include "util/sss_utf8.h"
#include "providers/dp_backend.h"
#include "db/sysdb.h"

#define CONFDB_SIMPLE_ALLOW_USERS "simple_allow_users"
#define CONFDB_SIMPLE_DENY_USERS "simple_deny_users"

#define CONFDB_SIMPLE_ALLOW_GROUPS "simple_allow_groups"
#define CONFDB_SIMPLE_DENY_GROUPS "simple_deny_groups"

#define TIMEOUT_OF_REFRESH_FILTER_LISTS 5

static void simple_access_check(struct tevent_req *req);
static errno_t simple_access_parse_names(TALLOC_CTX *mem_ctx,
                                         struct be_ctx *be_ctx,
                                         char **list,
                                         char ***_out);

static int simple_access_obtain_filter_lists(struct simple_ctx *ctx)
{
    struct be_ctx *bectx = ctx->be_ctx;
    int ret;
    int i;
    struct {
        const char *name;
        const char *option;
        char **orig_list;
        char ***ctx_list;
    } lists[] = {{"Allow users", CONFDB_SIMPLE_ALLOW_USERS, NULL, NULL},
                 {"Deny users", CONFDB_SIMPLE_DENY_USERS, NULL, NULL},
                 {"Allow groups", CONFDB_SIMPLE_ALLOW_GROUPS, NULL, NULL},
                 {"Deny groups", CONFDB_SIMPLE_DENY_GROUPS, NULL, NULL},
                 {NULL, NULL, NULL, NULL}};

    lists[0].ctx_list = &ctx->allow_users;
    lists[1].ctx_list = &ctx->deny_users;
    lists[2].ctx_list = &ctx->allow_groups;
    lists[3].ctx_list = &ctx->deny_groups;

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
            *lists[i].ctx_list = NULL;
            continue;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "confdb_get_string_as_list failed.\n");
            goto failed;
        }

        ret = simple_access_parse_names(ctx, bectx, lists[i].orig_list,
                                        lists[i].ctx_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse %s list [%d]: %s\n",
                                        lists[i].name, ret, sss_strerror(ret));
            goto failed;
        }
    }

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
    return ret;
}

void simple_access_handler(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct pam_data *pd;
    struct tevent_req *req;
    struct simple_ctx *ctx;
    int ret;
    time_t now;

    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);

    pd->pam_status = PAM_SYSTEM_ERR;

    if (pd->cmd != SSS_PAM_ACCT_MGMT) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "simple access does not handle pam task %d.\n", pd->cmd);
        pd->pam_status = PAM_MODULE_UNKNOWN;
        goto done;
    }

    ctx = talloc_get_type(be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                          struct simple_ctx);


    now = time(NULL);
    if ((now - ctx->last_refresh_of_filter_lists)
        > TIMEOUT_OF_REFRESH_FILTER_LISTS) {

        ret = simple_access_obtain_filter_lists(ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to refresh filter lists\n");
        }
        ctx->last_refresh_of_filter_lists = now;
    }

    req = simple_access_check_send(be_req, be_ctx->ev, ctx, pd->user);
    if (!req) {
        pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }
    tevent_req_set_callback(req, simple_access_check, be_req);
    return;

done:
    be_req_terminate(be_req, DP_ERR_OK, pd->pam_status, NULL);
}

static void simple_access_check(struct tevent_req *req)
{
    bool access_granted = false;
    errno_t ret;
    struct pam_data *pd;
    struct be_req *be_req;

    be_req = tevent_req_callback_data(req, struct be_req);
    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);

    ret = simple_access_check_recv(req, &access_granted);
    talloc_free(req);
    if (ret != EOK) {
        pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    if (access_granted) {
        pd->pam_status = PAM_SUCCESS;
    } else {
        pd->pam_status = PAM_PERM_DENIED;
    }

done:
    be_req_terminate(be_req, DP_ERR_OK, pd->pam_status, NULL);
}

static errno_t simple_access_parse_names(TALLOC_CTX *mem_ctx,
                                         struct be_ctx *be_ctx,
                                         char **list,
                                         char ***_out)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char **out = NULL;
    char *domain = NULL;
    char *name = NULL;
    size_t size;
    size_t i;
    errno_t ret;

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
                             &domain, &name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse name '%s' [%d]: %s\n",
                                        list[i], ret, sss_strerror(ret));
            goto done;
        }

        if (domain == NULL || strcasecmp(domain, be_ctx->domain->name) == 0 ||
            (be_ctx->domain->flat_name != NULL &&
             strcasecmp(domain, be_ctx->domain->flat_name) == 0)) {
            /* This object belongs to main SSSD domain. Those users and groups
             * are stored without domain part, so we will strip it off.
             * */
            out[i] = talloc_move(out, &name);
        } else {
            /* Subdomain users and groups are stored as fully qualified names,
             * thus we will remember the domain part.
             *
             * Since subdomains may come and go, we will look for their
             * existence later, during each access check.
             */
            out[i] = talloc_move(out, &list[i]);
        }
    }

    *_out = talloc_steal(mem_ctx, out);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

struct bet_ops simple_access_ops = {
    .handler = simple_access_handler,
    .finalize = NULL
};

int sssm_simple_access_init(struct be_ctx *bectx, struct bet_ops **ops,
                            void **pvt_data)
{
    int ret = EINVAL;
    struct simple_ctx *ctx;
    ctx = talloc_zero(bectx, struct simple_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    ctx->domain = bectx->domain;
    ctx->be_ctx = bectx;
    ctx->last_refresh_of_filter_lists = 0;

    ret = simple_access_obtain_filter_lists(ctx);
    if (ret != EOK) {
        goto failed;
    }

    *ops = &simple_access_ops;
    *pvt_data = ctx;

    return EOK;

failed:
    talloc_free(ctx);
    return ret;
}

