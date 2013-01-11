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

void simple_access_handler(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    int ret;
    bool access_granted = false;
    struct pam_data *pd;
    struct simple_ctx *ctx;

    pd = talloc_get_type(be_req->req_data, struct pam_data);

    pd->pam_status = PAM_SYSTEM_ERR;

    if (pd->cmd != SSS_PAM_ACCT_MGMT) {
        DEBUG(4, ("simple access does not handles pam task %d.\n", pd->cmd));
        pd->pam_status = PAM_MODULE_UNKNOWN;
        goto done;
    }

    ctx = talloc_get_type(be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                          struct simple_ctx);

    ret = simple_access_check(ctx, pd->user, &access_granted);
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
        DEBUG(1, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    ctx->domain = bectx->domain;

    /* Users */
    ret = confdb_get_string_as_list(bectx->cdb, ctx, bectx->conf_path,
                                    CONFDB_SIMPLE_ALLOW_USERS,
                                    &ctx->allow_users);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(9, ("Allow user list is empty.\n"));
            ctx->allow_users = NULL;
        } else {
            DEBUG(1, ("confdb_get_string_as_list failed.\n"));
            goto failed;
        }
    }

    ret = confdb_get_string_as_list(bectx->cdb, ctx, bectx->conf_path,
                                    CONFDB_SIMPLE_DENY_USERS,
                                    &ctx->deny_users);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(9, ("Deny user list is empty.\n"));
            ctx->deny_users = NULL;
        } else {
            DEBUG(1, ("confdb_get_string_as_list failed.\n"));
            goto failed;
        }
    }

    /* Groups */
    ret = confdb_get_string_as_list(bectx->cdb, ctx, bectx->conf_path,
                                    CONFDB_SIMPLE_ALLOW_GROUPS,
                                    &ctx->allow_groups);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(9, ("Allow group list is empty.\n"));
            ctx->allow_groups = NULL;
        } else {
            DEBUG(1, ("confdb_get_string_as_list failed.\n"));
            goto failed;
        }
    }

    ret = confdb_get_string_as_list(bectx->cdb, ctx, bectx->conf_path,
                                    CONFDB_SIMPLE_DENY_GROUPS,
                                    &ctx->deny_groups);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(9, ("Deny user list is empty.\n"));
            ctx->deny_groups = NULL;
        } else {
            DEBUG(1, ("confdb_get_string_as_list failed.\n"));
            goto failed;
        }
    }

    if (!ctx->allow_users &&
            !ctx->allow_groups &&
            !ctx->deny_users &&
            !ctx->deny_groups) {
        DEBUG(SSSDBG_OP_FAILURE, ("No rules supplied for simple access provider. "
                                  "Access will be granted for all users.\n"));
    }

    *ops = &simple_access_ops;
    *pvt_data = ctx;

    return EOK;

failed:
    talloc_free(ctx);
    return ret;
}
