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

#include <errno.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/dp_backend.h"
#include "db/sysdb.h"
#include "providers/simple/simple_access.h"

#define CONFDB_SIMPLE_ALLOW_USERS "simple_allow_users"
#define CONFDB_SIMPLE_DENY_USERS "simple_deny_users"

errno_t simple_access_check(struct simple_ctx *ctx, const char *username,
                            bool *access_granted)
{
    int i;

    *access_granted = false;
    if (ctx->allow_users != NULL) {
        for(i = 0; ctx->allow_users[i] != NULL; i++) {
            if (strcmp(username, ctx->allow_users[i]) == 0) {
                DEBUG(9, ("User [%s] found in allow list, access granted.\n",
                      username));
                *access_granted = true;
                return EOK;
            }
        }
    } else {
        *access_granted = true;
        if (ctx->deny_users != NULL) {
            for(i = 0; ctx->deny_users[i] != NULL; i++) {
                if (strcmp(username, ctx->deny_users[i]) == 0) {
                    DEBUG(9, ("User [%s] found in deny list, access denied.\n",
                          username));
                    *access_granted = false;
                    return EOK;
                }
            }
        }
    }

    return EOK;
}

void simple_access_handler(struct be_req *be_req)
{
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

    ctx = talloc_get_type(be_req->be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
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
    be_req->fn(be_req, DP_ERR_OK, pd->pam_status, NULL);
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

    if (ctx->allow_users != NULL && ctx->deny_users != NULL) {
        DEBUG(1, ("Access and deny list are defined, only one is allowed.\n"));
        ret = EINVAL;
        goto failed;
    }


    *ops = &simple_access_ops;
    *pvt_data = ctx;

    return EOK;

failed:
    talloc_free(ctx);
    return ret;
}
