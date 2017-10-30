/*
    SSSD

    files_init.c - Initialization of the files provider

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

#include "providers/data_provider/dp.h"
#include "providers/files/files_private.h"

int sssm_files_init(TALLOC_CTX *mem_ctx,
                    struct be_ctx *be_ctx,
                    struct data_provider *provider,
                    const char *module_name,
                    void **_module_data)
{
    struct files_id_ctx *ctx;
    int ret;
    const char *passwd_file = NULL;
    const char *group_file = NULL;

    /* So far this is mostly useful for tests */
    passwd_file = getenv("SSS_FILES_PASSWD");
    if (passwd_file == NULL) {
        passwd_file = "/etc/passwd";
    }

    group_file = getenv("SSS_FILES_GROUP");
    if (group_file == NULL) {
        group_file = "/etc/group";
    }

    ctx = talloc_zero(mem_ctx, struct files_id_ctx);
    if (ctx == NULL) {
        return ENOMEM;
    }
    ctx->be = be_ctx;
    ctx->domain = be_ctx->domain;
    ctx->passwd_file = passwd_file;
    ctx->group_file = group_file;

    ctx->fctx = sf_init(ctx, be_ctx->ev,
                        ctx->passwd_file, ctx->group_file,
                        ctx);
    if (ctx->fctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_module_data = ctx;
    ret = EOK;
done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sssm_files_id_init(TALLOC_CTX *mem_ctx,
                       struct be_ctx *be_ctx,
                       void *module_data,
                       struct dp_method *dp_methods)
{
    struct files_id_ctx *ctx;

    ctx = talloc_get_type(module_data, struct files_id_ctx);
    if (ctx == NULL) {
        return EINVAL;
    }

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  files_account_info_handler_send,
                  files_account_info_handler_recv,
                  ctx, struct files_id_ctx,
                  struct dp_id_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send,
                  default_account_domain_recv,
                  NULL, void,
                  struct dp_get_acct_domain_data, struct dp_reply_std);

    return EOK;
}
