/*
    SSSD

    Himmelblau Provider - Initialization

    Authors:
        David Mulder <dmulder@suse.com>

    Copyright (C) 2026 SUSE

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

#include "config.h"

#include "providers/himmelblau/himmelblau_common.h"
#include "providers/himmelblau/himmelblau_opts.h"
#include "confdb/confdb.h"

errno_t sssm_himmelblau_init(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             struct data_provider *provider,
                             const char *module_name,
                             void **_module_data)
{
    struct himmelblau_init_ctx *init_ctx;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Initializing himmelblau provider\n");

    init_ctx = talloc_zero(mem_ctx, struct himmelblau_init_ctx);
    if (init_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return ENOMEM;
    }

    init_ctx->be_ctx = be_ctx;

    /* Get options from confdb */
    ret = dp_get_options(init_ctx, be_ctx->cdb, be_ctx->conf_path,
                         default_himmelblau_opts, HIMMELBLAU_OPTS,
                         &init_ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "dp_get_options() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Get domain from options */
    init_ctx->domain = dp_opt_get_string(init_ctx->opts, HIMMELBLAU_DOMAIN);
    if (init_ctx->domain == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Option " CONFDB_HIMMELBLAU_DOMAIN " is required\n");
        ret = EINVAL;
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Himmelblau domain: %s\n", init_ctx->domain);

    /* Get device storage path from options */
    init_ctx->device_storage_path = dp_opt_get_string(init_ctx->opts,
                                                       HIMMELBLAU_DEVICE_STORAGE);

    DEBUG(SSSDBG_CONF_SETTINGS, "Device storage path: %s\n",
          init_ctx->device_storage_path);

    *_module_data = init_ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(init_ctx);
    }

    return ret;
}

errno_t sssm_himmelblau_auth_init(TALLOC_CTX *mem_ctx,
                                  struct be_ctx *be_ctx,
                                  void *module_data,
                                  struct dp_method *dp_methods)
{
    struct himmelblau_init_ctx *init_ctx;
    struct himmelblau_auth_ctx *auth_ctx;

    DEBUG(SSSDBG_TRACE_FUNC, "Initializing himmelblau auth target\n");

    init_ctx = talloc_get_type(module_data, struct himmelblau_init_ctx);

    auth_ctx = talloc_zero(init_ctx, struct himmelblau_auth_ctx);
    if (auth_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return ENOMEM;
    }

    auth_ctx->be_ctx = be_ctx;
    auth_ctx->init_ctx = init_ctx;
    auth_ctx->domain = init_ctx->domain;
    auth_ctx->device_storage_path = init_ctx->device_storage_path;

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  himmelblau_pam_handler_send, himmelblau_pam_handler_recv,
                  auth_ctx,
                  struct himmelblau_auth_ctx, struct pam_data, struct pam_data *);

    init_ctx->auth_ctx = auth_ctx;

    DEBUG(SSSDBG_TRACE_FUNC, "Himmelblau auth target initialized\n");

    return EOK;
}

errno_t sssm_himmelblau_id_init(TALLOC_CTX *mem_ctx,
                                struct be_ctx *be_ctx,
                                void *module_data,
                                struct dp_method *dp_methods)
{
    struct himmelblau_init_ctx *init_ctx;
    struct himmelblau_id_ctx *id_ctx;

    DEBUG(SSSDBG_TRACE_FUNC, "Initializing himmelblau id target\n");

    init_ctx = talloc_get_type(module_data, struct himmelblau_init_ctx);

    id_ctx = talloc_zero(init_ctx, struct himmelblau_id_ctx);
    if (id_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return ENOMEM;
    }

    id_ctx->be_ctx = be_ctx;
    id_ctx->init_ctx = init_ctx;
    id_ctx->domain = init_ctx->domain;

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  himmelblau_account_info_handler_send,
                  himmelblau_account_info_handler_recv,
                  id_ctx,
                  struct himmelblau_id_ctx, struct dp_id_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send, default_account_domain_recv, NULL,
                  void, struct dp_get_acct_domain_data, struct dp_reply_std);

    init_ctx->id_ctx = id_ctx;

    DEBUG(SSSDBG_TRACE_FUNC, "Himmelblau id target initialized\n");

    return EOK;
}
