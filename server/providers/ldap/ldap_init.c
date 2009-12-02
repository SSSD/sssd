/*
    SSSD

    LDAP Provider Initialization functions

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include "providers/child_common.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async_private.h"

static void sdap_shutdown(struct be_req *req);

/* Id Handler */
struct bet_ops sdap_id_ops = {
    .handler = sdap_account_info_handler,
    .finalize = sdap_shutdown
};

/* Auth Handler */
struct bet_ops sdap_auth_ops = {
    .handler = sdap_pam_auth_handler,
    .finalize = sdap_shutdown
};

/* Chpass Handler */
struct bet_ops sdap_chpass_ops = {
    .handler = sdap_pam_chpass_handler,
    .finalize = sdap_shutdown
};

int sssm_ldap_init(struct be_ctx *bectx,
                   struct bet_ops **ops,
                   void **pvt_data)
{
    struct sdap_id_ctx *ctx;
    const char *urls;
    int ret;

    ctx = talloc_zero(bectx, struct sdap_id_ctx);
    if (!ctx) return ENOMEM;

    ctx->be = bectx;

    ret = ldap_get_options(ctx, bectx->cdb,
                           bectx->conf_path, &ctx->opts);
    if (ret != EOK) {
        goto done;
    }

    urls = dp_opt_get_string(ctx->opts->basic, SDAP_URI);
    if (!urls) {
        DEBUG(0, ("Missing ldap_uri\n"));
        ret = EINVAL;
        goto done;
    }

    ret = sdap_service_init(ctx, ctx->be, "LDAP", urls, &ctx->service);
    if (ret != EOK) {
        DEBUG(1, ("Failed to initialize failover service!\n"));
        goto done;
    }

    ret = setup_tls_config(ctx->opts->basic);
    if (ret != EOK) {
        DEBUG(1, ("setup_tls_config failed [%d][%s].\n",
                  ret, strerror(ret)));
        goto done;
    }

    ret = sdap_id_setup_tasks(ctx);
    if (ret != EOK) {
        goto done;
    }

    ret = setup_child(ctx);
    if (ret != EOK) {
        DEBUG(1, ("setup_child failed [%d][%s].\n",
                  ret, strerror(ret)));
        goto done;
    }

    *ops = &sdap_id_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sssm_ldap_auth_init(struct be_ctx *bectx,
                        struct bet_ops **ops,
                        void **pvt_data)
{
    struct sdap_auth_ctx *ctx;
    const char *urls;
    int ret;

    ctx = talloc(bectx, struct sdap_auth_ctx);
    if (!ctx) return ENOMEM;

    ctx->be = bectx;

    ret = ldap_get_options(ctx, bectx->cdb,
                           bectx->conf_path, &ctx->opts);
    if (ret != EOK) {
        goto done;
    }

    urls = dp_opt_get_string(ctx->opts->basic, SDAP_URI);
    if (!urls) {
        DEBUG(0, ("Missing ldap_uri\n"));
        ret = EINVAL;
        goto done;
    }

    ret = sdap_service_init(ctx, ctx->be, "LDAP", urls, &ctx->service);
    if (ret != EOK) {
        DEBUG(1, ("Failed to initialize failover service!\n"));
        goto done;
    }

    ret = setup_tls_config(ctx->opts->basic);
    if (ret != EOK) {
        DEBUG(1, ("setup_tls_config failed [%d][%s].\n",
                  ret, strerror(ret)));
        goto done;
    }

    *ops = &sdap_auth_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sssm_ldap_chpass_init(struct be_ctx *bectx,
                          struct bet_ops **ops,
                          void **pvt_data)
{
    int ret;

    ret = sssm_ldap_auth_init(bectx, ops, pvt_data);

    *ops = &sdap_chpass_ops;

    return ret;
}

static void sdap_shutdown(struct be_req *req)
{
    /* TODO: Clean up any internal data */
    sdap_handler_done(req, DP_ERR_OK, EOK, NULL);
}

