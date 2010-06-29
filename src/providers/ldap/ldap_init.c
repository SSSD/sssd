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
#include "providers/ldap/sdap_access.h"

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

/* Access Handler */
struct bet_ops sdap_access_ops = {
    .handler = sdap_pam_access_handler,
    .finalize = sdap_shutdown
};

int sssm_ldap_id_init(struct be_ctx *bectx,
                      struct bet_ops **ops,
                      void **pvt_data)
{
    struct sdap_id_ctx *ctx;
    const char *urls;
    const char *dns_service_name;
    int ret;

    /* If we're already set up, just return that */
    if(bectx->bet_info[BET_ID].mod_name &&
       strcmp("ldap", bectx->bet_info[BET_ID].mod_name) == 0) {
        DEBUG(8, ("Re-using sdap_id_ctx for this provider\n"));
        *ops = bectx->bet_info[BET_ID].bet_ops;
        *pvt_data = bectx->bet_info[BET_ID].pvt_bet_data;
        return EOK;
    }

    ctx = talloc_zero(bectx, struct sdap_id_ctx);
    if (!ctx) return ENOMEM;

    ctx->be = bectx;

    ret = ldap_get_options(ctx, bectx->cdb,
                           bectx->conf_path, &ctx->opts);
    if (ret != EOK) {
        goto done;
    }

    dns_service_name = dp_opt_get_string(ctx->opts->basic,
                                         SDAP_DNS_SERVICE_NAME);
    DEBUG(7, ("Service name for discovery set to %s\n", dns_service_name));

    urls = dp_opt_get_string(ctx->opts->basic, SDAP_URI);
    if (!urls) {
        DEBUG(1, ("Missing ldap_uri, will use service discovery\n"));
    }

    ret = sdap_service_init(ctx, ctx->be, "LDAP",
                            dns_service_name, urls, &ctx->service);
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

    ret = sdap_id_conn_cache_create(ctx, ctx->be,
                                    ctx->opts, ctx->service,
                                    &ctx->conn_cache);
    if (ret != EOK) {
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
    const char *dns_service_name;
    int ret;

    ctx = talloc(bectx, struct sdap_auth_ctx);
    if (!ctx) return ENOMEM;

    ctx->be = bectx;

    ret = ldap_get_options(ctx, bectx->cdb,
                           bectx->conf_path, &ctx->opts);
    if (ret != EOK) {
        goto done;
    }

    dns_service_name = dp_opt_get_string(ctx->opts->basic,
                                         SDAP_DNS_SERVICE_NAME);
    DEBUG(7, ("Service name for discovery set to %s\n", dns_service_name));

    urls = dp_opt_get_string(ctx->opts->basic, SDAP_URI);
    if (!urls) {
        DEBUG(1, ("Missing ldap_uri, will use service discovery\n"));
    }

    ret = sdap_service_init(ctx, ctx->be, "LDAP", dns_service_name,
                            urls, &ctx->service);
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

int sssm_ldap_access_init(struct be_ctx *bectx,
                          struct bet_ops **ops,
                          void **pvt_data)
{
    int ret;
    struct sdap_access_ctx *access_ctx;
    const char *filter;

    access_ctx = talloc_zero(bectx, struct sdap_access_ctx);
    if(access_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sssm_ldap_id_init(bectx, ops, (void **)&access_ctx->id_ctx);
    if (ret != EOK) {
        DEBUG(1, ("sssm_ldap_id_init failed.\n"));
        goto done;
    }

    filter = dp_opt_get_cstring(access_ctx->id_ctx->opts->basic,
                                            SDAP_ACCESS_FILTER);
    if (filter == NULL) {
        /* It's okay if this is NULL. In that case we will simply act
         * like the 'deny' provider.
         */
        DEBUG(0, ("Warning: access_provider=ldap set, "
                  "but no ldap_access_filter configured. "
                  "All domain users will be denied access.\n"));
    }
    else {
        if (filter[0] == '(') {
            /* This filter is wrapped in parentheses.
             * Pass it as-is to the openldap libraries.
             */
            access_ctx->filter = filter;
        }
        else {
            /* Add parentheses around the filter */
            access_ctx->filter = talloc_asprintf(access_ctx, "(%s)", filter);
            if (access_ctx->filter == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }
    }

    *ops = &sdap_access_ops;
    *pvt_data = access_ctx;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(access_ctx);
    }
    return ret;
}

static void sdap_shutdown(struct be_req *req)
{
    /* TODO: Clean up any internal data */
    sdap_handler_done(req, DP_ERR_OK, EOK, NULL);
}

