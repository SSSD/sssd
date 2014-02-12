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

#include "util/child_common.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/sdap_sudo.h"
#include "providers/ldap/sdap_autofs.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/fail_over_srv.h"
#include "providers/dp_refresh.h"

static void sdap_shutdown(struct be_req *req);

/* Id Handler */
struct bet_ops sdap_id_ops = {
    .handler = sdap_account_info_handler,
    .finalize = sdap_shutdown,
    .check_online = sdap_check_online
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

/* Please use this only for short lists */
errno_t check_order_list_for_duplicates(char **list,
                                        bool case_sensitive)
{
    size_t c;
    size_t d;
    int cmp;

    for (c = 0; list[c] != NULL; c++) {
        for (d = c + 1; list[d] != NULL; d++) {
            if (case_sensitive) {
                cmp = strcmp(list[c], list[d]);
            } else {
                cmp = strcasecmp(list[c], list[d]);
            }
            if (cmp == 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Duplicate string [%s] found.\n", list[c]);
                return EINVAL;
            }
        }
    }

    return EOK;
}

static int ldap_id_init_internal(struct be_ctx *bectx,
                                 struct bet_ops **ops,
                                 void **pvt_data)
{
    struct sdap_id_ctx *ctx = NULL;
    const char *urls;
    const char *backup_urls;
    const char *dns_service_name;
    const char *sasl_mech;
    struct sdap_service *sdap_service;
    struct sdap_options *opts = NULL;
    int ret;

    /* If we're already set up, just return that */
    if(bectx->bet_info[BET_ID].mod_name &&
       strcmp("ldap", bectx->bet_info[BET_ID].mod_name) == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Re-using sdap_id_ctx for this provider\n");
        *ops = bectx->bet_info[BET_ID].bet_ops;
        *pvt_data = bectx->bet_info[BET_ID].pvt_bet_data;
        return EOK;
    }

    ret = ldap_get_options(bectx, bectx->domain, bectx->cdb,
                           bectx->conf_path, &opts);
    if (ret != EOK) {
        goto done;
    }

    dns_service_name = dp_opt_get_string(opts->basic,
                                         SDAP_DNS_SERVICE_NAME);
    DEBUG(SSSDBG_CONF_SETTINGS,
          "Service name for discovery set to %s\n", dns_service_name);

    urls = dp_opt_get_string(opts->basic, SDAP_URI);
    backup_urls = dp_opt_get_string(opts->basic, SDAP_BACKUP_URI);

    ret = sdap_service_init(bectx, bectx, "LDAP",
                            dns_service_name, urls, backup_urls,
                            &sdap_service);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize failover service!\n");
        goto done;
    }

    ctx = sdap_id_ctx_new(bectx, bectx, sdap_service);
    if (!ctx) {
        ret = ENOMEM;
        goto done;
    }
    ctx->opts = talloc_steal(ctx, opts);

    sasl_mech = dp_opt_get_string(ctx->opts->basic, SDAP_SASL_MECH);
    if (sasl_mech && strcasecmp(sasl_mech, "GSSAPI") == 0) {
        if (dp_opt_get_bool(ctx->opts->basic, SDAP_KRB5_KINIT)) {
            ret = sdap_gssapi_init(ctx, ctx->opts->basic,
                                   ctx->be, ctx->conn->service,
                                   &ctx->krb5_service);
            if (ret !=  EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sdap_gssapi_init failed [%d][%s].\n",
                            ret, strerror(ret));
                goto done;
            }
        }
    }

    ret = setup_tls_config(ctx->opts->basic);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "setup_tls_config failed [%d][%s].\n",
                  ret, strerror(ret));
        goto done;
    }

    /* Set up the ID mapping object */
    ret = sdap_idmap_init(ctx, ctx, &ctx->opts->idmap_ctx);
    if (ret != EOK) goto done;

    ret = sdap_setup_child();
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "setup_child failed [%d][%s].\n",
                  ret, strerror(ret));
        goto done;
    }

    /* setup SRV lookup plugin */
    ret = be_fo_set_dns_srv_lookup_plugin(bectx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set SRV lookup plugin "
                                    "[%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    /* setup periodical refresh of expired records */
    ret = be_refresh_add_cb(bectx->refresh_ctx, BE_REFRESH_TYPE_NETGROUPS,
                            sdap_refresh_netgroups_send,
                            sdap_refresh_netgroups_recv,
                            ctx);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Periodical refresh of netgroups "
              "will not work [%d]: %s\n", ret, strerror(ret));
    }

    *ops = &sdap_id_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(opts);
        talloc_free(ctx);
    }
    return ret;
}

int sssm_ldap_id_init(struct be_ctx *bectx,
                      struct bet_ops **ops,
                      void **pvt_data)
{
    int ret;
    struct sdap_id_ctx *ctx = NULL;

    ret = ldap_id_init_internal(bectx, ops, (void **) &ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldap_id_init_internal failed [%d][%s].\n",
              ret, strerror(ret));
        goto done;
    }

    ret = ldap_id_setup_tasks(ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sdap_id_setup_tasks failed [%d][%s].\n",
              ret, strerror(ret));
        goto done;
    }

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
    void *data;
    struct sdap_id_ctx *id_ctx;
    struct sdap_auth_ctx *ctx;
    int ret;

    ret = ldap_id_init_internal(bectx, ops, &data);
    if (ret == EOK) {
        id_ctx = talloc_get_type(data, struct sdap_id_ctx);

        ctx = talloc(bectx, struct sdap_auth_ctx);
        if (!ctx) return ENOMEM;

        ctx->be = bectx;
        ctx->opts = id_ctx->opts;
        ctx->service = id_ctx->conn->service;
        ctx->chpass_service = NULL;

        *ops = &sdap_auth_ops;
        *pvt_data = ctx;
    }

    return ret;
}

int sssm_ldap_chpass_init(struct be_ctx *bectx,
                          struct bet_ops **ops,
                          void **pvt_data)
{
    int ret;
    void *data;
    struct sdap_auth_ctx *ctx = NULL;
    const char *urls;
    const char *backup_urls;
    const char *dns_service_name;

    ret = sssm_ldap_auth_init(bectx, ops, &data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sssm_ldap_auth_init failed.\n");
        goto done;
    }

    ctx = talloc_get_type(data, struct sdap_auth_ctx);

    dns_service_name = dp_opt_get_string(ctx->opts->basic,
                                         SDAP_CHPASS_DNS_SERVICE_NAME);
    if (dns_service_name) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Service name for chpass discovery set to %s\n",
                  dns_service_name);
    }

    urls = dp_opt_get_string(ctx->opts->basic, SDAP_CHPASS_URI);
    backup_urls = dp_opt_get_string(ctx->opts->basic, SDAP_CHPASS_BACKUP_URI);
    if (!urls && !backup_urls && !dns_service_name) {
        DEBUG(SSSDBG_TRACE_ALL,
              "ldap_chpass_uri and ldap_chpass_dns_service_name not set, "
                  "using ldap_uri.\n");
        ctx->chpass_service = NULL;
    } else {
        ret = sdap_service_init(ctx, ctx->be, "LDAP_CHPASS", dns_service_name,
                                urls, backup_urls, &ctx->chpass_service);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to initialize failover service!\n");
            goto done;
        }
    }


    *ops = &sdap_chpass_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sssm_ldap_access_init(struct be_ctx *bectx,
                          struct bet_ops **ops,
                          void **pvt_data)
{
    int ret;
    struct sdap_access_ctx *access_ctx;
    const char *filter;
    const char *order;
    char **order_list;
    int order_list_len;
    size_t c;
    const char *dummy;

    access_ctx = talloc_zero(bectx, struct sdap_access_ctx);
    if(access_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldap_id_init_internal(bectx, ops, (void **)&access_ctx->id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ldap_id_init_internal failed.\n");
        goto done;
    }

    order = dp_opt_get_cstring(access_ctx->id_ctx->opts->basic,
                               SDAP_ACCESS_ORDER);
    if (order == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ldap_access_order not given, using 'filter'.\n");
        order = "filter";
    }

    ret = split_on_separator(access_ctx, order, ',', true, true,
                             &order_list, &order_list_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "split_on_separator failed.\n");
        goto done;
    }

    ret = check_order_list_for_duplicates(order_list, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "check_order_list_for_duplicates failed.\n");
        goto done;
    }

    if (order_list_len > LDAP_ACCESS_LAST) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Currently only [%d] different access rules are supported.\n",
               LDAP_ACCESS_LAST);
        ret = EINVAL;
        goto done;
    }

    for (c = 0; order_list[c] != NULL; c++) {
        if (strcasecmp(order_list[c], LDAP_ACCESS_FILTER_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_FILTER;

            filter = dp_opt_get_cstring(access_ctx->id_ctx->opts->basic,
                                        SDAP_ACCESS_FILTER);
            if (filter == NULL) {
                /* It's okay if this is NULL. In that case we will simply act
                 * like the 'deny' provider.
                 */
                DEBUG(SSSDBG_FATAL_FAILURE,
                      "Warning: LDAP access rule 'filter' is set, "
                          "but no ldap_access_filter configured. "
                          "All domain users will be denied access.\n");
            } else {
                access_ctx->filter = sdap_get_access_filter(access_ctx,
                                                            filter);
                if (access_ctx->filter == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
            }
        } else if (strcasecmp(order_list[c], LDAP_ACCESS_EXPIRE_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_EXPIRE;

            dummy = dp_opt_get_cstring(access_ctx->id_ctx->opts->basic,
                                       SDAP_ACCOUNT_EXPIRE_POLICY);
            if (dummy == NULL) {
                DEBUG(SSSDBG_FATAL_FAILURE,
                      "Warning: LDAP access rule 'expire' is set, "
                          "but no ldap_account_expire_policy configured. "
                          "All domain users will be denied access.\n");
            } else {
                if (strcasecmp(dummy, LDAP_ACCOUNT_EXPIRE_SHADOW) != 0 &&
                    strcasecmp(dummy, LDAP_ACCOUNT_EXPIRE_AD) != 0 &&
                    strcasecmp(dummy, LDAP_ACCOUNT_EXPIRE_NDS) != 0 &&
                    strcasecmp(dummy, LDAP_ACCOUNT_EXPIRE_RHDS) != 0 &&
                    strcasecmp(dummy, LDAP_ACCOUNT_EXPIRE_IPA) != 0 &&
                    strcasecmp(dummy, LDAP_ACCOUNT_EXPIRE_389DS) != 0) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Unsupported LDAP account expire policy [%s].\n",
                              dummy);
                    ret = EINVAL;
                    goto done;
                }
            }
        } else if (strcasecmp(order_list[c], LDAP_ACCESS_SERVICE_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_SERVICE;
        } else if (strcasecmp(order_list[c], LDAP_ACCESS_HOST_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_HOST;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected access rule name [%s].\n", order_list[c]);
            ret = EINVAL;
            goto done;
        }
    }
    access_ctx->access_rule[c] = LDAP_ACCESS_EMPTY;
    if (c == 0) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Warning: access_provider=ldap set, "
                  "but ldap_access_order is empty. "
                  "All domain users will be denied access.\n");
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

int sssm_ldap_sudo_init(struct be_ctx *be_ctx,
                        struct bet_ops **ops,
                        void **pvt_data)
{
#ifdef BUILD_SUDO
    struct sdap_id_ctx *id_ctx;
    void *data;
    int ret;

    ret = ldap_id_init_internal(be_ctx, ops, &data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot init LDAP ID provider [%d]: %s\n",
                                    ret, strerror(ret));
        return ret;
    }

    id_ctx = talloc_get_type(data, struct sdap_id_ctx);
    if (!id_ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No ID provider?\n");
        return EIO;
    }

    return sdap_sudo_init(be_ctx, id_ctx, ops, pvt_data);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Sudo init handler called but SSSD is "
                                 "built without sudo support, ignoring\n");
    return EOK;
#endif
}

int sssm_ldap_autofs_init(struct be_ctx *be_ctx,
                          struct bet_ops **ops,
                          void **pvt_data)
{
#ifdef BUILD_AUTOFS
    struct sdap_id_ctx *id_ctx;
    void *data;
    int ret;

    ret = ldap_id_init_internal(be_ctx, ops, &data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot init LDAP ID provider [%d]: %s\n",
                                    ret, strerror(ret));
        return ret;
    }

    id_ctx = talloc_get_type(data, struct sdap_id_ctx);
    if (!id_ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No ID provider?\n");
        return EIO;
    }

    return sdap_autofs_init(be_ctx, id_ctx, ops, pvt_data);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Autofs init handler called but SSSD is "
                                 "built without autofs support, ignoring\n");
    return EOK;
#endif
}

static void sdap_shutdown(struct be_req *req)
{
    /* TODO: Clean up any internal data */
    sdap_handler_done(req, DP_ERR_OK, EOK, NULL);
}

