/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

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


#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sasl/sasl.h>

#include "util/util.h"
#include "providers/ad/ad_common.h"
#include "providers/ad/ad_access.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_init_shared.h"
#include "providers/ad/ad_id.h"
#include "providers/ad/ad_srv.h"
#include "providers/dp_dyndns.h"
#include "providers/ad/ad_subdomains.h"
#include "providers/ad/ad_domain_info.h"

struct ad_options *ad_options = NULL;

static void
ad_shutdown(struct be_req *req);

struct bet_ops ad_id_ops = {
    .handler = ad_account_info_handler,
    .finalize = ad_shutdown,
    .check_online = ad_check_online
};

struct bet_ops ad_auth_ops = {
    .handler = krb5_pam_handler,
    .finalize = NULL
};

struct bet_ops ad_chpass_ops = {
    .handler = krb5_pam_handler,
    .finalize = NULL
};

struct bet_ops ad_access_ops = {
    .handler = ad_access_handler,
    .finalize = NULL
};

#define AD_COMPAT_ON "1"
static int ad_sasl_getopt(void *context, const char *plugin_name,
                          const char *option,
                          const char **result, unsigned *len)
{
    if (!plugin_name || !result) {
        return SASL_FAIL;
    }
    if (strcmp(plugin_name, "GSSAPI") != 0) {
        return SASL_FAIL;
    }
    if (strcmp(option, "ad_compat") != 0) {
        return SASL_FAIL;
    }
    *result = AD_COMPAT_ON;
    if (len) {
        *len = 2;
    }
    return SASL_OK;
}

typedef int (*sss_sasl_gen_cb_fn)(void);

static int map_sasl2sssd_log_level(int sasl_level)
{
    int sssd_level;

    switch(sasl_level) {
    case SASL_LOG_ERR:       /* log unusual errors (default) */
        sssd_level = SSSDBG_CRIT_FAILURE;
        break;
    case SASL_LOG_FAIL:      /* log all authentication failures */
        sssd_level = SSSDBG_OP_FAILURE;
        break;
    case SASL_LOG_WARN:      /* log non-fatal warnings */
        sssd_level = SSSDBG_MINOR_FAILURE;
        break;
    case SASL_LOG_NOTE:      /* more verbose than LOG_WARN */
    case SASL_LOG_DEBUG:     /* more verbose than LOG_NOTE */
    case SASL_LOG_TRACE:     /* traces of internal protocols */
    case SASL_LOG_PASS:      /* traces of internal protocols, including */
        sssd_level = SSSDBG_TRACE_ALL;
        break;
    default:
        sssd_level = SSSDBG_TRACE_ALL;
        break;
    }

    return sssd_level;
}

int ad_sasl_log(void *context, int level, const char *message)
{
    int sssd_level;

    if (level == SASL_LOG_ERR || level == SASL_LOG_FAIL) {
        sss_log(SSS_LOG_ERR, "%s\n", message);
    }

    sssd_level = map_sasl2sssd_log_level(level);
    DEBUG(sssd_level, "SASL: %s\n", message);
    return SASL_OK;
}

static const sasl_callback_t ad_sasl_callbacks[] = {
    { SASL_CB_GETOPT, (sss_sasl_gen_cb_fn)ad_sasl_getopt, NULL },
    { SASL_CB_LOG, (sss_sasl_gen_cb_fn)ad_sasl_log, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};
/* This is quite a hack, we *try* to fool openldap libraries by initializing
 * sasl first so we can pass in the SASL_CB_GETOPT callback we need to set some
 * options. Should be removed as soon as openldap exposes a way to do that */
static void ad_sasl_initialize(void)
{
    /* NOTE: this may fail if soe other library in the system happens to
     * initialize and use openldap libraries or directly the cyrus-sasl
     * library as this initialization function can be called only once per
     * process */
    (void)sasl_client_init(ad_sasl_callbacks);
}

static errno_t
common_ad_init(struct be_ctx *bectx)
{
    errno_t ret;
    char *ad_servers = NULL;
    char *ad_backup_servers = NULL;
    char *ad_realm;

    ad_sasl_initialize();

    /* Get AD-specific options */
    ret = ad_get_common_options(bectx, bectx->cdb,
                                bectx->conf_path,
                                bectx->domain,
                                &ad_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not parse common options: [%s]\n",
               strerror(ret));
        goto done;
    }

    ad_servers = dp_opt_get_string(ad_options->basic, AD_SERVER);
    ad_backup_servers = dp_opt_get_string(ad_options->basic, AD_BACKUP_SERVER);
    ad_realm = dp_opt_get_string(ad_options->basic, AD_KRB5_REALM);

    /* Set up the failover service */
    ret = ad_failover_init(ad_options, bectx, ad_servers, ad_backup_servers, ad_realm,
                           AD_SERVICE_NAME, AD_GC_SERVICE_NAME,
                           dp_opt_get_string(ad_options->basic, AD_DOMAIN),
                           &ad_options->service);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to init AD failover service: [%s]\n",
               strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    return ret;
}

int
sssm_ad_id_init(struct be_ctx *bectx,
                struct bet_ops **ops,
                void **pvt_data)
{
    errno_t ret;
    struct ad_id_ctx *ad_ctx;
    const char *hostname;
    const char *ad_domain;
    const char *ad_site_override;
    struct ad_srv_plugin_ctx *srv_ctx;

    if (!ad_options) {
        ret = common_ad_init(bectx);
        if (ret != EOK) {
            return ret;
        }
    }

    if (ad_options->id_ctx) {
        /* already initialized */
        *ops = &ad_id_ops;
        *pvt_data = ad_options->id_ctx;
        return EOK;
    }


    ad_ctx = ad_id_ctx_init(ad_options, bectx);
    if (ad_ctx == NULL) {
        return ENOMEM;
    }
    ad_options->id_ctx = ad_ctx;

    ret = ad_dyndns_init(ad_ctx->sdap_id_ctx->be, ad_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
             "Failure setting up automatic DNS update\n");
        /* Continue without DNS updates */
    }

    ret = sdap_setup_child();
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "setup_child failed [%d][%s].\n",
               ret, strerror(ret));
        goto done;
    }

    /* Set up various SDAP options */
    ret = ad_get_id_options(ad_options, bectx->cdb,
                            bectx->conf_path,
                            &ad_ctx->sdap_id_ctx->opts);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_id_setup_tasks(bectx,
                              ad_ctx->sdap_id_ctx,
                              ad_ctx->sdap_id_ctx->opts->sdom,
                              ad_enumeration_send,
                              ad_enumeration_recv,
                              ad_ctx);
    if (ret != EOK) {
        goto done;
    }

    ad_ctx->sdap_id_ctx->opts->sdom->pvt = ad_ctx;

    /* Set up the ID mapping object */
    ret = sdap_idmap_init(ad_ctx->sdap_id_ctx, ad_ctx->sdap_id_ctx,
                          &ad_ctx->sdap_id_ctx->opts->idmap_ctx);
    if (ret != EOK) goto done;

    ret = setup_tls_config(ad_ctx->sdap_id_ctx->opts->basic);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "setup_tls_config failed [%s]\n", strerror(ret));
        goto done;
    }

    /* setup SRV lookup plugin */
    hostname = dp_opt_get_string(ad_options->basic, AD_HOSTNAME);
    if (dp_opt_get_bool(ad_options->basic, AD_ENABLE_DNS_SITES)) {
        /* use AD plugin */
        ad_domain = dp_opt_get_string(ad_options->basic, AD_DOMAIN);
        ad_site_override = dp_opt_get_string(ad_options->basic, AD_SITE);

        srv_ctx = ad_srv_plugin_ctx_init(bectx, bectx->be_res,
                                         default_host_dbs, ad_options->id,
                                         hostname, ad_domain,
                                         ad_site_override);
        if (srv_ctx == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory?\n");
            ret = ENOMEM;
            goto done;
        }

        be_fo_set_srv_lookup_plugin(bectx, ad_srv_plugin_send,
                                    ad_srv_plugin_recv, srv_ctx, "AD");
    } else {
        /* fall back to standard plugin */
        ret = be_fo_set_dns_srv_lookup_plugin(bectx, hostname);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set SRV lookup plugin "
                                        "[%d]: %s\n", ret, strerror(ret));
            goto done;
        }
    }

    /* setup periodical refresh of expired records */
    ret = sdap_refresh_init(bectx->refresh_ctx, ad_ctx->sdap_id_ctx);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Periodical refresh "
              "will not work [%d]: %s\n", ret, strerror(ret));
    }

    *ops = &ad_id_ops;
    *pvt_data = ad_ctx;

    ret = EOK;
done:
    if (ret != EOK) {
        talloc_zfree(ad_options->id_ctx);
    }
    return ret;
}

int
sssm_ad_auth_init(struct be_ctx *bectx,
                  struct bet_ops **ops,
                  void **pvt_data)
{
    errno_t ret;
    struct krb5_ctx *krb5_auth_ctx = NULL;

    if (!ad_options) {
        ret = common_ad_init(bectx);
        if (ret != EOK) {
            return ret;
        }
    }

    if (ad_options->auth_ctx) {
        /* Already initialized */
        *ops = &ad_auth_ops;
        *pvt_data = ad_options->auth_ctx;
        return EOK;
    }

    krb5_auth_ctx = talloc_zero(NULL, struct krb5_ctx);
    if (!krb5_auth_ctx) {
        ret = ENOMEM;
        goto done;
    }

    krb5_auth_ctx->config_type = K5C_GENERIC;
    krb5_auth_ctx->service = ad_options->service->krb5_service;

    ret = ad_get_auth_options(krb5_auth_ctx, ad_options, bectx,
                              &krb5_auth_ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not determine Kerberos options\n");
        goto done;
    }

    ret = krb5_child_init(krb5_auth_ctx, bectx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not initialize krb5_child settings: [%s]\n",
               strerror(ret));
        goto done;
    }

    ad_options->auth_ctx = talloc_steal(ad_options, krb5_auth_ctx);
    *ops = &ad_auth_ops;
    *pvt_data = ad_options->auth_ctx;

done:
    if (ret != EOK) {
        talloc_free(krb5_auth_ctx);
    }
    return ret;
}

int
sssm_ad_chpass_init(struct be_ctx *bectx,
                    struct bet_ops **ops,
                    void **pvt_data)
{
    errno_t ret;

    if (!ad_options) {
        ret = common_ad_init(bectx);
        if (ret != EOK) {
            return ret;
        }
    }

    if (ad_options->auth_ctx) {
        /* Already initialized */
        *ops = &ad_chpass_ops;
        *pvt_data = ad_options->auth_ctx;
        return EOK;
    }

    ret = sssm_ad_auth_init(bectx, ops, pvt_data);
    *ops = &ad_chpass_ops;
    ad_options->auth_ctx = *pvt_data;
    return ret;
}

/* GPO parsing of PAM service names to Windows Logon Rights*/
errno_t ad_gpo_parse_map_options(struct ad_access_ctx *access_ctx);

int
sssm_ad_access_init(struct be_ctx *bectx,
                    struct bet_ops **ops,
                    void **pvt_data)
{
    errno_t ret;
    struct ad_access_ctx *access_ctx;
    struct ad_id_ctx *ad_id_ctx;
    const char *filter;
    const char *gpo_access_control_mode;
    int gpo_cache_timeout;

    access_ctx = talloc_zero(bectx, struct ad_access_ctx);
    if (!access_ctx) return ENOMEM;

    ret = sssm_ad_id_init(bectx, ops, (void **)&ad_id_ctx);
    if (ret != EOK) {
        goto fail;
    }
    access_ctx->ad_id_ctx = ad_id_ctx;

    ret = dp_copy_options(access_ctx, ad_options->basic, AD_OPTS_BASIC,
                          &access_ctx->ad_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not initialize access provider options: [%s]\n",
               strerror(ret));
        goto fail;
    }

    /* Set up an sdap_access_ctx for checking expired/locked accounts */
    access_ctx->sdap_access_ctx =
            talloc_zero(access_ctx, struct sdap_access_ctx);
    if (!access_ctx->sdap_access_ctx) {
        ret = ENOMEM;
        goto fail;
    }
    access_ctx->sdap_access_ctx->id_ctx = ad_id_ctx->sdap_id_ctx;

    /* If ad_access_filter is set, the value of ldap_acess_order is
     * expire, filter, otherwise only expire
     */
    access_ctx->sdap_access_ctx->access_rule[0] = LDAP_ACCESS_EXPIRE;
    filter = dp_opt_get_cstring(access_ctx->ad_options, AD_ACCESS_FILTER);
    if (filter != NULL) {
        /* The processing of the extended filter is performed during the access
         * check itself
         */
        access_ctx->sdap_access_ctx->filter = talloc_strdup(
                                                  access_ctx->sdap_access_ctx,
                                                  filter);
        if (access_ctx->sdap_access_ctx->filter == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        access_ctx->sdap_access_ctx->access_rule[1] = LDAP_ACCESS_FILTER;
        access_ctx->sdap_access_ctx->access_rule[2] = LDAP_ACCESS_EMPTY;
    } else {
        access_ctx->sdap_access_ctx->access_rule[1] = LDAP_ACCESS_EMPTY;
    }

    /* GPO access control mode */
    gpo_access_control_mode =
        dp_opt_get_string(access_ctx->ad_options, AD_GPO_ACCESS_CONTROL);
    if (strcasecmp(gpo_access_control_mode, "disabled") == 0) {
        access_ctx->gpo_access_control_mode = GPO_ACCESS_CONTROL_DISABLED;
    } else if (strcasecmp(gpo_access_control_mode, "permissive") == 0) {
        access_ctx->gpo_access_control_mode = GPO_ACCESS_CONTROL_PERMISSIVE;
    } else if (strcasecmp(gpo_access_control_mode, "enforcing") == 0) {
        access_ctx->gpo_access_control_mode = GPO_ACCESS_CONTROL_ENFORCING;
    } else {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unrecognized GPO access control mode: %s\n",
              gpo_access_control_mode);
        ret = EINVAL;
        goto fail;
    }

    /* GPO cache timeout */
    gpo_cache_timeout =
        dp_opt_get_int(access_ctx->ad_options, AD_GPO_CACHE_TIMEOUT);
    access_ctx->gpo_cache_timeout = gpo_cache_timeout;

    /* GPO logon maps */

    ret = sss_hash_create(access_ctx, 10, &access_ctx->gpo_map_options_table);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not create gpo_map_options hash table: [%s]\n",
              strerror(ret));
        goto fail;
    }

    ret = ad_gpo_parse_map_options(access_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not parse gpo_map_options (invalid config): [%s]\n",
              strerror(ret));
        goto fail;
    }

    *ops = &ad_access_ops;
    *pvt_data = access_ctx;

    return EOK;

fail:
    talloc_free(access_ctx);
    return ret;
}

static void
ad_shutdown(struct be_req *req)
{
    /* TODO: Clean up any internal data */
    sdap_handler_done(req, DP_ERR_OK, EOK, NULL);
}

int sssm_ad_subdomains_init(struct be_ctx *bectx,
                            struct bet_ops **ops,
                            void **pvt_data)
{
    int ret;
    struct ad_id_ctx *id_ctx;
    const char *ad_domain;

    ret = sssm_ad_id_init(bectx, ops, (void **) &id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sssm_ad_id_init failed.\n");
        return ret;
    }

    if (ad_options == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Global AD options not available.\n");
        return EINVAL;
    }

    ad_domain = dp_opt_get_string(ad_options->basic, AD_DOMAIN);

    ret = ad_subdom_init(bectx, id_ctx, ad_domain, ops, pvt_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ad_subdom_init failed.\n");
        return ret;
    }

    return EOK;
}


int sssm_ad_sudo_init(struct be_ctx *bectx,
                      struct bet_ops **ops,
                      void **pvt_data)
{
#ifdef BUILD_SUDO
    struct ad_id_ctx *id_ctx;
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing AD sudo handler\n");

    ret = sssm_ad_id_init(bectx, ops, (void **) &id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sssm_ad_id_init failed.\n");
        return ret;
    }

    return ad_sudo_init(bectx, id_ctx, ops, pvt_data);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Sudo init handler called but SSSD is "
                                "built without sudo support, ignoring\n");
    return EOK;
#endif
}

int sssm_ad_autofs_init(struct be_ctx *bectx,
                        struct bet_ops **ops,
                        void **pvt_data)
{
#ifdef BUILD_AUTOFS
    struct ad_id_ctx *id_ctx;
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing AD autofs handler\n");

    ret = sssm_ad_id_init(bectx, ops, (void **) &id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sssm_ad_id_init failed.\n");
        return ret;
    }

    return ad_autofs_init(bectx, id_ctx, ops, pvt_data);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Autofs init handler called but SSSD is "
                                "built without autofs support, ignoring\n");
    return EOK;
#endif
}
