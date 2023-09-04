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
#include "providers/ad/ad_resolver.h"
#include "providers/ad/ad_srv.h"
#include "providers/be_dyndns.h"
#include "providers/ad/ad_subdomains.h"
#include "providers/ad/ad_domain_info.h"

struct ad_init_ctx {
    struct ad_options *options;
    struct ad_id_ctx *id_ctx;
    struct krb5_ctx *auth_ctx;
    struct ad_resolver_ctx *resolver_ctx;
};

#define AD_COMPAT_ON "1"
static int ad_sasl_getopt(void *context, const char *plugin_name,
                          const char *option,
                          const char **result, unsigned *len)
{
    if (!plugin_name || !result) {
        return SASL_FAIL;
    }
    if (!sdap_sasl_mech_needs_kinit(plugin_name)) {
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

static int ad_sasl_log(void *context, int level, const char *message)
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
    { SASL_CB_GETOPT, (sss_sasl_gen_cb_fn)(void *)ad_sasl_getopt, NULL },
    { SASL_CB_LOG, (sss_sasl_gen_cb_fn)(void *)ad_sasl_log, NULL },
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

static errno_t ad_init_options(TALLOC_CTX *mem_ctx,
                               struct be_ctx *be_ctx,
                               struct ad_options **_ad_options)
{
    struct ad_options *ad_options;
    char *ad_servers = NULL;
    char *ad_backup_servers = NULL;
    char *ad_realm;
    bool ad_use_ldaps = false;
    errno_t ret;

    ad_sasl_initialize();

    /* Get AD-specific options */
    ret = ad_get_common_options(mem_ctx, be_ctx->cdb, be_ctx->conf_path,
                                be_ctx->domain, &ad_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not parse common options "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    ad_servers = dp_opt_get_string(ad_options->basic, AD_SERVER);
    ad_backup_servers = dp_opt_get_string(ad_options->basic, AD_BACKUP_SERVER);
    ad_realm = dp_opt_get_string(ad_options->basic, AD_KRB5_REALM);
    ad_use_ldaps = dp_opt_get_bool(ad_options->basic, AD_USE_LDAPS);

    /* Set up the failover service */
    ret = ad_failover_init(ad_options, be_ctx, ad_servers, ad_backup_servers,
                           ad_realm, AD_SERVICE_NAME, AD_GC_SERVICE_NAME,
                           dp_opt_get_string(ad_options->basic, AD_DOMAIN),
                           false, /* will be set in ad_get_auth_options() */
                           ad_use_ldaps,
                           (size_t) -1,
                           (size_t) -1,
                           &ad_options->service);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to init AD failover service: "
              "[%d]: %s\n", ret, sss_strerror(ret));
        talloc_free(ad_options);
        return ret;
    }

    *_ad_options = ad_options;

    return EOK;
}

static errno_t ad_init_srv_plugin(struct be_ctx *be_ctx,
                                  struct ad_options *ad_options)
{
    struct ad_srv_plugin_ctx *srv_ctx;
    const char *hostname;
    const char *ad_domain;
    const char *ad_site_override;
    bool sites_enabled;
    errno_t ret;

    hostname = dp_opt_get_string(ad_options->basic, AD_HOSTNAME);
    ad_domain = dp_opt_get_string(ad_options->basic, AD_DOMAIN);
    ad_site_override = dp_opt_get_string(ad_options->basic, AD_SITE);
    sites_enabled = dp_opt_get_bool(ad_options->basic, AD_ENABLE_DNS_SITES);

    if (!sites_enabled) {
        ret = be_fo_set_dns_srv_lookup_plugin(be_ctx, hostname);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set SRV lookup plugin "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }

        return EOK;
    }

    srv_ctx = ad_srv_plugin_ctx_init(be_ctx, be_ctx, be_ctx->be_res,
                                     default_host_dbs, ad_options->id,
                                     ad_options,
                                     hostname, ad_domain,
                                     ad_site_override);
    if (srv_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory?\n");
        return ENOMEM;
    }

    be_fo_set_srv_lookup_plugin(be_ctx, ad_srv_plugin_send,
                                ad_srv_plugin_recv, srv_ctx, "AD");

    return EOK;
}

static errno_t ad_init_sdap_access_ctx(struct ad_access_ctx *access_ctx)
{
    struct dp_option *options = access_ctx->ad_options;
    struct sdap_id_ctx *sdap_id_ctx = access_ctx->ad_id_ctx->sdap_id_ctx;
    struct sdap_access_ctx *sdap_access_ctx;
    const char *filter;

    sdap_access_ctx = talloc_zero(access_ctx, struct sdap_access_ctx);
    if (sdap_access_ctx == NULL) {
        return ENOMEM;
    }

    sdap_access_ctx->id_ctx = sdap_id_ctx;


    /* If ad_access_filter is set, the value of ldap_acess_order is
     * expire, filter, otherwise only expire.
     */
    sdap_access_ctx->access_rule[0] = LDAP_ACCESS_EXPIRE;
    filter = dp_opt_get_cstring(options, AD_ACCESS_FILTER);
    if (filter != NULL) {
        /* The processing of the extended filter is performed during the access
         * check itself.
         */
        sdap_access_ctx->filter = talloc_strdup(sdap_access_ctx, filter);
        if (sdap_access_ctx->filter == NULL) {
            talloc_free(sdap_access_ctx);
            return ENOMEM;
        }

        sdap_access_ctx->access_rule[1] = LDAP_ACCESS_FILTER;
        sdap_access_ctx->access_rule[2] = LDAP_ACCESS_EMPTY;
    } else {
        sdap_access_ctx->access_rule[1] = LDAP_ACCESS_EMPTY;
    }

    access_ctx->sdap_access_ctx = sdap_access_ctx;

    return EOK;
}

errno_t ad_gpo_parse_map_options(struct ad_access_ctx *access_ctx);

static errno_t ad_init_gpo(struct ad_access_ctx *access_ctx)
{
    struct dp_option *options;
    const char *gpo_access_control_mode;
    int gpo_cache_timeout;
    errno_t ret;

    options = access_ctx->ad_options;

    /* GPO access control mode */
    gpo_access_control_mode = dp_opt_get_string(options, AD_GPO_ACCESS_CONTROL);
    if (gpo_access_control_mode == NULL) {
        return EINVAL;
    } else if (strcasecmp(gpo_access_control_mode, "disabled") == 0) {
        access_ctx->gpo_access_control_mode = GPO_ACCESS_CONTROL_DISABLED;
    } else if (strcasecmp(gpo_access_control_mode, "permissive") == 0) {
        access_ctx->gpo_access_control_mode = GPO_ACCESS_CONTROL_PERMISSIVE;
    } else if (strcasecmp(gpo_access_control_mode, "enforcing") == 0) {
        access_ctx->gpo_access_control_mode = GPO_ACCESS_CONTROL_ENFORCING;
    } else {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unrecognized GPO access control mode: "
              "%s\n", gpo_access_control_mode);
        return EINVAL;
    }

    /* GPO cache timeout */
    gpo_cache_timeout = dp_opt_get_int(options, AD_GPO_CACHE_TIMEOUT);
    access_ctx->gpo_cache_timeout = gpo_cache_timeout;

    /* GPO logon maps */
    ret = sss_hash_create(access_ctx, 0, &access_ctx->gpo_map_options_table);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not create gpo_map_options "
              "hash table [%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    ret = ad_gpo_parse_map_options(access_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not parse gpo_map_options "
              "(invalid config) [%d]: %s\n", ret, sss_strerror(ret));
        talloc_zfree(access_ctx->gpo_map_options_table);
        return ret;
    }

    return EOK;
}

static errno_t ad_init_auth_ctx(TALLOC_CTX *mem_ctx,
                                struct be_ctx *be_ctx,
                                struct ad_options *ad_options,
                                struct krb5_ctx **_auth_ctx)
{
    struct krb5_ctx *krb5_auth_ctx;
    errno_t ret;

    krb5_auth_ctx = talloc_zero(mem_ctx, struct krb5_ctx);
    if (krb5_auth_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    krb5_auth_ctx->config_type = K5C_GENERIC;
    krb5_auth_ctx->sss_creds_password = true;
    krb5_auth_ctx->service = ad_options->service->krb5_service;

    ret = ad_get_auth_options(krb5_auth_ctx, ad_options, be_ctx,
                              &krb5_auth_ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not determine Kerberos options\n");
        goto done;
    }

    ret = krb5_child_init(krb5_auth_ctx, be_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not initialize krb5_child settings: "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ad_options->auth_ctx = krb5_auth_ctx;
    *_auth_ctx = krb5_auth_ctx;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(krb5_auth_ctx);
    }

    return ret;
}

static errno_t ad_init_misc(struct be_ctx *be_ctx,
                            struct ad_options *ad_options,
                            struct ad_id_ctx *ad_id_ctx,
                            struct sdap_id_ctx *sdap_id_ctx)
{
    errno_t ret;

    ret = ad_dyndns_init(be_ctx, ad_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failure setting up automatic DNS update\n");
        /* Continue without DNS updates */
    }

    setup_ldap_debug(sdap_id_ctx->opts->basic);

    ret = setup_tls_config(sdap_id_ctx->opts->basic);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get TLS options [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    ret = sdap_idmap_init(sdap_id_ctx, sdap_id_ctx,
                          &sdap_id_ctx->opts->idmap_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not initialize ID mapping. In case ID mapping properties "
              "changed on the server, please remove the SSSD database\n");
        return ret;
    }

    ret = sdap_id_setup_tasks(be_ctx, sdap_id_ctx, sdap_id_ctx->opts->sdom,
                              ad_id_enumeration_send, ad_id_enumeration_recv,
                              ad_id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup background tasks "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    sdap_id_ctx->opts->sdom->pvt = ad_id_ctx;

    ret = ad_init_srv_plugin(be_ctx, ad_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup SRV plugin [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    ret = ad_refresh_init(be_ctx, ad_id_ctx);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Periodical refresh "
              "will not work [%d]: %s\n", ret, sss_strerror(ret));
    }

    ret = ad_machine_account_password_renewal_init(be_ctx, ad_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot setup task for machine account "
                                   "password renewal.\n");
        return ret;
    }

    ret = confdb_certmap_to_sysdb(be_ctx->cdb, be_ctx->domain, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialize certificate mapping rules. "
              "Authentication with certificates/Smartcards might not work "
              "as expected.\n");
        /* not fatal, ignored */
    }

    ret = sdap_init_certmap(sdap_id_ctx, sdap_id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialized certificate mapping.\n");
        return ret;
    }

    return EOK;
}

errno_t sssm_ad_init(TALLOC_CTX *mem_ctx,
                     struct be_ctx *be_ctx,
                     struct data_provider *provider,
                     const char *module_name,
                     void **_module_data)
{
    struct ad_init_ctx *init_ctx;
    errno_t ret;

    init_ctx = talloc_zero(mem_ctx, struct ad_init_ctx);
    if (init_ctx == NULL) {
        return ENOMEM;
    }

    /* Always initialize options since it is needed everywhere. */
    ret = ad_init_options(mem_ctx, be_ctx, &init_ctx->options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init AD options [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    /* Always initialize id_ctx since it is needed everywhere. */
    init_ctx->id_ctx = ad_id_ctx_init(init_ctx->options, be_ctx);
    if (init_ctx->id_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize AD ID context\n");
        ret = ENOMEM;
        goto done;
    }

    init_ctx->options->id_ctx = init_ctx->id_ctx;

    ret = ad_get_id_options(init_ctx->options,
                            be_ctx->cdb,
                            be_ctx->conf_path,
                            be_ctx->provider,
                            &init_ctx->id_ctx->sdap_id_ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init AD id options\n");
        return ret;
    }

    /* Setup miscellaneous things. */
    ret = ad_init_misc(be_ctx, init_ctx->options, init_ctx->id_ctx,
                       init_ctx->id_ctx->sdap_id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init AD module "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Initialize auth_ctx only if one of the target is enabled. */
    if (dp_target_enabled(provider, module_name, DPT_AUTH, DPT_CHPASS)) {
        ret = ad_init_auth_ctx(init_ctx, be_ctx, init_ctx->options,
                               &init_ctx->auth_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create auth context "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }
    }

    *_module_data = init_ctx;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(init_ctx);
    }

    return ret;
}

errno_t sssm_ad_id_init(TALLOC_CTX *mem_ctx,
                        struct be_ctx *be_ctx,
                        void *module_data,
                        struct dp_method *dp_methods)
{
    struct ad_init_ctx *init_ctx;
    struct ad_id_ctx *id_ctx;

    init_ctx = talloc_get_type(module_data, struct ad_init_ctx);
    id_ctx = init_ctx->id_ctx;

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  ad_account_info_handler_send, ad_account_info_handler_recv, id_ctx,
                  struct ad_id_ctx, struct dp_id_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_CHECK_ONLINE,
                  sdap_online_check_handler_send, sdap_online_check_handler_recv, id_ctx->sdap_id_ctx,
                  struct sdap_id_ctx, void, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  ad_get_account_domain_send, ad_get_account_domain_recv, id_ctx,
                  struct ad_id_ctx, struct dp_get_acct_domain_data, struct dp_reply_std);

    return EOK;
}

errno_t sssm_ad_auth_init(TALLOC_CTX *mem_ctx,
                          struct be_ctx *be_ctx,
                          void *module_data,
                          struct dp_method *dp_methods)
{
    struct ad_init_ctx *init_ctx;
    struct krb5_ctx *auth_ctx;

    init_ctx = talloc_get_type(module_data, struct ad_init_ctx);
    auth_ctx = init_ctx->auth_ctx;

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  krb5_pam_handler_send, krb5_pam_handler_recv, auth_ctx,
                  struct krb5_ctx, struct pam_data, struct pam_data *);

    return EOK;
}

errno_t sssm_ad_chpass_init(TALLOC_CTX *mem_ctx,
                            struct be_ctx *be_ctx,
                            void *module_data,
                            struct dp_method *dp_methods)
{
    return sssm_ad_auth_init(mem_ctx, be_ctx, module_data, dp_methods);
}

errno_t sssm_ad_access_init(TALLOC_CTX *mem_ctx,
                            struct be_ctx *be_ctx,
                            void *module_data,
                            struct dp_method *dp_methods)
{
    struct ad_init_ctx *init_ctx;
    struct ad_access_ctx *access_ctx;
    errno_t ret;

    init_ctx = talloc_get_type(module_data, struct ad_init_ctx);

    access_ctx = talloc_zero(mem_ctx, struct ad_access_ctx);
    if (access_ctx == NULL) {
        return ENOMEM;
    }

    access_ctx->ad_id_ctx = init_ctx->id_ctx;

    ret = dp_copy_options(access_ctx, init_ctx->options->basic, AD_OPTS_BASIC,
                          &access_ctx->ad_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not initialize access provider "
              "options [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = ad_init_sdap_access_ctx(access_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not initialize sdap access context "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = ad_init_gpo(access_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not initialize GPO "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    dp_set_method(dp_methods, DPM_ACCESS_HANDLER,
                  ad_pam_access_handler_send, ad_pam_access_handler_recv, access_ctx,
                  struct ad_access_ctx, struct pam_data, struct pam_data *);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(access_ctx);
    }

    return ret;
}

errno_t sssm_ad_autofs_init(TALLOC_CTX *mem_ctx,
                            struct be_ctx *be_ctx,
                            void *module_data,
                            struct dp_method *dp_methods)
{
#ifdef BUILD_AUTOFS
    struct ad_init_ctx *init_ctx;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing AD autofs handler\n");
    init_ctx = talloc_get_type(module_data, struct ad_init_ctx);

    return ad_autofs_init(mem_ctx, be_ctx, init_ctx->id_ctx, dp_methods);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Autofs init handler called but SSSD is "
                                "built without autofs support, ignoring\n");
    return EOK;
#endif
}

errno_t sssm_ad_subdomains_init(TALLOC_CTX *mem_ctx,
                                struct be_ctx *be_ctx,
                                void *module_data,
                                struct dp_method *dp_methods)
{
    struct ad_init_ctx *init_ctx;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing AD subdomains handler\n");
    init_ctx = talloc_get_type(module_data, struct ad_init_ctx);

    return ad_subdomains_init(mem_ctx, be_ctx, init_ctx->id_ctx, dp_methods);
}

errno_t sssm_ad_sudo_init(TALLOC_CTX *mem_ctx,
                          struct be_ctx *be_ctx,
                          void *module_data,
                          struct dp_method *dp_methods)
{
#ifdef BUILD_SUDO
    struct ad_init_ctx *init_ctx;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing AD sudo handler\n");
    init_ctx = talloc_get_type(module_data, struct ad_init_ctx);

    return ad_sudo_init(mem_ctx, be_ctx, init_ctx->id_ctx, dp_methods);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Sudo init handler called but SSSD is "
                                "built without sudo support, ignoring\n");
    return EOK;
#endif
}

errno_t sssm_ad_resolver_init(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx,
                              void *module_data,
                              struct dp_method *dp_methods)
{
    struct ad_init_ctx *init_ctx;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing AD resolver handler\n");
    init_ctx = talloc_get_type(module_data, struct ad_init_ctx);

    ret = ad_resolver_ctx_init(init_ctx, init_ctx->id_ctx,
                               &init_ctx->resolver_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to initialize AD resolver context\n");
        return ret;
    }

    ret = ad_resolver_setup_tasks(be_ctx, init_ctx->resolver_ctx,
                                  ad_resolver_enumeration_send,
                                  ad_resolver_enumeration_recv);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to setup resolver background tasks [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    dp_set_method(dp_methods, DPM_RESOLVER_HOSTS_HANDLER,
                  sdap_iphost_handler_send, sdap_iphost_handler_recv,
                  init_ctx->resolver_ctx->sdap_resolver_ctx,
                  struct sdap_resolver_ctx,
                  struct dp_resolver_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_RESOLVER_IP_NETWORK_HANDLER,
                  sdap_ipnetwork_handler_send, sdap_ipnetwork_handler_recv,
                  init_ctx->resolver_ctx->sdap_resolver_ctx,
                  struct sdap_resolver_ctx,
                  struct dp_resolver_data, struct dp_reply_std);

    return EOK;
}
