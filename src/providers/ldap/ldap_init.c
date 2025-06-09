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

#include "providers/ldap/ldap_common.h"
#include "providers/ldap/ldap_opts.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/sdap_hostid.h"
#include "providers/ldap/sdap_sudo.h"
#include "providers/ldap/sdap_autofs.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ldap/ldap_resolver_enum.h"
#include "providers/fail_over_srv.h"
#include "providers/be_refresh.h"

struct ldap_init_ctx {
    struct sdap_options *options;
    struct sdap_id_ctx *id_ctx;
    struct sdap_auth_ctx *auth_ctx;
    struct sdap_resolver_ctx *resolver_ctx;
};

static errno_t ldap_init_auth_ctx(TALLOC_CTX *mem_ctx,
                                  struct be_ctx *be_ctx,
                                  struct sdap_id_ctx *id_ctx,
                                  struct sdap_options *options,
                                  struct sdap_auth_ctx **_auth_ctx)
{
    struct sdap_auth_ctx *auth_ctx;

    auth_ctx = talloc(mem_ctx, struct sdap_auth_ctx);
    if (auth_ctx == NULL) {
        return ENOMEM;
    }

    auth_ctx->be = be_ctx;
    auth_ctx->opts = options;
    auth_ctx->service = id_ctx->conn->service;
    auth_ctx->chpass_service = NULL;

    *_auth_ctx = auth_ctx;

    return EOK;
}

static errno_t init_chpass_service(TALLOC_CTX *mem_ctx,
                                   struct be_ctx *be_ctx,
                                   struct sdap_options *opts,
                                   struct sdap_service **_chpass_service)
{
    errno_t ret;
    const char *urls;
    const char *backup_urls;
    const char *dns_service_name;
    struct sdap_service *chpass_service;

    dns_service_name = dp_opt_get_string(opts->basic,
                                         SDAP_CHPASS_DNS_SERVICE_NAME);
    if (dns_service_name != NULL) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Service name for chpass discovery set to %s\n",
              dns_service_name);
    }

    urls = dp_opt_get_string(opts->basic, SDAP_CHPASS_URI);
    backup_urls = dp_opt_get_string(opts->basic, SDAP_CHPASS_BACKUP_URI);

    if (urls != NULL || backup_urls != NULL || dns_service_name != NULL) {
        ret = sdap_service_init(mem_ctx,
                                be_ctx,
                                "LDAP_CHPASS",
                                dns_service_name,
                                urls,
                                backup_urls,
                                &chpass_service);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to initialize failover service!\n");
            return ret;
        }
    } else {
        DEBUG(SSSDBG_TRACE_ALL,
              "ldap_chpass_uri and ldap_chpass_dns_service_name not set, "
              "using ldap_uri.\n");
        chpass_service = NULL;
    }

    *_chpass_service = chpass_service;
    return EOK;
}

static errno_t get_sdap_service(TALLOC_CTX *mem_ctx,
                                struct be_ctx *be_ctx,
                                struct sdap_options *opts,
                                struct sdap_service **_sdap_service)
{
    errno_t ret;
    const char *urls;
    const char *backup_urls;
    const char *dns_service_name;
    struct sdap_service *sdap_service;

    urls = dp_opt_get_string(opts->basic, SDAP_URI);
    backup_urls = dp_opt_get_string(opts->basic, SDAP_BACKUP_URI);
    dns_service_name = dp_opt_get_string(opts->basic, SDAP_DNS_SERVICE_NAME);
    if (dns_service_name != NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Service name for discovery set to %s\n", dns_service_name);
    }

    ret = sdap_service_init(mem_ctx, be_ctx, "LDAP",
                            dns_service_name,
                            urls,
                            backup_urls,
                            &sdap_service);
    if (ret != EOK) {
        return ret;
    }

    *_sdap_service = sdap_service;
    return EOK;
}

static bool should_call_gssapi_init(struct sdap_options *opts)
{
    const char *sasl_mech;

    sasl_mech = dp_opt_get_string(opts->basic, SDAP_SASL_MECH);
    if (sasl_mech == NULL) {
        return false;
    }

    if (!sdap_sasl_mech_needs_kinit(sasl_mech)) {
        return false;
    }

    if (dp_opt_get_bool(opts->basic, SDAP_KRB5_KINIT) == false) {
        return false;
    }

    return true;
}

static errno_t ldap_init_misc(struct be_ctx *be_ctx,
                              struct sdap_options *options,
                              struct sdap_id_ctx *id_ctx)
{
    errno_t ret;

    if (should_call_gssapi_init(options)) {
        ret = sdap_gssapi_init(id_ctx, options->basic, be_ctx,
                               id_ctx->conn->service, &id_ctx->krb5_service);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sdap_gssapi_init failed [%d][%s].\n",
                  ret, sss_strerror(ret));
            return ret;
        }
    }

    setup_ldap_debug(options->basic);

    ret = setup_tls_config(options->basic);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get TLS options [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    /* Setup the ID mapping object */
    ret = sdap_idmap_init(id_ctx, id_ctx, &options->idmap_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not initialize ID mapping. In case ID mapping properties "
              "changed on the server, please remove the SSSD database\n");
        return ret;
    }

    ret = ldap_id_setup_tasks(id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup background tasks "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    /* Setup SRV lookup plugin */
    ret = be_fo_set_dns_srv_lookup_plugin(be_ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set SRV lookup plugin "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    /* Setup periodical refresh of expired records */
    ret = sdap_refresh_init(be_ctx, id_ctx);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Periodical refresh will not work "
              "[%d]: %s\n", ret, sss_strerror(ret));
    }

    ret = confdb_certmap_to_sysdb(be_ctx->cdb, be_ctx->domain, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialize certificate mapping rules. "
              "Authentication with certificates/Smartcards might not work "
              "as expected.\n");
        /* not fatal, ignored */
    }

    ret = sdap_init_certmap(id_ctx, id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialized certificate mapping.\n");
        return ret;
    }

    return EOK;
}

errno_t sssm_ldap_init(TALLOC_CTX *mem_ctx,
                       struct be_ctx *be_ctx,
                       struct data_provider *provider,
                       const char *module_name,
                       void **_module_data)
{
    struct sdap_service *sdap_service;
    struct ldap_init_ctx *init_ctx;
    errno_t ret;

    init_ctx = talloc_zero(mem_ctx, struct ldap_init_ctx);
    if (init_ctx == NULL) {
        return ENOMEM;
    }

    /* Always initialize options since it is needed everywhere. */
    ret = ldap_get_options(init_ctx, be_ctx->domain, be_ctx->cdb,
                           be_ctx->conf_path, be_ctx->provider,
                           &init_ctx->options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize LDAP options "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Always initialize id_ctx since it is needed everywhere. */
    ret = get_sdap_service(init_ctx, be_ctx, init_ctx->options, &sdap_service);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize failover service "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    init_ctx->id_ctx = sdap_id_ctx_new(init_ctx, be_ctx, sdap_service);
    if (init_ctx->id_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize LDAP ID context\n");
        ret = ENOMEM;
        goto done;
    }

    init_ctx->id_ctx->opts = init_ctx->options;

    /* Setup miscellaneous things. */
    ret = ldap_init_misc(be_ctx, init_ctx->options, init_ctx->id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init LDAP module "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Initialize auth_ctx only if one of the target is enabled. */
    if (dp_target_enabled(provider, module_name, DPT_AUTH, DPT_CHPASS)) {
        ret = ldap_init_auth_ctx(init_ctx, be_ctx, init_ctx->id_ctx,
                                 init_ctx->options, &init_ctx->auth_ctx);
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

errno_t sssm_ldap_id_init(TALLOC_CTX *mem_ctx,
                          struct be_ctx *be_ctx,
                          void *module_data,
                          struct dp_method *dp_methods)
{
    struct ldap_init_ctx *init_ctx;
    struct sdap_id_ctx *id_ctx;

    init_ctx = talloc_get_type(module_data, struct ldap_init_ctx);
    id_ctx = init_ctx->id_ctx;

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  sdap_account_info_handler_send, sdap_account_info_handler_recv, id_ctx,
                  struct sdap_id_ctx, struct dp_id_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_CHECK_ONLINE,
                  sdap_online_check_handler_send, sdap_online_check_handler_recv, id_ctx,
                  struct sdap_id_ctx, void, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send, default_account_domain_recv, NULL,
                  void, struct dp_get_acct_domain_data, struct dp_reply_std);

    return EOK;
}

errno_t sssm_ldap_auth_init(TALLOC_CTX *mem_ctx,
                            struct be_ctx *be_ctx,
                            void *module_data,
                            struct dp_method *dp_methods)
{
    struct ldap_init_ctx *init_ctx;
    struct sdap_auth_ctx *auth_ctx;

    init_ctx = talloc_get_type(module_data, struct ldap_init_ctx);
    auth_ctx = init_ctx->auth_ctx;

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  sdap_pam_auth_handler_send, sdap_pam_auth_handler_recv, auth_ctx,
                  struct sdap_auth_ctx, struct pam_data, struct pam_data *);

    return EOK;
}

errno_t sssm_ldap_chpass_init(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx,
                              void *module_data,
                              struct dp_method *dp_methods)
{
    struct ldap_init_ctx *init_ctx;
    struct sdap_auth_ctx *auth_ctx;
    errno_t ret;

    init_ctx = talloc_get_type(module_data, struct ldap_init_ctx);
    auth_ctx = init_ctx->auth_ctx;

    ret = init_chpass_service(auth_ctx, be_ctx, init_ctx->options,
                              &auth_ctx->chpass_service);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize chpass service "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  sdap_pam_chpass_handler_send, sdap_pam_chpass_handler_recv, auth_ctx,
                  struct sdap_auth_ctx, struct pam_data, struct pam_data *);

    return EOK;
}

errno_t sssm_ldap_access_init(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx,
                              void *module_data,
                              struct dp_method *dp_methods)
{
    struct ldap_init_ctx *init_ctx;
    struct sdap_access_ctx *access_ctx;
    errno_t ret;

    init_ctx = talloc_get_type(module_data, struct ldap_init_ctx);

    access_ctx = talloc_zero(mem_ctx, struct sdap_access_ctx);
    if(access_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    access_ctx->type = SDAP_TYPE_LDAP;
    access_ctx->id_ctx = init_ctx->id_ctx;

    ret = sdap_set_access_rules(access_ctx, access_ctx,
                                access_ctx->id_ctx->opts->basic, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "set_access_rules failed: [%d][%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    dp_set_method(dp_methods, DPM_ACCESS_HANDLER,
                  sdap_pam_access_handler_send, sdap_pam_access_handler_recv, access_ctx,
                  struct sdap_access_ctx, struct pam_data, struct pam_data *);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(access_ctx);
    }

    return ret;
}

errno_t sssm_ldap_hostid_init(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx,
                              void *module_data,
                              struct dp_method *dp_methods)
{
#ifdef BUILD_SSH
    struct ldap_init_ctx *init_ctx;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing LDAP host handler\n");
    init_ctx = talloc_get_type(module_data, struct ldap_init_ctx);

    return sdap_hostid_init(mem_ctx, be_ctx, init_ctx->id_ctx, dp_methods);

#else
    DEBUG(SSSDBG_MINOR_FAILURE, "HostID init handler called but SSSD is "
                                "built without SSH support, ignoring\n");
    return EOK;
#endif
}

errno_t sssm_ldap_autofs_init(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx,
                              void *module_data,
                              struct dp_method *dp_methods)
{
#ifdef BUILD_AUTOFS
    struct ldap_init_ctx *init_ctx;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing LDAP autofs handler\n");
    init_ctx = talloc_get_type(module_data, struct ldap_init_ctx);

    return sdap_autofs_init(mem_ctx, be_ctx, init_ctx->id_ctx, dp_methods);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Autofs init handler called but SSSD is "
                                 "built without autofs support, ignoring\n");
    return EOK;
#endif
}

errno_t sssm_ldap_sudo_init(TALLOC_CTX *mem_ctx,
                            struct be_ctx *be_ctx,
                            void *module_data,
                            struct dp_method *dp_methods)
{
#ifdef BUILD_SUDO
    struct ldap_init_ctx *init_ctx;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing LDAP sudo handler\n");
    init_ctx = talloc_get_type(module_data, struct ldap_init_ctx);

    return sdap_sudo_init(mem_ctx,
                          be_ctx,
                          init_ctx->id_ctx,
                          native_sudorule_map,
                          dp_methods);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Sudo init handler called but SSSD is "
                                 "built without sudo support, ignoring\n");
    return EOK;
#endif
}

errno_t sssm_ldap_resolver_init(TALLOC_CTX *mem_ctx,
                                struct be_ctx *be_ctx,
                                void *module_data,
                                struct dp_method *dp_methods)
{
    struct ldap_init_ctx *init_ctx;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing LDAP resolver handler\n");
    init_ctx = talloc_get_type(module_data, struct ldap_init_ctx);

    ret = sdap_resolver_ctx_new(init_ctx, init_ctx->id_ctx,
                                &init_ctx->resolver_ctx);
    if (ret != EOK) {
        return ret;
    }

    ret = ldap_resolver_setup_tasks(be_ctx, init_ctx->resolver_ctx,
                                    ldap_resolver_enumeration_send,
                                    ldap_resolver_enumeration_recv);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to setup resolver background tasks [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    dp_set_method(dp_methods, DPM_RESOLVER_HOSTS_HANDLER,
                  sdap_iphost_handler_send, sdap_iphost_handler_recv,
                  init_ctx->resolver_ctx, struct sdap_resolver_ctx,
                  struct dp_resolver_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_RESOLVER_IP_NETWORK_HANDLER,
                  sdap_ipnetwork_handler_send, sdap_ipnetwork_handler_recv,
                  init_ctx->resolver_ctx, struct sdap_resolver_ctx,
                  struct dp_resolver_data, struct dp_reply_std);

    return EOK;
}
