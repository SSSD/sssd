/*
    SSSD

    minimal Provider Initialization functions

    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Copyright (C) 2025 Red Hat

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

#include "src/providers/data_provider.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/ldap_opts.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/ldap_resolver_enum.h"
#include "providers/fail_over_srv.h"
#include "providers/be_refresh.h"

#include "src/providers/minimal/minimal.h"
#include "src/providers/minimal/minimal_id.h"
#include "src/providers/minimal/minimal_ldap_auth.h"
#include "src/providers/failover/failover.h"
#include "src/providers/failover/failover_vtable.h"
#include "src/providers/failover/ldap/failover_ldap.h"

/* Copied from ldap_init.c with no changes */
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

/* Copied from sdap.c: these were made static there when the calls were
 * moved into sdap_connect_send(). The minimal provider still needs them
 * at init time for testing purposes. */
static void sss_ldap_debug(const char *buf)
{
    sss_debug_fn(__FILE__, __LINE__, __FUNCTION__, SSSDBG_TRACE_ALL,
                "libldap: %s", buf);
}

static void setup_ldap_debug(struct dp_option *basic_opts)
{
    int ret;
    int ldap_debug_level;

    ldap_debug_level = dp_opt_get_int(basic_opts, SDAP_LIBRARY_DEBUG_LEVEL);
    if (ldap_debug_level == 0) {
        return;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Setting LDAP library debug level [%d].\n",
                                ldap_debug_level);

    ret = ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &ldap_debug_level);
    if (ret != LBER_OPT_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set LBER_OPT_DEBUG_LEVEL, ignored .\n");
    }

    ret = ber_set_option(NULL,  LBER_OPT_LOG_PRINT_FN, sss_ldap_debug);
    if (ret != LBER_OPT_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set LBER_OPT_LOG_PRINT_FN, ignored .\n");
    }

    ret = ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &ldap_debug_level);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set LDAP_OPT_DEBUG_LEVEL, ignored .\n");
    }
}

static errno_t setup_tls_config(struct dp_option *basic_opts)
{
    int ret;
    int ldap_opt_x_tls_require_cert;
    const char *tls_opt;
    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_REQCERT);
    if (tls_opt) {
        if (strcasecmp(tls_opt, "never") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_NEVER;
        }
        else if (strcasecmp(tls_opt, "allow") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_ALLOW;
        }
        else if (strcasecmp(tls_opt, "try") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_TRY;
        }
        else if (strcasecmp(tls_opt, "demand") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_DEMAND;
        }
        else if (strcasecmp(tls_opt, "hard") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_HARD;
        }
        else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unknown value for tls_reqcert '%s'.\n", tls_opt);
            return EINVAL;
        }
        /* LDAP_OPT_X_TLS_REQUIRE_CERT has to be set as a global option,
         * because the SSL/TLS context is initialized from this value. */
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
                              &ldap_opt_x_tls_require_cert);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_set_option(req_cert) failed: %s\n",
                  sss_ldap_err2string(ret));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CACERT);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_set_option(cacertfile) failed: %s\n",
                  sss_ldap_err2string(ret));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CACERTDIR);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTDIR, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_set_option(cacertdir) failed: %s\n",
                  sss_ldap_err2string(ret));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CERT);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_set_option(certfile) failed: %s\n",
                  sss_ldap_err2string(ret));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_KEY);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_KEYFILE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_set_option(keyfile) failed: %s\n",
                  sss_ldap_err2string(ret));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CIPHER_SUITE);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CIPHER_SUITE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_set_option(cipher) failed: %s\n",
                  sss_ldap_err2string(ret));
            return EIO;
        }
    }

    return EOK;
}

/* Copied from ldap_init.c with some changes
 * removing calls to
 * - sdap_gssapi_init()
 * - sdap_idmap_init()
 * - confdb_certmap_to_sysdb()
 * - sdap_init_certmap() */
static errno_t ldap_init_misc(struct be_ctx *be_ctx,
                              struct sdap_options *options,
                              struct sdap_id_ctx *id_ctx)
{
    errno_t ret;

    setup_ldap_debug(options->basic);

    ret = setup_tls_config(options->basic);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get TLS options [%d]: %s\n",
              ret, sss_strerror(ret));
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

    return EOK;
}

/* Copied from ldap_init.c */
static errno_t minimal_init_auth_ctx(TALLOC_CTX *mem_ctx,
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

static struct sss_failover_ctx *
sssm_minimal_init_failover(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           struct sdap_options *opts)
{
    struct sss_failover_ctx *fctx;
    struct sss_failover_group *group;
    struct sss_failover_server *server;
    errno_t ret;

    /* Setup new failover. */
    fctx = sss_failover_init(mem_ctx, be_ctx->ev, "LDAP",
                             be_ctx->be_res->resolv,
                             be_ctx->be_res->family_order);
    if (fctx == NULL) {
        return NULL;
    }

    /* Add primary servers */
    group = sss_failover_group_new(fctx, "primary");
    if (group == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_failover_group_setup_dns_discovery(group);
    if (ret != EOK) {
        goto done;
    }

    server = sss_failover_server_new(fctx, "fake_1.ldap.test",
                                     "ldap://fake_1.ldap.test", 389, 1, 1);
    if (server == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_failover_group_add_server(group, server);
    if (ret != EOK) {
        goto done;
    }

    server = sss_failover_server_new(fctx, "fake_2.ldap.test",
                                     "ldap://fake_2.ldap.test", 389, 1, 1);
    if (server == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_failover_group_add_server(group, server);
    if (ret != EOK) {
        goto done;
    }

    server = sss_failover_server_new(fctx, "master.ldap.test",
                                     "ldap://master.ldap.test", 389, 1, 1);
    if (server == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_failover_group_add_server(group, server);
    if (ret != EOK) {
        goto done;
    }

    sss_failover_vtable_set_connect(fctx,
                                    sss_failover_ldap_connect_send,
                                    sss_failover_ldap_connect_recv,
                                    opts);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(fctx);
        return NULL;
    }

    return fctx;
}

errno_t sssm_minimal_init(TALLOC_CTX *mem_ctx,
                      struct be_ctx *be_ctx,
                      struct data_provider *provider,
                      const char *module_name,
                      void **_module_data)
{
    struct sdap_service *sdap_service;
    struct minimal_init_ctx *init_ctx;
    errno_t ret;

    init_ctx = talloc_zero(mem_ctx, struct minimal_init_ctx);
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

    /* Initialize auth_ctx only if DPT_AUTH target is enabled. */
    if (dp_target_enabled(provider, module_name, DPT_AUTH)) {
        ret = minimal_init_auth_ctx(init_ctx, be_ctx, init_ctx->id_ctx,
                                    init_ctx->options, &init_ctx->auth_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create auth context "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }
    }

    /* Setup new failover. */
    init_ctx->fctx = sssm_minimal_init_failover(init_ctx, be_ctx, init_ctx->id_ctx->opts);
    if (init_ctx->fctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to init new failover\n");
        ret = ENOMEM;
        goto done;
    }

    *_module_data = init_ctx;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(init_ctx);
    }

    return ret;
}

errno_t sssm_minimal_id_init(TALLOC_CTX *mem_ctx,
                         struct be_ctx *be_ctx,
                         void *module_data,
                         struct dp_method *dp_methods)
{
    struct minimal_init_ctx *init_ctx;
    errno_t ret;

    init_ctx = talloc_get_type(module_data, struct minimal_init_ctx);

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  minimal_account_info_handler_send, minimal_account_info_handler_recv, init_ctx,
                  struct minimal_init_ctx, struct dp_id_data, struct dp_reply_std);

    /* LDAP provider check online handler */
    dp_set_method(dp_methods, DPM_CHECK_ONLINE,
                  sdap_online_check_handler_send, sdap_online_check_handler_recv, init_ctx->id_ctx,
                  struct sdap_id_ctx, void, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send, default_account_domain_recv, NULL,
                  void, struct dp_get_acct_domain_data, struct dp_reply_std);

    ret = EOK;

    return ret;
}

errno_t sssm_minimal_auth_init(TALLOC_CTX *mem_ctx,
                               struct be_ctx *be_ctx,
                               void *module_data,
                               struct dp_method *dp_methods)
{
    struct minimal_init_ctx *init_ctx;

    init_ctx = talloc_get_type(module_data, struct minimal_init_ctx);

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  minimal_sdap_pam_auth_handler_send, minimal_sdap_pam_auth_handler_recv, init_ctx,
                  struct minimal_init_ctx, struct pam_data, struct pam_data *);

    return EOK;
}
