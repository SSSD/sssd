/*
    SSSD

    IPA Provider Initialization functions

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

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "util/child_common.h"
#include "providers/ipa/ipa_common.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_init_shared.h"
#include "providers/ipa/ipa_id.h"
#include "providers/ipa/ipa_auth.h"
#include "providers/ipa/ipa_access.h"
#include "providers/ipa/ipa_dyndns.h"
#include "providers/ipa/ipa_selinux.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ipa/ipa_subdomains.h"
#include "providers/ipa/ipa_srv.h"
#include "providers/be_dyndns.h"
#include "providers/ipa/ipa_session.h"

#define DNS_SRV_MISCONFIGURATION "SRV discovery is enabled on the IPA " \
    "server while using custom dns_discovery_domain. DNS discovery of " \
    "trusted AD domain will likely fail. It is recommended not to use " \
    "SRV discovery or the dns_discovery_domain option for the IPA "     \
    "domain while running on the server itself\n"

#define PREAUTH_INDICATOR_ERROR "Failed to create preauth indicator file, " \
    "special password prompting might not be available.\n"

struct ipa_init_ctx {
    struct ipa_options *options;
    struct ipa_id_ctx *id_ctx;
    struct ipa_auth_ctx *auth_ctx;
};


struct krb5_ctx *ipa_init_get_krb5_auth_ctx(void *data)
{
    struct ipa_init_ctx *ipa_init_ctx;

    ipa_init_ctx = talloc_get_type(data, struct ipa_init_ctx);
    if (ipa_init_ctx == NULL || ipa_init_ctx->auth_ctx == NULL) {
        return NULL;
    }

    return ipa_init_ctx->auth_ctx->krb5_auth_ctx;
}

static bool srv_in_server_list(const char *servers)
{
    TALLOC_CTX *tmp_ctx;
    char **list = NULL;
    int ret = 0;
    bool has_srv = false;

    if (servers == NULL) return true;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return false;
    }

    /* split server parm into a list */
    ret = split_on_separator(tmp_ctx, servers, ',', true, true, &list, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to parse server list!\n");
        goto done;
    }

    for (int i = 0; list[i]; i++) {
        has_srv = be_fo_is_srv_identifier(list[i]);
        if (has_srv == true) {
            break;
        }
    }

done:
    talloc_free(tmp_ctx);
    return has_srv;
}

static errno_t ipa_init_options(TALLOC_CTX *mem_ctx,
                                struct be_ctx *be_ctx,
                                struct ipa_options **_ipa_options)
{
    struct ipa_options *ipa_options;
    const char *ipa_servers;
    const char *ipa_backup_servers;
    const char *realm;
    errno_t ret;

    ret = ipa_get_options(mem_ctx, be_ctx->cdb, be_ctx->conf_path,
                          be_ctx->domain, &ipa_options);
    if (ret != EOK) {
        return ret;
    }

    ipa_servers = dp_opt_get_string(ipa_options->basic, IPA_SERVER);
    ipa_backup_servers = dp_opt_get_string(ipa_options->basic, IPA_BACKUP_SERVER);
    realm = dp_opt_get_string(ipa_options->basic, IPA_KRB5_REALM);

    ret = ipa_service_init(ipa_options, be_ctx, ipa_servers,
                           ipa_backup_servers, realm, "IPA", ipa_options,
                           &ipa_options->service);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to init IPA service [%d]: %s\n",
              ret, sss_strerror(ret));
        talloc_free(ipa_options);
        return ret;
    }

    *_ipa_options = ipa_options;
    return EOK;
}

static errno_t ipa_init_id_ctx(TALLOC_CTX *mem_ctx,
                               struct be_ctx *be_ctx,
                               struct ipa_options *ipa_options,
                               struct ipa_id_ctx **_ipa_id_ctx)
{
    struct ipa_id_ctx *ipa_id_ctx = NULL;
    struct sdap_id_ctx *sdap_id_ctx = NULL;
    char *basedn;
    errno_t ret;

    ipa_id_ctx = talloc_zero(mem_ctx, struct ipa_id_ctx);
    if (ipa_id_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    sdap_id_ctx = sdap_id_ctx_new(mem_ctx, be_ctx, ipa_options->service->sdap);
    if (sdap_id_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ipa_id_ctx->ipa_options = ipa_options;
    ipa_id_ctx->sdap_id_ctx = sdap_id_ctx;
    ipa_options->id_ctx = ipa_id_ctx;

    ret = ipa_get_id_options(ipa_options,
                             be_ctx->cdb,
                             be_ctx->conf_path,
                             be_ctx->provider,
                             true,
                             &sdap_id_ctx->opts);
    if (ret != EOK) {
        goto done;
    }

    ret = ipa_set_sdap_options(ipa_options, ipa_options->id);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set IPA sdap options\n");
        goto done;
    }

    ret = domain_to_basedn(mem_ctx,
                           dp_opt_get_string(ipa_options->basic, IPA_KRB5_REALM),
                           &basedn);
    if (ret != EOK) {
        goto done;
    }

    ret = ipa_set_search_bases(ipa_options,
                               be_ctx->cdb,
                               basedn,
                               be_ctx->conf_path,
                               NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set search bases\n");
        goto done;
    }

    *_ipa_id_ctx = ipa_id_ctx;

    ret = EOK;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init id context [%d]: %s\n",
              ret, sss_strerror(ret));

        talloc_free(ipa_id_ctx);
        talloc_free(sdap_id_ctx);
    }

    return ret;
}


static errno_t ipa_init_dyndns(struct be_ctx *be_ctx,
                               struct ipa_options *ipa_options)
{
    bool enabled;
    errno_t ret;

    ret = ipa_get_dyndns_options(be_ctx, ipa_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get dyndns options [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    enabled = dp_opt_get_bool(ipa_options->dyndns_ctx->opts,
                              DP_OPT_DYNDNS_UPDATE);
    if (!enabled) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Dynamic DNS updates are off.\n");
        return EOK;
    }

    /* Perform automatic DNS updates when the IP address changes.
     * Register a callback for successful LDAP reconnections.
     * This is the easiest way to identify that we have gone online.
     */

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Dynamic DNS updates are on. Checking for nsupdate...\n");

    ret = be_nsupdate_check();
    if (ret != EOK) {
        DEBUG(SSSDBG_CONF_SETTINGS, "nsupdate is not availabe, "
              "dynamic DNS updates will not work\n");
        return EOK;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "nsupdate is available\n");

    ret = ipa_dyndns_init(be_ctx, ipa_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failure setting up automatic DNS update\n");
        /* We will continue without DNS updating */
    }

    return EOK;
}

static errno_t ipa_init_server_mode(struct be_ctx *be_ctx,
                                    struct ipa_options *ipa_options,
                                    struct ipa_id_ctx *ipa_id_ctx)
{
    const char *ipa_servers;
    const char *dnsdomain;
    const char *hostname;
    bool sites_enabled;
    errno_t ret;

    ipa_id_ctx->view_name = talloc_strdup(ipa_id_ctx, SYSDB_DEFAULT_VIEW_NAME);
    if (ipa_id_ctx->view_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup() failed.\n");
        return ENOMEM;
    }

    ret = sysdb_update_view_name(be_ctx->domain->sysdb, ipa_id_ctx->view_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot add/update view name to sysdb.\n");
        return ret;
    }

    hostname = dp_opt_get_string(ipa_options->basic, IPA_HOSTNAME);
    ipa_servers = dp_opt_get_string(ipa_options->basic, IPA_SERVER);
    sites_enabled = dp_opt_get_bool(ipa_options->basic, IPA_ENABLE_DNS_SITES);
    dnsdomain = dp_opt_get_string(be_ctx->be_res->opts, DP_RES_OPT_DNS_DOMAIN);

    if (srv_in_server_list(ipa_servers) || sites_enabled) {
        DEBUG(SSSDBG_IMPORTANT_INFO, "SSSD configuration uses either DNS "
              "SRV resolution or IPA site discovery to locate IPA servers. "
              "On IPA server itself, it is recommended that SSSD is "
              "configured to only connect to the IPA server it's running at. ");

        /* If SRV discovery is enabled on the server and
         * dns_discovery_domain is set explicitly, then
         * the current failover code would use the dns_discovery
         * domain to try to find AD servers and fail.
         */
        if (dnsdomain != NULL) {
            sss_log(SSS_LOG_ERR, DNS_SRV_MISCONFIGURATION);
            DEBUG(SSSDBG_CRIT_FAILURE, DNS_SRV_MISCONFIGURATION);
        }

        ret = be_fo_set_dns_srv_lookup_plugin(be_ctx, hostname);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set SRV lookup plugin "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }

        return EOK;
    } else {
        /* In server mode we need to ignore the dns_discovery_domain if set
         * and only discover servers based on AD domains. */
        ret = dp_opt_set_string(be_ctx->be_res->opts, DP_RES_OPT_DNS_DOMAIN,
                                NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not reset the "
                  "dns_discovery_domain, trusted AD domains discovery "
                  "might fail. Please remove dns_discovery_domain "
                  "from the config file and restart the SSSD\n");
        } else {
            DEBUG(SSSDBG_CONF_SETTINGS, "The value of dns_discovery_domain "
                  "will be ignored in ipa_server_mode\n");
        }
    }

    return EOK;
}

static errno_t ipa_init_client_mode(struct be_ctx *be_ctx,
                                    struct ipa_options *ipa_options,
                                    struct ipa_id_ctx *ipa_id_ctx)
{
    struct ipa_srv_plugin_ctx *srv_ctx;
    const char *ipa_domain;
    const char *hostname;
    bool sites_enabled;
    errno_t ret;

    ret = sysdb_get_view_name(ipa_id_ctx, be_ctx->domain->sysdb,
                              &ipa_id_ctx->view_name);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot find view name in the cache. "
              "Will do online lookup later.\n");
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_get_view_name() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    hostname = dp_opt_get_string(ipa_options->basic, IPA_HOSTNAME);
    sites_enabled = dp_opt_get_bool(ipa_options->basic, IPA_ENABLE_DNS_SITES);

    if (sites_enabled) {
        /* use IPA plugin */
        ipa_domain = dp_opt_get_string(ipa_options->basic, IPA_DOMAIN);
        srv_ctx = ipa_srv_plugin_ctx_init(be_ctx, be_ctx->be_res->resolv,
                                          hostname, ipa_domain);
        if (srv_ctx == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory?\n");
            return ENOMEM;
        }

        be_fo_set_srv_lookup_plugin(be_ctx, ipa_srv_plugin_send,
                                    ipa_srv_plugin_recv, srv_ctx, "IPA");
    } else {
        /* fall back to standard plugin on clients. */
        ret = be_fo_set_dns_srv_lookup_plugin(be_ctx, hostname);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set SRV lookup plugin "
                  "[%d]: %s\n", ret, strerror(ret));
            return ret;
        }
    }

    return EOK;
}

static errno_t ipa_init_ipa_auth_ctx(TALLOC_CTX *mem_ctx,
                                     struct ipa_options *ipa_options,
                                     struct ipa_id_ctx *ipa_id_ctx,
                                     struct ipa_auth_ctx **_ipa_auth_ctx)
{
    struct ipa_auth_ctx *ipa_auth_ctx;
    errno_t ret;

    ipa_auth_ctx = talloc_zero(mem_ctx, struct ipa_auth_ctx);
    if (ipa_auth_ctx == NULL) {
        return ENOMEM;
    }

    ipa_auth_ctx->sdap_id_ctx = ipa_id_ctx->sdap_id_ctx;

    ret = dp_copy_options(ipa_auth_ctx, ipa_options->basic,
                          IPA_OPTS_BASIC, &ipa_auth_ctx->ipa_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "dp_copy_options failed.\n");
        talloc_free(ipa_auth_ctx);
        return ret;
    }

    *_ipa_auth_ctx = ipa_auth_ctx;

    return EOK;
}

static errno_t ipa_init_krb5_auth_ctx(TALLOC_CTX *mem_ctx,
                                      struct be_ctx *be_ctx,
                                      struct ipa_options *ipa_options,
                                      struct krb5_ctx **_krb5_auth_ctx)
{
    struct krb5_ctx *krb5_auth_ctx;
    bool server_mode;
    errno_t ret;

    krb5_auth_ctx = talloc_zero(mem_ctx, struct krb5_ctx);
    if (krb5_auth_ctx == NULL) {
        return ENOMEM;
    }

    krb5_auth_ctx->service = ipa_options->service->krb5_service;

    server_mode = dp_opt_get_bool(ipa_options->basic, IPA_SERVER_MODE);
    krb5_auth_ctx->config_type = server_mode ? K5C_IPA_SERVER : K5C_IPA_CLIENT;

    ret = ipa_get_auth_options(ipa_options, be_ctx->cdb, be_ctx->conf_path,
                               &krb5_auth_ctx->opts);
    if (ret != EOK) {
        talloc_free(krb5_auth_ctx);
        return ret;
    }

    *_krb5_auth_ctx = krb5_auth_ctx;
    return EOK;
}

static errno_t ipa_init_sdap_auth_ctx(TALLOC_CTX *mem_ctx,
                                      struct be_ctx *be_ctx,
                                      struct ipa_options *ipa_options,
                                      struct sdap_auth_ctx **_sdap_auth_ctx)
{
    struct sdap_auth_ctx *sdap_auth_ctx;

    sdap_auth_ctx = talloc_zero(mem_ctx, struct sdap_auth_ctx);
    if (sdap_auth_ctx == NULL) {
        return ENOMEM;
    }

    sdap_auth_ctx->be =  be_ctx;
    sdap_auth_ctx->service = ipa_options->service->sdap;

    if (ipa_options->id == NULL) {
        talloc_free(sdap_auth_ctx);
        return EINVAL;
    }

    sdap_auth_ctx->opts = ipa_options->id;

    *_sdap_auth_ctx = sdap_auth_ctx;

    return EOK;
}

static struct sdap_ext_member_ctx *
ipa_create_ext_members_ctx(TALLOC_CTX *mem_ctx,
                           struct ipa_id_ctx *id_ctx)
{
    struct sdap_ext_member_ctx *ext_ctx = NULL;

    ext_ctx = talloc_zero(mem_ctx, struct sdap_ext_member_ctx);
    if (ext_ctx == NULL) {
        return NULL;
    }

    ext_ctx->pvt = id_ctx;
    ext_ctx->ext_member_resolve_send = ipa_ext_group_member_send;
    ext_ctx->ext_member_resolve_recv = ipa_ext_group_member_recv;

    return ext_ctx;
}

static errno_t ipa_init_auth_ctx(TALLOC_CTX *mem_ctx,
                                 struct be_ctx *be_ctx,
                                 struct ipa_options *ipa_options,
                                 struct ipa_id_ctx *id_ctx,
                                 struct ipa_auth_ctx **_auth_ctx)
{
    struct sdap_auth_ctx *sdap_auth_ctx;
    struct ipa_auth_ctx *ipa_auth_ctx;
    struct krb5_ctx *krb5_auth_ctx;
    errno_t ret;

    ret = ipa_init_ipa_auth_ctx(mem_ctx, ipa_options, id_ctx, &ipa_auth_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init IPA auth context\n");
        return ret;
    }

    ipa_options->auth_ctx = ipa_auth_ctx;

    ret = ipa_init_krb5_auth_ctx(ipa_auth_ctx, be_ctx, ipa_options,
                                 &krb5_auth_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init KRB5 auth context\n");
        goto done;
    }
    ipa_options->auth_ctx->krb5_auth_ctx = krb5_auth_ctx;

    ret = ipa_init_sdap_auth_ctx(ipa_auth_ctx, be_ctx, ipa_options,
                                 &sdap_auth_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init SDAP auth context\n");
        goto done;
    }
    ipa_options->auth_ctx->sdap_auth_ctx = sdap_auth_ctx;

    setup_ldap_debug(sdap_auth_ctx->opts->basic);

    ret = setup_tls_config(sdap_auth_ctx->opts->basic);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "setup_tls_config failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Initialize features needed by the krb5_child */
    ret = krb5_child_init(krb5_auth_ctx, be_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not initialize krb5_child "
              "settings [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = create_preauth_indicator();
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, PREAUTH_INDICATOR_ERROR);
        sss_log(SSSDBG_CRIT_FAILURE, PREAUTH_INDICATOR_ERROR);
    }

    *_auth_ctx = ipa_auth_ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ipa_auth_ctx);
    }

    return ret;
}

static bool ipa_check_fqdn(const char *str)
{
    return strchr(str, '.');
}

static errno_t ipa_init_misc(struct be_ctx *be_ctx,
                             struct ipa_options *ipa_options,
                             struct ipa_id_ctx *ipa_id_ctx,
                             struct sdap_id_ctx *sdap_id_ctx)
{
    errno_t ret;

    if (!ipa_check_fqdn(dp_opt_get_string(ipa_options->basic,
                        IPA_HOSTNAME))) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ipa_hostname is not Fully Qualified Domain Name.\n");
    }

    ret = ipa_init_dyndns(be_ctx, ipa_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init dyndns [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    setup_ldap_debug(sdap_id_ctx->opts->basic);

    ret = setup_tls_config(sdap_id_ctx->opts->basic);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get TLS options [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    ret = ipa_idmap_init(sdap_id_ctx, sdap_id_ctx,
                         &sdap_id_ctx->opts->idmap_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not initialize ID mapping. In case ID mapping properties "
              "changed on the server, please remove the SSSD database\n");
        return ret;
    }

    ret = ldap_id_setup_tasks(sdap_id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup background tasks "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    if (dp_opt_get_bool(ipa_options->basic, IPA_SERVER_MODE)) {
        ret = ipa_init_server_mode(be_ctx, ipa_options, ipa_id_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init server mode "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }
    } else {
        ret = ipa_init_client_mode(be_ctx, ipa_options, ipa_id_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init client mode "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }
    }

    ret = ipa_refresh_init(be_ctx, ipa_id_ctx);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Periodical refresh "
              "will not work [%d]: %s\n", ret, sss_strerror(ret));
    }

    ipa_id_ctx->sdap_id_ctx->opts->ext_ctx = ipa_create_ext_members_ctx(
                                ipa_id_ctx->sdap_id_ctx->opts, ipa_id_ctx);
    if (ipa_id_ctx->sdap_id_ctx->opts->ext_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set the extrernal group ctx\n");
        return ENOMEM;
    }

    ret = sdap_init_certmap(sdap_id_ctx, sdap_id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialized certificate mapping.\n");
        return ret;
    }

    /* We must ignore entries in the views search base
     * (default: cn=views,cn=accounts,$BASEDN) */
    sdap_id_ctx->opts->sdom->ignore_user_search_bases = \
                                   ipa_id_ctx->ipa_options->views_search_bases;

    return EOK;
}

errno_t sssm_ipa_init(TALLOC_CTX *mem_ctx,
                      struct be_ctx *be_ctx,
                      struct data_provider *provider,
                      const char *module_name,
                      void **_module_data)
{
    struct ipa_init_ctx *init_ctx;
    errno_t ret;

    init_ctx = talloc_zero(mem_ctx, struct ipa_init_ctx);
    if (init_ctx == NULL) {
        return ENOMEM;
    }

    /* Always initialize options since it is needed everywhere. */
    ret = ipa_init_options(init_ctx, be_ctx, &init_ctx->options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init IPA options "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Always initialize id_ctx since it is needed everywhere. */
    ret = ipa_init_id_ctx(init_ctx, be_ctx, init_ctx->options,
                          &init_ctx->id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init IPA ID context "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Setup miscellaneous things. */
    ret = ipa_init_misc(be_ctx, init_ctx->options, init_ctx->id_ctx,
                        init_ctx->id_ctx->sdap_id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init IPA module "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Initialize auth_ctx only if one of the target is enabled. */
    if (dp_target_enabled(provider, module_name, DPT_AUTH, DPT_CHPASS)) {
        ret = ipa_init_auth_ctx(init_ctx, be_ctx, init_ctx->options,
                                init_ctx->id_ctx, &init_ctx->auth_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init IPA auth context "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
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

errno_t sssm_ipa_id_init(TALLOC_CTX *mem_ctx,
                         struct be_ctx *be_ctx,
                         void *module_data,
                         struct dp_method *dp_methods)
{
    struct ipa_init_ctx *init_ctx;
    struct ipa_id_ctx *id_ctx;

    init_ctx = talloc_get_type(module_data, struct ipa_init_ctx);
    id_ctx = init_ctx->id_ctx;

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  ipa_account_info_handler_send, ipa_account_info_handler_recv, id_ctx,
                  struct ipa_id_ctx, struct dp_id_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_CHECK_ONLINE,
                  sdap_online_check_handler_send, sdap_online_check_handler_recv, id_ctx->sdap_id_ctx,
                  struct sdap_id_ctx, void, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send, default_account_domain_recv, NULL,
                  void, struct dp_get_acct_domain_data, struct dp_reply_std);

    return EOK;
}

errno_t sssm_ipa_auth_init(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           void *module_data,
                           struct dp_method *dp_methods)
{
    struct ipa_init_ctx *init_ctx;
    struct ipa_auth_ctx *auth_ctx;

    init_ctx = talloc_get_type(module_data, struct ipa_init_ctx);
    auth_ctx = init_ctx->auth_ctx;

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  ipa_pam_auth_handler_send, ipa_pam_auth_handler_recv, auth_ctx,
                  struct ipa_auth_ctx, struct pam_data, struct pam_data *);

    return EOK;
}

errno_t sssm_ipa_chpass_init(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             void *module_data,
                             struct dp_method *dp_methods)
{
    return sssm_ipa_auth_init(mem_ctx, be_ctx, module_data, dp_methods);
}

errno_t sssm_ipa_access_init(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             void *module_data,
                             struct dp_method *dp_methods)
{
    struct ipa_access_ctx *access_ctx;
    struct ipa_init_ctx *init_ctx;
    struct ipa_id_ctx *id_ctx;
    errno_t ret;

    init_ctx = talloc_get_type(module_data, struct ipa_init_ctx);
    id_ctx = init_ctx->id_ctx;

    access_ctx = talloc_zero(mem_ctx, struct ipa_access_ctx);
    if (access_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed.\n");
        return ENOMEM;
    }

    access_ctx->sdap_ctx = id_ctx->sdap_id_ctx;
    access_ctx->host_map = id_ctx->ipa_options->id->host_map;
    access_ctx->hostgroup_map = id_ctx->ipa_options->hostgroup_map;
    access_ctx->host_search_bases = id_ctx->ipa_options->id->sdom->host_search_bases;
    access_ctx->hbac_search_bases = id_ctx->ipa_options->hbac_search_bases;

    ret = dp_copy_options(access_ctx, id_ctx->ipa_options->basic,
                          IPA_OPTS_BASIC, &access_ctx->ipa_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "dp_copy_options() failed.\n");
        goto done;
    }

    /* Set up an sdap_access_ctx for checking as configured */
    access_ctx->sdap_access_ctx = talloc_zero(access_ctx, struct sdap_access_ctx);
    if (access_ctx->sdap_access_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        ret = ENOMEM;
        goto done;
    }

    access_ctx->sdap_access_ctx->type = SDAP_TYPE_IPA;
    access_ctx->sdap_access_ctx->id_ctx = access_ctx->sdap_ctx;
    ret = sdap_set_access_rules(access_ctx, access_ctx->sdap_access_ctx,
                                access_ctx->ipa_options,
                                id_ctx->ipa_options->id->basic);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sdap_set_access_rules failed: [%d][%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    dp_set_method(dp_methods, DPM_ACCESS_HANDLER,
                  ipa_pam_access_handler_send, ipa_pam_access_handler_recv, access_ctx,
                  struct ipa_access_ctx, struct pam_data, struct pam_data *);

    dp_set_method(dp_methods, DPM_REFRESH_ACCESS_RULES,
                      ipa_refresh_access_rules_send, ipa_refresh_access_rules_recv, access_ctx,
                      struct ipa_access_ctx, void, void *);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(access_ctx);
    }

    return ret;
}

errno_t sssm_ipa_selinux_init(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx,
                              void *module_data,
                              struct dp_method *dp_methods)
{
#if defined HAVE_SELINUX
    struct ipa_selinux_ctx *selinux_ctx;
    struct ipa_init_ctx *init_ctx;
    struct ipa_options *opts;

    init_ctx = talloc_get_type(module_data, struct ipa_init_ctx);
    opts = init_ctx->options;

    selinux_ctx = talloc_zero(mem_ctx, struct ipa_selinux_ctx);
    if (selinux_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed.\n");
        return ENOMEM;
    }

    selinux_ctx->id_ctx = init_ctx->id_ctx;
    selinux_ctx->hbac_search_bases = opts->hbac_search_bases;
    selinux_ctx->host_search_bases = opts->id->sdom->host_search_bases;
    selinux_ctx->selinux_search_bases = opts->selinux_search_bases;

    dp_set_method(dp_methods, DPM_SELINUX_HANDLER,
                  ipa_selinux_handler_send, ipa_selinux_handler_recv, selinux_ctx,
                  struct ipa_selinux_ctx, struct pam_data, struct pam_data *);

    return EOK;
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "SELinux init handler called but SSSD is "
                                "built without SELinux support, ignoring\n");
    return EOK;
#endif
}

errno_t sssm_ipa_hostid_init(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             void *module_data,
                             struct dp_method *dp_methods)
{
#ifdef BUILD_SSH
    struct ipa_init_ctx *init_ctx;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing IPA host handler\n");
    init_ctx = talloc_get_type(module_data, struct ipa_init_ctx);

    return ipa_hostid_init(mem_ctx, be_ctx, init_ctx->id_ctx, dp_methods);

#else
    DEBUG(SSSDBG_MINOR_FAILURE, "HostID init handler called but SSSD is "
                                "built without SSH support, ignoring\n");
    return EOK;
#endif
}

errno_t sssm_ipa_autofs_init(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             void *module_data,
                             struct dp_method *dp_methods)
{
#ifdef BUILD_AUTOFS
    struct ipa_init_ctx *init_ctx;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing IPA autofs handler\n");
    init_ctx = talloc_get_type(module_data, struct ipa_init_ctx);

    return ipa_autofs_init(mem_ctx, be_ctx, init_ctx->id_ctx, dp_methods);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Autofs init handler called but SSSD is "
                                "built without autofs support, ignoring\n");
    return EOK;
#endif
}

errno_t sssm_ipa_subdomains_init(TALLOC_CTX *mem_ctx,
                                 struct be_ctx *be_ctx,
                                 void *module_data,
                                 struct dp_method *dp_methods)
{
    struct ipa_init_ctx *init_ctx;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing IPA subdomains handler\n");
    init_ctx = talloc_get_type(module_data, struct ipa_init_ctx);

    return ipa_subdomains_init(mem_ctx, be_ctx, init_ctx->id_ctx, dp_methods);
}

errno_t sssm_ipa_sudo_init(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           void *module_data,
                           struct dp_method *dp_methods)
{
#ifdef BUILD_SUDO
    struct ipa_init_ctx *init_ctx;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing IPA sudo handler\n");
    init_ctx = talloc_get_type(module_data, struct ipa_init_ctx);

    return ipa_sudo_init(mem_ctx, be_ctx, init_ctx->id_ctx, dp_methods);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Sudo init handler called but SSSD is "
                                "built without sudo support, ignoring\n");
    return EOK;
#endif
}

errno_t sssm_ipa_session_init(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx,
                              void *module_data,
                              struct dp_method *dp_methods)
{
    struct ipa_session_ctx *session_ctx;
    struct ipa_init_ctx *init_ctx;
    struct ipa_id_ctx *id_ctx;
    errno_t ret;

    init_ctx = talloc_get_type(module_data, struct ipa_init_ctx);
    id_ctx = init_ctx->id_ctx;

    session_ctx = talloc_zero(mem_ctx, struct ipa_session_ctx);
    if (session_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed.\n");

        return ENOMEM;
    }

    session_ctx->sdap_ctx = id_ctx->sdap_id_ctx;
    session_ctx->host_map = id_ctx->ipa_options->id->host_map;
    session_ctx->hostgroup_map = id_ctx->ipa_options->hostgroup_map;
    session_ctx->host_search_bases = id_ctx->ipa_options->id->sdom->host_search_bases;
    session_ctx->deskprofile_search_bases = id_ctx->ipa_options->deskprofile_search_bases;

    ret = dp_copy_options(session_ctx, id_ctx->ipa_options->basic,
                          IPA_OPTS_BASIC, &session_ctx->ipa_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "dp_copy_options() failed.\n");

        goto done;
    }

    dp_set_method(dp_methods, DPM_SESSION_HANDLER,
                  ipa_pam_session_handler_send, ipa_pam_session_handler_recv, session_ctx,
                  struct ipa_session_ctx, struct pam_data, struct pam_data *);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(session_ctx);
    }

    return ret;
}
