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
#include "providers/ipa/ipa_hostid.h"
#include "providers/ipa/ipa_dyndns.h"
#include "providers/ipa/ipa_selinux.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ipa/ipa_subdomains.h"
#include "providers/ipa/ipa_srv.h"
#include "providers/dp_dyndns.h"

struct ipa_options *ipa_options = NULL;

/* Id Handler */
struct bet_ops ipa_id_ops = {
    .handler = ipa_account_info_handler,
    .finalize = NULL,
    .check_online = ipa_check_online
};

struct bet_ops ipa_auth_ops = {
    .handler = ipa_auth,
    .finalize = NULL,
};

struct bet_ops ipa_chpass_ops = {
    .handler = ipa_auth,
    .finalize = NULL,
};

struct bet_ops ipa_access_ops = {
    .handler = ipa_access_handler,
    .finalize = NULL
};

struct bet_ops ipa_selinux_ops = {
    .handler = ipa_selinux_handler,
    .finalize = NULL
};

#ifdef BUILD_SSH
struct bet_ops ipa_hostid_ops = {
    .handler = ipa_host_info_handler,
    .finalize = NULL
};
#endif

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

int common_ipa_init(struct be_ctx *bectx)
{
    const char *ipa_servers;
    const char *ipa_backup_servers;
    int ret;

    ret = ipa_get_options(bectx, bectx->cdb,
                          bectx->conf_path,
                          bectx->domain, &ipa_options);
    if (ret != EOK) {
        return ret;
    }

    ipa_servers = dp_opt_get_string(ipa_options->basic, IPA_SERVER);
    ipa_backup_servers = dp_opt_get_string(ipa_options->basic, IPA_BACKUP_SERVER);

    ret = ipa_service_init(ipa_options, bectx, ipa_servers,
                           ipa_backup_servers, ipa_options,
                           &ipa_options->service);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to init IPA failover service!\n");
        return ret;
    }

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

int sssm_ipa_id_init(struct be_ctx *bectx,
                     struct bet_ops **ops,
                     void **pvt_data)
{
    struct ipa_id_ctx *ipa_ctx;
    struct sdap_id_ctx *sdap_ctx;
    const char *hostname;
    const char *ipa_domain;
    const char *ipa_servers;
    struct ipa_srv_plugin_ctx *srv_ctx;
    bool server_mode;
    int ret;

    if (!ipa_options) {
        ret = common_ipa_init(bectx);
        if (ret != EOK) {
            return ret;
        }
    }

    if (ipa_options->id_ctx) {
        /* already initialized */
        *ops = &ipa_id_ops;
        *pvt_data = ipa_options->id_ctx;
        return EOK;
    }

    ipa_ctx = talloc_zero(ipa_options, struct ipa_id_ctx);
    if (!ipa_ctx) {
        return ENOMEM;
    }
    ipa_options->id_ctx = ipa_ctx;
    ipa_ctx->ipa_options = ipa_options;

    sdap_ctx = sdap_id_ctx_new(ipa_options, bectx, ipa_options->service->sdap);
    if (sdap_ctx == NULL) {
        return ENOMEM;
    }
    ipa_ctx->sdap_id_ctx = sdap_ctx;

    ret = ipa_get_id_options(ipa_options, bectx->cdb,
                             bectx->conf_path,
                             &sdap_ctx->opts);
    if (ret != EOK) {
        goto done;
    }

    ret = ipa_get_dyndns_options(bectx, ipa_options);
    if (ret != EOK) {
        goto done;
    }

    if (dp_opt_get_bool(ipa_options->dyndns_ctx->opts, DP_OPT_DYNDNS_UPDATE)) {
        /* Perform automatic DNS updates when the
         * IP address changes.
         * Register a callback for successful LDAP
         * reconnections. This is the easiest way to
         * identify that we have gone online.
         */

        DEBUG(SSSDBG_CONF_SETTINGS,
              "Dynamic DNS updates are on. Checking for nsupdate..\n");
        ret = be_nsupdate_check();
        if (ret == EOK) {
            /* nsupdate is available. Dynamic updates
             * are supported
             */
            ret = ipa_dyndns_init(sdap_ctx->be, ipa_options);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failure setting up automatic DNS update\n");
                /* We will continue without DNS updating */
            }
        }
    }

    ret = setup_tls_config(sdap_ctx->opts->basic);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "setup_tls_config failed [%d][%s].\n",
                  ret, strerror(ret));
        goto done;
    }


    /* Set up the ID mapping object */
    ret = ipa_idmap_init(sdap_ctx, sdap_ctx, &sdap_ctx->opts->idmap_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not initialize ID mapping. In case ID mapping properties "
              "changed on the server, please remove the SSSD database\n");
        goto done;
    }


    ret = ldap_id_setup_tasks(sdap_ctx);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_setup_child();
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "setup_child failed [%d][%s].\n",
                  ret, strerror(ret));
        goto done;
    }

    /* setup SRV lookup plugin */
    hostname = dp_opt_get_string(ipa_options->basic, IPA_HOSTNAME);
    server_mode = dp_opt_get_bool(ipa_options->basic, IPA_SERVER_MODE);

    if (server_mode == true) {
        ipa_ctx->view_name = talloc_strdup(ipa_ctx, SYSDB_DEFAULT_VIEW_NAME);
        if (ipa_ctx->view_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_update_view_name(bectx->domain->sysdb, ipa_ctx->view_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot add/update view name to sysdb.\n");
            goto done;
        }

        ipa_servers = dp_opt_get_string(ipa_options->basic, IPA_SERVER);
        if (srv_in_server_list(ipa_servers) == true
                || dp_opt_get_bool(ipa_options->basic,
                                   IPA_ENABLE_DNS_SITES) == true) {
            DEBUG(SSSDBG_MINOR_FAILURE, "SRV resolution or IPA sites enabled "
                  "on the IPA server. Site discovery of trusted AD servers "
                  "might not work\n");

            /* If SRV discovery is enabled on the server and
             * dns_discovery_domain is set explicitly, then
             * the current failover code would use the dns_discovery
             * domain to try to find AD servers and fail
             */
            if (dp_opt_get_string(bectx->be_res->opts,
                                  DP_RES_OPT_DNS_DOMAIN)) {
                sss_log(SSS_LOG_ERR, ("SRV discovery is enabled on the IPA "
                        "server while using custom dns_discovery_domain. "
                        "DNS discovery of trusted AD domain will likely fail. "
                        "It is recommended not to use SRV discovery or the "
                        "dns_discovery_domain option for the IPA domain while "
                        "running on the server itself\n"));
                DEBUG(SSSDBG_CRIT_FAILURE, "SRV discovery is enabled on IPA "
                      "server while using custom dns_discovery_domain. "
                      "DNS discovery of trusted AD domain will likely fail. "
                      "It is recommended not to use SRV discovery or the "
                      "dns_discovery_domain option for the IPA domain while "
                      "running on the server itself\n");
            }

            ret = be_fo_set_dns_srv_lookup_plugin(bectx, hostname);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set SRV lookup plugin "
                                            "[%d]: %s\n", ret, strerror(ret));
                goto done;
            }
        } else {
            /* In server mode we need to ignore the dns_discovery_domain if set
             * and only discover servers based on AD domains
             */
            ret = dp_opt_set_string(bectx->be_res->opts, DP_RES_OPT_DNS_DOMAIN,
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
    } else {
        ret = sysdb_get_view_name(ipa_ctx, bectx->domain->sysdb,
                                  &ipa_ctx->view_name);
        if (ret != EOK) {
            if (ret == ENOENT) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Cannot find view name in the cache. " \
                      "Will do online lookup later.\n");
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_get_view_name failed.\n");
                goto done;
            }
        }

        if (dp_opt_get_bool(ipa_options->basic, IPA_ENABLE_DNS_SITES)) {
            /* use IPA plugin */
            ipa_domain = dp_opt_get_string(ipa_options->basic, IPA_DOMAIN);
            srv_ctx = ipa_srv_plugin_ctx_init(bectx, bectx->be_res->resolv,
                                              hostname, ipa_domain);
            if (srv_ctx == NULL) {
                DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory?\n");
                ret = ENOMEM;
                goto done;
            }

            be_fo_set_srv_lookup_plugin(bectx, ipa_srv_plugin_send,
                                        ipa_srv_plugin_recv, srv_ctx, "IPA");
        } else {
            /* fall back to standard plugin on clients. */
            ret = be_fo_set_dns_srv_lookup_plugin(bectx, hostname);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set SRV lookup plugin "
                                            "[%d]: %s\n", ret, strerror(ret));
                goto done;
            }
        }
    }

    /* setup periodical refresh of expired records */
    ret = sdap_refresh_init(bectx->refresh_ctx, sdap_ctx);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Periodical refresh "
              "will not work [%d]: %s\n", ret, strerror(ret));
    }

    ipa_ctx->sdap_id_ctx->opts->ext_ctx = ipa_create_ext_members_ctx(
                                                    ipa_ctx->sdap_id_ctx->opts,
                                                    ipa_ctx);
    if (ipa_ctx->sdap_id_ctx->opts->ext_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to set SRV the extrernal group ctx\n");
        ret = ENOMEM;
        goto done;
    }

    *ops = &ipa_id_ops;
    *pvt_data = ipa_ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(ipa_options->id_ctx);
    }
    return ret;
}

void cleanup_ipa_preauth_indicator(void)
{
    int ret;

    ret = unlink(PAM_PREAUTH_INDICATOR);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to remove preauth indicator file [%s].\n",
              PAM_PREAUTH_INDICATOR);
    }
}

static errno_t create_ipa_preauth_indicator(void)
{
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    int fd;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    fd = open(PAM_PREAUTH_INDICATOR, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW,
              0644);
    if (fd < 0) {
        if (errno != EEXIST) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to create preauth indicator file [%s].\n",
                  PAM_PREAUTH_INDICATOR);
            ret = EOK;
            goto done;
        }

        DEBUG(SSSDBG_CRIT_FAILURE,
              "Preauth indicator file [%s] already exists. "
              "Maybe it is left after an unplanned exit. Continuing.\n",
              PAM_PREAUTH_INDICATOR);
    } else {
        close(fd);
    }

    ret = atexit(cleanup_ipa_preauth_indicator);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "atexit failed. Continuing.\n");
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

int sssm_ipa_auth_init(struct be_ctx *bectx,
                       struct bet_ops **ops,
                       void **pvt_data)
{
    struct ipa_auth_ctx *ipa_auth_ctx;
    struct ipa_id_ctx *id_ctx;
    struct krb5_ctx *krb5_auth_ctx;
    struct sdap_auth_ctx *sdap_auth_ctx;
    struct bet_ops *id_ops;
    int ret;

    if (!ipa_options) {
        ret = common_ipa_init(bectx);
        if (ret != EOK) {
            return ret;
        }
    }

    if (ipa_options->auth_ctx) {
        /* already initialized */
        *ops = &ipa_auth_ops;
        *pvt_data = ipa_options->auth_ctx;
        return EOK;
    }

    ipa_auth_ctx = talloc_zero(ipa_options, struct ipa_auth_ctx);
    if (!ipa_auth_ctx) {
        return ENOMEM;
    }
    ipa_options->auth_ctx = ipa_auth_ctx;

    ret = sssm_ipa_id_init(bectx, &id_ops, (void **) &id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sssm_ipa_id_init failed.\n");
        goto done;
    }
    ipa_auth_ctx->sdap_id_ctx = id_ctx->sdap_id_ctx;

    ret = dp_copy_options(ipa_auth_ctx, ipa_options->basic,
                          IPA_OPTS_BASIC, &ipa_auth_ctx->ipa_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "dp_copy_options failed.\n");
        goto done;
    }

    krb5_auth_ctx = talloc_zero(ipa_auth_ctx, struct krb5_ctx);
    if (!krb5_auth_ctx) {
        ret = ENOMEM;
        goto done;
    }
    krb5_auth_ctx->service = ipa_options->service->krb5_service;

    if (dp_opt_get_bool(id_ctx->ipa_options->basic,
                        IPA_SERVER_MODE) == true) {
        krb5_auth_ctx->config_type = K5C_IPA_SERVER;
    } else {
        krb5_auth_ctx->config_type = K5C_IPA_CLIENT;
    }
    ipa_options->auth_ctx->krb5_auth_ctx = krb5_auth_ctx;

    ret = ipa_get_auth_options(ipa_options, bectx->cdb, bectx->conf_path,
                               &krb5_auth_ctx->opts);
    if (ret != EOK) {
        goto done;
    }

    sdap_auth_ctx = talloc_zero(ipa_auth_ctx, struct sdap_auth_ctx);
    if (!sdap_auth_ctx) {
        ret = ENOMEM;
        goto done;
    }
    sdap_auth_ctx->be =  bectx;
    sdap_auth_ctx->service = ipa_options->service->sdap;

    if (ipa_options->id == NULL) {
        ret = EINVAL;
        goto done;
    }
    sdap_auth_ctx->opts = ipa_options->id;

    ipa_options->auth_ctx->sdap_auth_ctx = sdap_auth_ctx;

    ret = setup_tls_config(sdap_auth_ctx->opts->basic);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "setup_tls_config failed [%d][%s].\n",
                  ret, strerror(ret));
        goto done;
    }

    /* Initialize features needed by the krb5_child */
    ret = krb5_child_init(krb5_auth_ctx, bectx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not initialize krb5_child settings: [%s]\n",
               strerror(ret));
        goto done;
    }

    ret = create_ipa_preauth_indicator();
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to create preauth indicator file, special password "
              "prompting might not be available.\n");
        sss_log(SSSDBG_CRIT_FAILURE,
                "Failed to create preauth indicator file, special password "
                "prompting might not be available.\n");
    }

    *ops = &ipa_auth_ops;
    *pvt_data = ipa_auth_ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(ipa_options->auth_ctx);
    }
    return ret;
}

int sssm_ipa_chpass_init(struct be_ctx *bectx,
                         struct bet_ops **ops,
                         void **pvt_data)
{
    int ret;
    ret = sssm_ipa_auth_init(bectx, ops, pvt_data);
    *ops = &ipa_chpass_ops;
    return ret;
}

int sssm_ipa_access_init(struct be_ctx *bectx,
                         struct bet_ops **ops,
                         void **pvt_data)
{
    int ret;
    struct ipa_access_ctx *ipa_access_ctx;
    struct ipa_id_ctx *id_ctx;

    ipa_access_ctx = talloc_zero(bectx, struct ipa_access_ctx);
    if (ipa_access_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    ret = sssm_ipa_id_init(bectx, ops, (void **) &id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sssm_ipa_id_init failed.\n");
        goto done;
    }
    ipa_access_ctx->sdap_ctx = id_ctx->sdap_id_ctx;
    ipa_access_ctx->host_map = id_ctx->ipa_options->host_map;
    ipa_access_ctx->hostgroup_map = id_ctx->ipa_options->hostgroup_map;
    ipa_access_ctx->host_search_bases = id_ctx->ipa_options->host_search_bases;
    ipa_access_ctx->hbac_search_bases = id_ctx->ipa_options->hbac_search_bases;

    ret = dp_copy_options(ipa_access_ctx, ipa_options->basic,
                          IPA_OPTS_BASIC, &ipa_access_ctx->ipa_options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "dp_copy_options failed.\n");
        goto done;
    }

    /* Set up an sdap_access_ctx for checking expired/locked
     * accounts.
     */
    ipa_access_ctx->sdap_access_ctx =
            talloc_zero(ipa_access_ctx, struct sdap_access_ctx);

    ipa_access_ctx->sdap_access_ctx->id_ctx = ipa_access_ctx->sdap_ctx;
    ipa_access_ctx->sdap_access_ctx->access_rule[0] = LDAP_ACCESS_EXPIRE;
    ipa_access_ctx->sdap_access_ctx->access_rule[1] = LDAP_ACCESS_EMPTY;

    *ops = &ipa_access_ops;
    *pvt_data = ipa_access_ctx;

done:
    if (ret != EOK) {
        talloc_free(ipa_access_ctx);
    }
    return ret;
}

int sssm_ipa_selinux_init(struct be_ctx *bectx,
                          struct bet_ops **ops,
                          void **pvt_data)
{
    int ret;
    struct ipa_selinux_ctx *selinux_ctx;
    struct ipa_options *opts;

    selinux_ctx = talloc_zero(bectx, struct ipa_selinux_ctx);
    if (selinux_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    ret = sssm_ipa_id_init(bectx, ops, (void **) &selinux_ctx->id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sssm_ipa_id_init failed.\n");
        goto done;
    }

    opts = selinux_ctx->id_ctx->ipa_options;

    selinux_ctx->hbac_search_bases = opts->hbac_search_bases;
    selinux_ctx->host_search_bases = opts->host_search_bases;
    selinux_ctx->selinux_search_bases = opts->selinux_search_bases;

    *ops = &ipa_selinux_ops;
    *pvt_data = selinux_ctx;

done:
    if (ret != EOK) {
        talloc_free(selinux_ctx);
    }
    return ret;
}

#ifdef BUILD_SSH
int sssm_ipa_hostid_init(struct be_ctx *bectx,
                         struct bet_ops **ops,
                         void **pvt_data)
{
    int ret;
    struct ipa_hostid_ctx *hostid_ctx;
    struct ipa_id_ctx *id_ctx;

    hostid_ctx = talloc_zero(bectx, struct ipa_hostid_ctx);
    if (hostid_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    ret = sssm_ipa_id_init(bectx, ops, (void **) &id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sssm_ipa_id_init failed.\n");
        goto done;
    }
    hostid_ctx->sdap_id_ctx = id_ctx->sdap_id_ctx;
    hostid_ctx->host_search_bases = id_ctx->ipa_options->host_search_bases;
    hostid_ctx->ipa_opts = ipa_options;

    *ops = &ipa_hostid_ops;
    *pvt_data = hostid_ctx;

done:
    if (ret != EOK) {
        talloc_free(hostid_ctx);
    }
    return ret;
}
#endif

int sssm_ipa_autofs_init(struct be_ctx *bectx,
                         struct bet_ops **ops,
                         void **pvt_data)
{
#ifdef BUILD_AUTOFS
    struct ipa_id_ctx *id_ctx;
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing IPA autofs handler\n");

    ret = sssm_ipa_id_init(bectx, ops, (void **) &id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sssm_ipa_id_init failed.\n");
        return ret;
    }

    return ipa_autofs_init(bectx, id_ctx, ops, pvt_data);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Autofs init handler called but SSSD is "
                                 "built without autofs support, ignoring\n");
    return EOK;
#endif
}

int sssm_ipa_subdomains_init(struct be_ctx *bectx,
                             struct bet_ops **ops,
                             void **pvt_data)
{
    int ret;
    struct ipa_id_ctx *id_ctx;

    ret = sssm_ipa_id_init(bectx, ops, (void **) &id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sssm_ipa_id_init failed.\n");
        return ret;
    }

    ret = ipa_subdom_init(bectx, id_ctx, ops, pvt_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ipa_subdom_init failed.\n");
        return ret;
    }

    return EOK;
}

int sssm_ipa_sudo_init(struct be_ctx *bectx,
                       struct bet_ops **ops,
                       void **pvt_data)
{
#ifdef BUILD_SUDO
    struct ipa_id_ctx *id_ctx;
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing IPA sudo handler\n");

    ret = sssm_ipa_id_init(bectx, ops, (void **) &id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sssm_ipa_id_init failed.\n");
        return ret;
    }

    return ipa_sudo_init(bectx, id_ctx, ops, pvt_data);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Sudo init handler called but SSSD is "
                                 "built without sudo support, ignoring\n");
    return EOK;
#endif
}
