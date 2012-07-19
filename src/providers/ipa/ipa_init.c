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
#include "providers/ipa/ipa_subdomains.h"

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
        DEBUG(0, ("Failed to init IPA failover service!\n"));
        return ret;
    }

    return EOK;
}

int sssm_ipa_id_init(struct be_ctx *bectx,
                     struct bet_ops **ops,
                     void **pvt_data)
{
    struct ipa_id_ctx *ipa_ctx;
    struct sdap_id_ctx *sdap_ctx;
    struct stat stat_buf;
    errno_t err;
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

    sdap_ctx = talloc_zero(ipa_options, struct sdap_id_ctx);
    if (!sdap_ctx) {
        return ENOMEM;
    }
    sdap_ctx->be = bectx;
    sdap_ctx->service = ipa_options->service->sdap;
    ipa_ctx->sdap_id_ctx = sdap_ctx;

    ret = ipa_get_id_options(ipa_options, bectx->cdb,
                             bectx->conf_path,
                             &sdap_ctx->opts);
    if (ret != EOK) {
        goto done;
    }

    if(dp_opt_get_bool(ipa_options->basic, IPA_DYNDNS_UPDATE)) {
        /* Perform automatic DNS updates when the
         * IP address changes.
         * Register a callback for successful LDAP
         * reconnections. This is the easiest way to
         * identify that we have gone online.
         */

        /* Ensure that nsupdate exists */
        errno = 0;
        ret = stat(NSUPDATE_PATH, &stat_buf);
        if (ret == -1) {
            err = errno;
            if (err == ENOENT) {
                DEBUG(0, ("%s does not exist. Dynamic DNS updates disabled\n",
                          NSUPDATE_PATH));
            }
            else {
                DEBUG(0, ("Could not set up dynamic DNS updates: [%d][%s]\n",
                          err, strerror(err)));
            }
        }
        else {
            /* nsupdate is available. Dynamic updates
             * are supported
             */
            ret = ipa_dyndns_init(sdap_ctx->be, ipa_options);
            if (ret != EOK) {
                DEBUG(1, ("Failure setting up automatic DNS update\n"));
                /* We will continue without DNS updating */
            }
        }
    }

    ret = setup_tls_config(sdap_ctx->opts->basic);
    if (ret != EOK) {
        DEBUG(1, ("setup_tls_config failed [%d][%s].\n",
                  ret, strerror(ret)));
        goto done;
    }

    ret = sdap_id_conn_cache_create(sdap_ctx, sdap_ctx, &sdap_ctx->conn_cache);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_id_setup_tasks(sdap_ctx);
    if (ret != EOK) {
        goto done;
    }

    ret = setup_child(sdap_ctx);
    if (ret != EOK) {
        DEBUG(1, ("setup_child failed [%d][%s].\n",
                  ret, strerror(ret)));
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
        DEBUG(1, ("sssm_ipa_id_init failed.\n"));
        goto done;
    }
    ipa_auth_ctx->sdap_id_ctx = id_ctx->sdap_id_ctx;

    ret = dp_copy_options(ipa_auth_ctx, ipa_options->basic,
                          IPA_OPTS_BASIC, &ipa_auth_ctx->ipa_options);
    if (ret != EOK) {
        DEBUG(1, ("dp_copy_options failed.\n"));
        goto done;
    }

    krb5_auth_ctx = talloc_zero(ipa_auth_ctx, struct krb5_ctx);
    if (!krb5_auth_ctx) {
        ret = ENOMEM;
        goto done;
    }
    krb5_auth_ctx->service = ipa_options->service->krb5_service;
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
    ipa_options->auth_ctx->sdap_auth_ctx = sdap_auth_ctx;

    ret = ipa_get_id_options(ipa_options, bectx->cdb, bectx->conf_path,
                             &sdap_auth_ctx->opts);
    if (ret != EOK) {
        goto done;
    }

    ret = setup_tls_config(sdap_auth_ctx->opts->basic);
    if (ret != EOK) {
        DEBUG(1, ("setup_tls_config failed [%d][%s].\n",
                  ret, strerror(ret)));
        goto done;
    }

    /* Initialize features needed by the krb5_child */
    ret = krb5_child_init(krb5_auth_ctx, bectx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Could not initialize krb5_child settings: [%s]\n",
               strerror(ret)));
        goto done;
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
        DEBUG(1, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    ret = sssm_ipa_id_init(bectx, ops, (void **) &id_ctx);
    if (ret != EOK) {
        DEBUG(1, ("sssm_ipa_id_init failed.\n"));
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
        DEBUG(1, ("dp_copy_options failed.\n"));
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    ret = sssm_ipa_id_init(bectx, ops, (void **) &selinux_ctx->id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sssm_ipa_id_init failed.\n"));
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    ret = sssm_ipa_id_init(bectx, ops, (void **) &id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sssm_ipa_id_init failed.\n"));
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

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Initializing IPA autofs handler\n"));

    ret = sssm_ipa_id_init(bectx, ops, (void **) &id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sssm_ipa_id_init failed.\n"));
        return ret;
    }

    return ipa_autofs_init(bectx, id_ctx, ops, pvt_data);
#else
    DEBUG(SSSDBG_MINOR_FAILURE, ("Autofs init handler called but SSSD is "
                                 "built without autofs support, ignoring\n"));
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("sssm_ipa_id_init failed.\n"));
        return ret;
    }

    ret = ipa_subdom_init(bectx, id_ctx, ops, pvt_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("ipa_subdom_init failed.\n"));
        return ret;
    }

    return EOK;
}
