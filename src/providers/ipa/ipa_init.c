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

#include "providers/child_common.h"
#include "providers/ipa/ipa_common.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/ipa/ipa_auth.h"
#include "providers/ipa/ipa_access.h"
#include "providers/ipa/ipa_timerules.h"

struct ipa_options *ipa_options = NULL;

/* Id Handler */
struct bet_ops ipa_id_ops = {
    .handler = sdap_account_info_handler,
    .finalize = NULL
};

struct bet_ops ipa_auth_ops = {
    .handler = ipa_auth,
    .finalize = NULL,
};

struct bet_ops ipa_chpass_ops = {
    .handler = krb5_pam_handler,
    .finalize = NULL,
};

struct bet_ops ipa_access_ops = {
    .handler = ipa_access_handler,
    .finalize = NULL
};

int common_ipa_init(struct be_ctx *bectx)
{
    const char *ipa_servers;
    const char *ipa_domain;
    int ret;

    ret = ipa_get_options(bectx, bectx->cdb,
                          bectx->conf_path,
                          bectx->domain, &ipa_options);
    if (ret != EOK) {
        return ret;
    }

    ipa_servers = dp_opt_get_string(ipa_options->basic, IPA_SERVER);
    if (!ipa_servers) {
        DEBUG(0, ("Missing ipa_server option!\n"));
        return EINVAL;
    }

    ipa_domain = dp_opt_get_string(ipa_options->basic, IPA_DOMAIN);
    if (!ipa_domain) {
        DEBUG(0, ("Missing ipa_domain option!\n"));
        return EINVAL;
    }

    ret = ipa_service_init(ipa_options, bectx, ipa_servers, ipa_domain,
                           &ipa_options->service);
    if (ret != EOK) {
        DEBUG(0, ("Failed to init IPA failover service!\n"));
        return ret;
    }

    return EOK;
}

int sssm_ipa_init(struct be_ctx *bectx,
                  struct bet_ops **ops,
                  void **pvt_data)
{
    struct sdap_id_ctx *ctx;
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

    ctx = talloc_zero(ipa_options, struct sdap_id_ctx);
    if (!ctx) {
        return ENOMEM;
    }
    ctx->be = bectx;
    ctx->service = ipa_options->service->sdap;
    ipa_options->id_ctx = ctx;

    ret = ipa_get_id_options(ipa_options, bectx->cdb,
                             bectx->conf_path,
                             &ctx->opts);
    if (ret != EOK) {
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

    *ops = &ipa_id_ops;
    *pvt_data = ctx;
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
    struct krb5_ctx *ctx;
    struct tevent_signal *sige;
    FILE *debug_filep;
    unsigned v;
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

    ctx = talloc_zero(bectx, struct krb5_ctx);
    if (!ctx) {
        return ENOMEM;
    }
    ctx->service = ipa_options->service->krb5_service;
    ipa_options->auth_ctx = ctx;

    ret = ipa_get_auth_options(ipa_options, bectx->cdb,
                               bectx->conf_path,
                               &ctx->opts);
    if (ret != EOK) {
        goto done;
    }

    ret = check_and_export_options(ctx->opts, bectx->domain);
    if (ret != EOK) {
        DEBUG(1, ("check_and_export_opts failed.\n"));
        goto done;
    }

    sige = tevent_add_signal(bectx->ev, ctx, SIGCHLD, SA_SIGINFO,
                             child_sig_handler, NULL);
    if (sige == NULL) {
        DEBUG(1, ("tevent_add_signal failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    if (debug_to_file != 0) {
        ret = open_debug_file_ex("krb5_child", &debug_filep);
        if (ret != EOK) {
            DEBUG(0, ("Error setting up logging (%d) [%s]\n",
                    ret, strerror(ret)));
            goto done;
        }

        ctx->child_debug_fd = fileno(debug_filep);
        if (ctx->child_debug_fd == -1) {
            DEBUG(0, ("fileno failed [%d][%s]\n", errno, strerror(errno)));
            ret = errno;
            goto done;
        }

        v = fcntl(ctx->child_debug_fd, F_GETFD, 0);
        fcntl(ctx->child_debug_fd, F_SETFD, v & ~FD_CLOEXEC);
    }

    *ops = &ipa_auth_ops;
    *pvt_data = ctx;
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

    ipa_access_ctx = talloc_zero(bectx, struct ipa_access_ctx);
    if (ipa_access_ctx == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    ret = sssm_ipa_init(bectx, ops, (void **) &ipa_access_ctx->sdap_ctx);
    if (ret != EOK) {
        DEBUG(1, ("sssm_ipa_init failed.\n"));
        goto done;
    }

    ret = dp_copy_options(ipa_access_ctx, ipa_options->basic,
                          IPA_OPTS_BASIC, &ipa_access_ctx->ipa_options);
    if (ret != EOK) {
        DEBUG(1, ("dp_copy_options failed.\n"));
        goto done;
    }

    ret = init_time_rules_parser(ipa_access_ctx, &ipa_access_ctx->tr_ctx);
    if (ret != EOK) {
        DEBUG(1, ("init_time_rules_parser failed.\n"));
        goto done;
    }

    *ops = &ipa_access_ops;
    *pvt_data = ipa_access_ctx;

done:
    if (ret != EOK) {
        talloc_free(ipa_access_ctx);
    }
    return ret;
}
