/*
    SSSD

    Kerberos 5 Backend Module

    Authors:
        Sumit Bose <sbose@redhat.com>

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
#include <fcntl.h>
#include <sys/stat.h>
#include "providers/child_common.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_common.h"

struct krb5_options {
    struct dp_option *opts;
    struct krb5_ctx *auth_ctx;
};

struct krb5_options *krb5_options = NULL;

struct bet_ops krb5_auth_ops = {
    .handler = krb5_pam_handler,
    .finalize = NULL,
};

int sssm_krb5_auth_init(struct be_ctx *bectx,
                        struct bet_ops **ops,
                        void **pvt_auth_data)
{
    struct krb5_ctx *ctx = NULL;
    int ret;
    unsigned v;
    FILE *debug_filep;
    const char *krb5_servers;
    const char *krb5_kpasswd_servers;
    const char *krb5_realm;
    const char *errstr;
    int errval;
    int errpos;

    if (krb5_options == NULL) {
        krb5_options = talloc_zero(bectx, struct krb5_options);
        if (krb5_options == NULL) {
            DEBUG(1, ("talloc_zero failed.\n"));
            return ENOMEM;
        }
        ret = krb5_get_options(krb5_options, bectx->cdb, bectx->conf_path,
                               &krb5_options->opts);
        if (ret != EOK) {
            DEBUG(1, ("krb5_get_options failed.\n"));
            return ret;
        }
    }

    if (krb5_options->auth_ctx != NULL) {
        *ops = &krb5_auth_ops;
        *pvt_auth_data = krb5_options->auth_ctx;
        return EOK;
    }

    ctx = talloc_zero(bectx, struct krb5_ctx);
    if (!ctx) {
        DEBUG(1, ("talloc failed.\n"));
        return ENOMEM;
    }

    ctx->action = INIT_PW;
    ctx->opts = krb5_options->opts;

    krb5_servers = dp_opt_get_string(ctx->opts, KRB5_KDC);
    if (krb5_servers == NULL) {
        DEBUG(1, ("Missing krb5_kdcip option, using service discovery!\n"));
    }

    krb5_realm = dp_opt_get_string(ctx->opts, KRB5_REALM);
    if (krb5_realm == NULL) {
        DEBUG(0, ("Missing krb5_realm option!\n"));
        return EINVAL;
    }

    ret = krb5_service_init(ctx, bectx, SSS_KRB5KDC_FO_SRV, krb5_servers,
                            krb5_realm, &ctx->service);
    if (ret != EOK) {
        DEBUG(0, ("Failed to init KRB5 failover service!\n"));
        return ret;
    }

    krb5_kpasswd_servers = dp_opt_get_string(ctx->opts, KRB5_KPASSWD);
    if (krb5_kpasswd_servers == NULL && krb5_servers != NULL) {
        DEBUG(0, ("Missing krb5_kpasswd option and KDC set explicitly, "
                  "will use KDC for pasword change operations!\n"));
        ctx->kpasswd_service = NULL;
    } else {
        ret = krb5_service_init(ctx, bectx, SSS_KRB5KPASSWD_FO_SRV,
                                krb5_kpasswd_servers, krb5_realm,
                                &ctx->kpasswd_service);
        if (ret != EOK) {
            DEBUG(0, ("Failed to init KRB5KPASSWD failover service!\n"));
            return ret;
        }
    }

    if (dp_opt_get_bool(ctx->opts, KRB5_STORE_PASSWORD_IF_OFFLINE)) {
        ret = init_delayed_online_authentication(ctx, bectx, bectx->ev);
        if (ret != EOK) {
            DEBUG(1, ("init_delayed_online_authentication failed.\n"));
            goto fail;
        }
    }

    ret = check_and_export_options(ctx->opts, bectx->domain);
    if (ret != EOK) {
        DEBUG(1, ("check_and_export_options failed.\n"));
        goto fail;
    }

    ret = krb5_install_sigterm_handler(bectx->ev, ctx);
    if (ret != EOK) {
        DEBUG(1, ("krb5_install_sigterm_handler failed.\n"));
        goto fail;
    }

    ret = krb5_install_offline_callback(bectx, ctx);
    if (ret != EOK) {
        DEBUG(1, ("krb5_install_offline_callback failed.\n"));
        goto fail;
    }

    if (debug_to_file != 0) {
        ret = open_debug_file_ex("krb5_child", &debug_filep);
        if (ret != EOK) {
            DEBUG(0, ("Error setting up logging (%d) [%s]\n",
                    ret, strerror(ret)));
            goto fail;
        }

        ctx->child_debug_fd = fileno(debug_filep);
        if (ctx->child_debug_fd == -1) {
            DEBUG(0, ("fileno failed [%d][%s]\n", errno, strerror(errno)));
            ret = errno;
            goto fail;
        }

        v = fcntl(ctx->child_debug_fd, F_GETFD, 0);
        fcntl(ctx->child_debug_fd, F_SETFD, v & ~FD_CLOEXEC);
    }

    ctx->illegal_path_re = pcre_compile2(ILLEGAL_PATH_PATTERN, 0,
                                         &errval, &errstr, &errpos, NULL);
    if (ctx->illegal_path_re == NULL) {
        DEBUG(1, ("Invalid Regular Expression pattern at position %d. "
                  "(Error: %d [%s])\n", errpos, errval, errstr));
        ret = EFAULT;
        goto fail;
    }

    *ops = &krb5_auth_ops;
    *pvt_auth_data = ctx;
    return EOK;

fail:
    talloc_free(ctx);
    return ret;
}

int sssm_krb5_chpass_init(struct be_ctx *bectx,
                          struct bet_ops **ops,
                          void **pvt_auth_data)
{
    return sssm_krb5_auth_init(bectx, ops, pvt_auth_data);
}
