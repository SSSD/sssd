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
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_init_shared.h"
#include "providers/data_provider.h"

static errno_t krb5_init_kpasswd(struct krb5_ctx *ctx,
                                 struct be_ctx *be_ctx)
{
    const char *realm;
    const char *primary_servers;
    const char *backup_servers;
    const char *kdc_servers;
    bool use_kdcinfo;
    size_t n_lookahead_primary;
    size_t n_lookahead_backup;
    errno_t ret;

    realm = dp_opt_get_string(ctx->opts, KRB5_REALM);
    if (realm == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Missing krb5_realm option!\n");
        return EINVAL;
    }

    kdc_servers = dp_opt_get_string(ctx->opts, KRB5_KDC);
    primary_servers = dp_opt_get_string(ctx->opts, KRB5_KPASSWD);
    backup_servers = dp_opt_get_string(ctx->opts, KRB5_BACKUP_KPASSWD);
    use_kdcinfo = dp_opt_get_bool(ctx->opts, KRB5_USE_KDCINFO);
    sss_krb5_parse_lookahead(dp_opt_get_string(ctx->opts, KRB5_KDCINFO_LOOKAHEAD),
                             &n_lookahead_primary, &n_lookahead_backup);


    if (primary_servers == NULL && backup_servers != NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "kpasswd server wasn't specified but "
              "backup_servers kpasswd given. Using it as primary_servers\n");
        primary_servers = backup_servers;
        backup_servers = NULL;
    }

    if (primary_servers == NULL && kdc_servers != NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Missing krb5_kpasswd option and KDC set "
              "explicitly, will use KDC for password change operations!\n");
        ctx->kpasswd_service = NULL;
    } else {
        ret = krb5_service_init(ctx, be_ctx, SSS_KRB5KPASSWD_FO_SRV,
                                primary_servers, backup_servers, realm,
                                use_kdcinfo,
                                n_lookahead_primary,
                                n_lookahead_backup,
                                &ctx->kpasswd_service);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to init KRB5KPASSWD failover service!\n");
            return ret;
        }
    }

    return EOK;
}

static errno_t krb5_init_kdc(struct krb5_ctx *ctx, struct be_ctx *be_ctx)
{
    const char *primary_servers;
    const char *backup_servers;
    const char *realm;
    bool use_kdcinfo;
    size_t n_lookahead_primary;
    size_t n_lookahead_backup;
    errno_t ret;

    realm = dp_opt_get_string(ctx->opts, KRB5_REALM);
    if (realm == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Missing krb5_realm option!\n");
        return EINVAL;
    }

    primary_servers = dp_opt_get_string(ctx->opts, KRB5_KDC);
    backup_servers = dp_opt_get_string(ctx->opts, KRB5_BACKUP_KDC);

    use_kdcinfo = dp_opt_get_bool(ctx->opts, KRB5_USE_KDCINFO);
    sss_krb5_parse_lookahead(dp_opt_get_string(ctx->opts, KRB5_KDCINFO_LOOKAHEAD),
                             &n_lookahead_primary, &n_lookahead_backup);

    ret = krb5_service_init(ctx, be_ctx, SSS_KRB5KDC_FO_SRV,
                            primary_servers, backup_servers, realm,
                            use_kdcinfo,
                            n_lookahead_primary,
                            n_lookahead_backup,
                            &ctx->service);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to init KRB5 failover service!\n");
        return ret;
    }

    return EOK;
}

errno_t sssm_krb5_init(TALLOC_CTX *mem_ctx,
                       struct be_ctx *be_ctx,
                       struct data_provider *provider,
                       const char *module_name,
                       void **_module_data)
{
    struct krb5_ctx *ctx;
    errno_t ret;

    ctx = talloc_zero(mem_ctx, struct krb5_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return ENOMEM;
    }

    ret = sss_krb5_get_options(ctx, be_ctx->cdb, be_ctx->conf_path, &ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get krb5 options [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ctx->action = INIT_PW;
    ctx->config_type = K5C_GENERIC;

    ret = krb5_init_kdc(ctx, be_ctx);
    if (ret != EOK) {
        goto done;
    }

    ret = krb5_init_kpasswd(ctx, be_ctx);
    if (ret != EOK) {
        goto done;
    }

    ret = krb5_child_init(ctx, be_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not initialize krb5_child settings "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_regexp_new(ctx, ILLEGAL_PATH_PATTERN, 0, &(ctx->illegal_path_re));
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }

    ret = be_fo_set_dns_srv_lookup_plugin(be_ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set SRV lookup plugin "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    *_module_data = ctx;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }

    return ret;
}

errno_t sssm_krb5_auth_init(TALLOC_CTX *mem_ctx,
                            struct be_ctx *be_ctx,
                            void *module_data,
                            struct dp_method *dp_methods)
{
    struct krb5_ctx *ctx;

    ctx = talloc_get_type(module_data, struct krb5_ctx);
    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  krb5_pam_handler_send, krb5_pam_handler_recv, ctx,
                  struct krb5_ctx, struct pam_data, struct pam_data *);

    return EOK;
}

errno_t sssm_krb5_chpass_init(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx,
                              void *module_data,
                              struct dp_method *dp_methods)
{
    return sssm_krb5_auth_init(mem_ctx, be_ctx, module_data, dp_methods);
}

errno_t sssm_krb5_access_init(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx,
                              void *module_data,
                              struct dp_method *dp_methods)
{
    struct krb5_ctx *ctx;

    ctx = talloc_get_type(module_data, struct krb5_ctx);
    dp_set_method(dp_methods, DPM_ACCESS_HANDLER,
                  krb5_pam_handler_send, krb5_pam_handler_recv, ctx,
                  struct krb5_ctx, struct pam_data, struct pam_data *);

    return EOK;
}
