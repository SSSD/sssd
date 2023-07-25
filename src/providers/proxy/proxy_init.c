/*
    SSSD

    proxy_init.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include "config.h"

#include "util/sss_format.h"
#include "providers/proxy/proxy.h"

#define OPT_MAX_CHILDREN_DEFAULT 10

static errno_t proxy_id_conf(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             char **_libname,
                             bool *_fast_alias)
{
    TALLOC_CTX *tmp_ctx;
    char *libname;
    bool fast_alias;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = confdb_get_string(be_ctx->cdb, tmp_ctx, be_ctx->conf_path,
                            CONFDB_PROXY_LIBNAME, NULL, &libname);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read confdb [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    } else if (libname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No library name given\n");
        ret = ENOENT;
        goto done;
    }

    ret = confdb_get_bool(be_ctx->cdb, be_ctx->conf_path,
                          CONFDB_PROXY_FAST_ALIAS, false, &fast_alias);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read confdb [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    *_libname = talloc_steal(mem_ctx, libname);
    *_fast_alias = fast_alias;

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t proxy_auth_conf(TALLOC_CTX *mem_ctx,
                               struct be_ctx *be_ctx,
                               char **_pam_target)
{
    char *pam_target;
    errno_t ret;

    ret = confdb_get_string(be_ctx->cdb, mem_ctx, be_ctx->conf_path,
                            CONFDB_PROXY_PAM_TARGET, NULL, &pam_target);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read confdb [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    if (pam_target == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing option %s.\n",
              CONFDB_PROXY_PAM_TARGET);
        return EINVAL;
    }

    *_pam_target = pam_target;

    return EOK;
}

static errno_t proxy_resolver_conf(TALLOC_CTX *mem_ctx,
                                   struct be_ctx *be_ctx,
                                   char **_libname)
{
    TALLOC_CTX *tmp_ctx;
    char *libname;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = confdb_get_string(be_ctx->cdb, tmp_ctx, be_ctx->conf_path,
                            CONFDB_PROXY_RESOLVER_LIBNAME, NULL, &libname);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read confdb [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    } else if (libname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No resolver library name given\n");
        ret = ENOENT;
        goto done;
    }

    *_libname = talloc_steal(mem_ctx, libname);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t proxy_init_auth_ctx(TALLOC_CTX *mem_ctx,
                                   struct be_ctx *be_ctx,
                                   struct data_provider *provider,
                                   struct proxy_auth_ctx **_auth_ctx)
{
    struct proxy_auth_ctx *auth_ctx;
    errno_t ret;
    int hret;
    int max_children;

    auth_ctx = talloc_zero(mem_ctx, struct proxy_auth_ctx);
    if (auth_ctx == NULL) {
        return ENOMEM;
    }

    auth_ctx->be = be_ctx;
    auth_ctx->timeout_ms = SSS_CLI_SOCKET_TIMEOUT / 4;
    auth_ctx->next_id = 1;

    ret = proxy_auth_conf(auth_ctx, be_ctx, &auth_ctx->pam_target);
    if (ret != EOK) {
        goto done;
    }

    ret = proxy_client_init(dp_sbus_conn(be_ctx->provider), auth_ctx);
    if (ret != EOK) {
        goto done;
    }

    /* Set up request hash table */
    ret = confdb_get_int(be_ctx->cdb, be_ctx->conf_path,
                         CONFDB_PROXY_MAX_CHILDREN,
                         OPT_MAX_CHILDREN_DEFAULT,
                         &max_children);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to read confdb [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    if (max_children < 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Option " CONFDB_PROXY_MAX_CHILDREN " must be higher then 0\n");
        ret = EINVAL;
        goto done;
    }
    auth_ctx->max_children = max_children;

    hret = hash_create(auth_ctx->max_children * 2, &auth_ctx->request_table,
                       NULL, NULL);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not initialize request table\n");
        ret = EIO;
        goto done;
    }

    *_auth_ctx = auth_ctx;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(auth_ctx);
    }

    return ret;
}

errno_t sssm_proxy_init(TALLOC_CTX *mem_ctx,
                       struct be_ctx *be_ctx,
                       struct data_provider *provider,
                       const char *module_name,
                       void **_module_data)
{
    struct proxy_module_ctx *module_ctx;
    errno_t ret;

    module_ctx = talloc_zero(mem_ctx, struct proxy_module_ctx);
    if (module_ctx == NULL) {
        return ENOMEM;
    }

    if (dp_target_enabled(provider, module_name,
                          DPT_ACCESS, DPT_AUTH, DPT_CHPASS)) {
        /* Initialize auth_ctx since one of the access, auth or chpass is
         * set. */
        ret = proxy_init_auth_ctx(module_ctx, be_ctx, provider,
                                  &module_ctx->auth_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create auth context [%d]: %s\n",
                  ret, sss_strerror(ret));
            talloc_free(module_ctx);
            return ret;
        }
    }

    *_module_data = module_ctx;

    return EOK;
}

static errno_t proxy_load_nss_symbols(struct sss_nss_ops *ops,
                                      const char *libname)
{
    errno_t ret;
    struct sss_nss_symbols syms[] = {
        {(void*)&ops->getpwnam_r,      true,  "getpwnam_r" },
        {(void*)&ops->getpwuid_r,      true,  "getpwuid_r" },
        {(void*)&ops->setpwent,        true,  "setpwent" },
        {(void*)&ops->getpwent_r,      true,  "getpwent_r" },
        {(void*)&ops->endpwent,        true,  "endpwent" },
        {(void*)&ops->getgrnam_r,      true,  "getgrnam_r" },
        {(void*)&ops->getgrgid_r,      true,  "getgrgid_r" },
        {(void*)&ops->setgrent,        true,  "setgrent" },
        {(void*)&ops->getgrent_r,      true,  "getgrent_r" },
        {(void*)&ops->endgrent,        true,  "endgrent" },
        {(void*)&ops->initgroups_dyn,  false, "initgroups_dyn" },
        {(void*)&ops->setnetgrent,     false, "setnetgrent" },
        {(void*)&ops->getnetgrent_r,   false, "getnetgrent_r" },
        {(void*)&ops->endnetgrent,     false, "endnetgrent" },
        {(void*)&ops->getservbyname_r, false, "getservbyname_r" },
        {(void*)&ops->getservbyport_r, false, "getservbyport_r" },
        {(void*)&ops->setservent,      false, "setservent" },
        {(void*)&ops->getservent_r,    false, "getservent_r" },
        {(void*)&ops->endservent,      false, "endservent" },
    };
    size_t nsyms = sizeof(syms) / sizeof(struct sss_nss_symbols);

    ret = sss_load_nss_symbols(ops, libname, syms, nsyms);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

static errno_t proxy_load_nss_hosts_symbols(struct sss_nss_ops *ops,
                                            const char *libname)
{
    errno_t ret;
    struct sss_nss_symbols syms[] = {
        {(void*)&ops->gethostbyname_r,  true,  "gethostbyname_r"},
        {(void*)&ops->gethostbyname2_r, true,  "gethostbyname2_r"},
        {(void*)&ops->gethostbyaddr_r,  true,  "gethostbyaddr_r"},
        {(void*)&ops->sethostent,       false, "sethostent"},
        {(void*)&ops->gethostent_r,     false, "gethostent_r"},
        {(void*)&ops->endhostent,       false, "endhostent"},
    };
    size_t nsyms = sizeof(syms) / sizeof(struct sss_nss_symbols);

    ret = sss_load_nss_symbols(ops, libname, syms, nsyms);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

static errno_t proxy_load_nss_nets_symbols(struct sss_nss_ops *ops,
                                           const char *libname)
{
    errno_t ret;
    struct sss_nss_symbols syms[] = {
        {(void*)&ops->getnetbyname_r,  true,  "getnetbyname_r"},
        {(void*)&ops->getnetbyaddr_r,  true,  "getnetbyaddr_r"},
        {(void*)&ops->setnetent,       false, "setnetent"},
        {(void*)&ops->getnetent_r,     false, "getnetent_r"},
        {(void*)&ops->endnetent,       false, "endnetent"},
    };
    size_t nsyms = sizeof(syms) / sizeof(struct sss_nss_symbols);

    ret = sss_load_nss_symbols(ops, libname, syms, nsyms);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t sssm_proxy_id_init(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           void *module_data,
                           struct dp_method *dp_methods)
{
    struct proxy_module_ctx *module_ctx;
    char *libname;
    errno_t ret;

    module_ctx = talloc_get_type(module_data, struct proxy_module_ctx);
    module_ctx->id_ctx = talloc_zero(module_ctx, struct proxy_id_ctx);
    if (module_ctx->id_ctx == NULL) {
        return ENOMEM;
    }

    module_ctx->id_ctx->be = be_ctx;

    ret = proxy_id_conf(module_ctx->id_ctx, be_ctx, &libname,
                        &module_ctx->id_ctx->fast_alias);
    if (ret != EOK) {
        goto done;
    }

    ret = proxy_load_nss_symbols(&module_ctx->id_ctx->ops, libname);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to load NSS symbols [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  proxy_account_info_handler_send, proxy_account_info_handler_recv,
                  module_ctx->id_ctx, struct proxy_id_ctx, struct dp_id_data,
                  struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send, default_account_domain_recv, NULL,
                  void, struct dp_get_acct_domain_data, struct dp_reply_std);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(module_ctx->id_ctx);
    }

    return ret;
}

errno_t sssm_proxy_auth_init(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             void *module_data,
                             struct dp_method *dp_methods)
{
    struct proxy_module_ctx *module_ctx;

    module_ctx = talloc_get_type(module_data, struct proxy_module_ctx);

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  proxy_pam_handler_send, proxy_pam_handler_recv,
                  module_ctx->auth_ctx, struct proxy_auth_ctx,
                  struct pam_data, struct pam_data *);

    return EOK;
}

errno_t sssm_proxy_chpass_init(TALLOC_CTX *mem_ctx,
                               struct be_ctx *be_ctx,
                               void *module_data,
                               struct dp_method *dp_methods)
{
    return sssm_proxy_auth_init(mem_ctx, be_ctx, module_data, dp_methods);
}

errno_t sssm_proxy_access_init(TALLOC_CTX *mem_ctx,
                               struct be_ctx *be_ctx,
                               void *module_data,
                               struct dp_method *dp_methods)
{
    struct proxy_module_ctx *module_ctx;

    module_ctx = talloc_get_type(module_data, struct proxy_module_ctx);

    dp_set_method(dp_methods, DPM_ACCESS_HANDLER,
                  proxy_pam_handler_send, proxy_pam_handler_recv,
                  module_ctx->auth_ctx, struct proxy_auth_ctx,
                  struct pam_data, struct pam_data *);

    return EOK;
}

errno_t sssm_proxy_resolver_init(TALLOC_CTX *mem_ctx,
                                 struct be_ctx *be_ctx,
                                 void *module_data,
                                 struct dp_method *dp_methods)
{
    struct proxy_module_ctx *module_ctx;
    char *libname;
    errno_t ret;

    module_ctx = talloc_get_type(module_data, struct proxy_module_ctx);

    module_ctx->resolver_ctx = talloc_zero(mem_ctx, struct proxy_resolver_ctx);
    if (module_ctx->resolver_ctx == NULL) {
        return ENOMEM;
    }

    ret = proxy_resolver_conf(module_ctx->resolver_ctx, be_ctx, &libname);
    if (ret == ENOENT) {
        ret = ENOTSUP;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    ret = proxy_load_nss_hosts_symbols(&module_ctx->resolver_ctx->ops, libname);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to load NSS symbols [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = proxy_load_nss_nets_symbols(&module_ctx->resolver_ctx->ops, libname);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to load NSS symbols [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    dp_set_method(dp_methods, DPM_RESOLVER_HOSTS_HANDLER,
                  proxy_hosts_handler_send, proxy_hosts_handler_recv,
                  module_ctx->resolver_ctx, struct proxy_resolver_ctx,
                  struct dp_resolver_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_RESOLVER_IP_NETWORK_HANDLER,
                  proxy_nets_handler_send, proxy_nets_handler_recv,
                  module_ctx->resolver_ctx, struct proxy_resolver_ctx,
                  struct dp_resolver_data, struct dp_reply_std);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(module_ctx->resolver_ctx);
    }

    return ret;
}
