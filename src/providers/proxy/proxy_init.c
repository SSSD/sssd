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

#define NSS_FN_NAME "_nss_%s_%s"

#define OPT_MAX_CHILDREN_DEFAULT 10

#define ERROR_INITGR "The '%s' library does not provides the " \
                         "_nss_XXX_initgroups_dyn function!\n" \
                         "initgroups will be slow as it will require " \
                         "full groups enumeration!\n"
#define ERROR_NETGR "The '%s' library does not support netgroups.\n"
#define ERROR_SERV "The '%s' library does not support services.\n"

static void *proxy_dlsym(void *handle,
                         const char *name,
                         const char *libname)
{
    char *funcname;
    void *funcptr;

    funcname = talloc_asprintf(NULL, NSS_FN_NAME, libname, name);
    if (funcname == NULL) {
        return NULL;
    }

    funcptr = dlsym(handle, funcname);
    talloc_free(funcname);

    return funcptr;
}

static errno_t proxy_id_conf(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             char **_libname,
                             char **_libpath,
                             bool *_fast_alias)
{
    TALLOC_CTX *tmp_ctx;
    char *libname;
    char *libpath;
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

    libpath = talloc_asprintf(tmp_ctx, "libnss_%s.so.2", libname);
    if (libpath == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
        ret = ENOMEM;
        goto done;
    }

    *_libname = talloc_steal(mem_ctx, libname);
    *_libpath = talloc_steal(mem_ctx, libpath);
    *_fast_alias = fast_alias;

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t proxy_id_load_symbols(struct proxy_nss_ops *ops,
                                     const char *libname,
                                     void *handle)
{
    int i;
    struct {void **dest;
            const char *name;
            const char *custom_error;
            bool is_fatal;
    } symbols[] = {
        {(void**)&ops->getpwnam_r, "getpwnam_r", NULL, true},
        {(void**)&ops->getpwuid_r, "getpwuid_r", NULL, true},
        {(void**)&ops->setpwent, "setpwent", NULL, true},
        {(void**)&ops->getpwent_r, "getpwent_r", NULL, true},
        {(void**)&ops->endpwent, "endpwent", NULL, true},
        {(void**)&ops->getgrnam_r, "getgrnam_r", NULL, true},
        {(void**)&ops->getgrgid_r, "getgrgid_r", NULL, true},
        {(void**)&ops->setgrent, "setgrent", NULL, true},
        {(void**)&ops->getgrent_r, "getgrent_r", NULL, true},
        {(void**)&ops->endgrent, "endgrent", NULL, true},
        {(void**)&ops->initgroups_dyn, "initgroups_dyn", ERROR_INITGR, false},
        {(void**)&ops->setnetgrent, "setnetgrent", ERROR_NETGR, false},
        {(void**)&ops->getnetgrent_r, "getnetgrent_r", ERROR_NETGR, false},
        {(void**)&ops->endnetgrent, "endnetgrent", ERROR_NETGR, false},
        {(void**)&ops->getservbyname_r, "getservbyname_r", ERROR_SERV, false},
        {(void**)&ops->getservbyport_r, "getservbyport_r", ERROR_SERV, false},
        {(void**)&ops->setservent, "setservent", ERROR_SERV, false},
        {(void**)&ops->getservent_r, "getservent_r", ERROR_SERV, false},
        {(void**)&ops->endservent, "endservent", ERROR_SERV, false},
        {NULL, NULL, NULL, false}
    };

    for (i = 0; symbols[i].dest != NULL; i++) {
        *symbols[i].dest = proxy_dlsym(handle, symbols[i].name, libname);
        if (*symbols[i].dest == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Failed to load _nss_%s_%s, "
                  "error: %s.\n", libname, symbols[i].name, dlerror());

            if (symbols[i].custom_error != NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, symbols[i].custom_error, libname);
            }

            if (symbols[i].is_fatal) {
                return ELIBBAD;
            }
        }
    }

    return EOK;
}

static errno_t proxy_setup_sbus(TALLOC_CTX *mem_ctx,
                                struct proxy_auth_ctx *ctx,
                                struct be_ctx *be_ctx)
{
    char *sbus_address;
    errno_t ret;

    sbus_address = talloc_asprintf(mem_ctx, "unix:path=%s/%s_%s", PIPE_PATH,
                                   PROXY_CHILD_PIPE, be_ctx->domain->name);
    if (sbus_address == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed.\n");
        return ENOMEM;
    }

    ret = sbus_new_server(mem_ctx, be_ctx->ev, sbus_address, 0, be_ctx->gid,
                          false, &ctx->sbus_srv, proxy_client_init, ctx, NULL);
    talloc_free(sbus_address);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not set up sbus server.\n");
        return ret;
    }

    return EOK;
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

static errno_t proxy_init_auth_ctx(TALLOC_CTX *mem_ctx,
                                   struct be_ctx *be_ctx,
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

    ret = proxy_setup_sbus(auth_ctx, auth_ctx, be_ctx);
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
    struct proxy_auth_ctx *auth_ctx;
    errno_t ret;

    if (!dp_target_enabled(provider, module_name,
                           DPT_ACCESS, DPT_AUTH, DPT_CHPASS)) {
        return EOK;
    }

    /* Initialize auth_ctx since one of the access, auth or chpass is set. */

    ret = proxy_init_auth_ctx(mem_ctx, be_ctx, &auth_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create auth context [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    *_module_data = auth_ctx;

    return EOK;
}

errno_t sssm_proxy_id_init(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           void *module_data,
                           struct dp_method *dp_methods)
{
    struct proxy_id_ctx *ctx;
    char *libname;
    char *libpath;
    errno_t ret;

    ctx = talloc_zero(mem_ctx, struct proxy_id_ctx);
    if (ctx == NULL) {
        return ENOMEM;
    }

    ctx->be = be_ctx;

    ret = proxy_id_conf(ctx, be_ctx, &libname, &libpath, &ctx->fast_alias);
    if (ret != EOK) {
        goto done;
    }

    ctx->handle = dlopen(libpath, RTLD_NOW);
    if (ctx->handle == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to load %s module, "
              "error: %s\n", libpath, dlerror());
        ret = ELIBACC;
        goto done;
    }

    ret = proxy_id_load_symbols(&ctx->ops, libname, ctx->handle);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to load NSS symbols [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  proxy_account_info_handler_send, proxy_account_info_handler_recv, ctx,
                  struct proxy_id_ctx, struct dp_id_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send, default_account_domain_recv, NULL,
                  void, struct dp_get_acct_domain_data, struct dp_reply_std);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }

    return ret;
}

errno_t sssm_proxy_auth_init(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             void *module_data,
                             struct dp_method *dp_methods)
{
    struct proxy_auth_ctx *auth_ctx;

    auth_ctx = talloc_get_type(module_data, struct proxy_auth_ctx);

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  proxy_pam_handler_send, proxy_pam_handler_recv, auth_ctx,
                  struct proxy_auth_ctx, struct pam_data, struct pam_data *);

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
    struct proxy_auth_ctx *auth_ctx;

    auth_ctx = talloc_get_type(module_data, struct proxy_auth_ctx);

    dp_set_method(dp_methods, DPM_ACCESS_HANDLER,
                  proxy_pam_handler_send, proxy_pam_handler_recv, auth_ctx,
                  struct proxy_auth_ctx, struct pam_data, struct pam_data *);

    return EOK;
}
