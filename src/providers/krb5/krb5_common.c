/*
    SSSD

    Kerberos Provider Common Functions

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2008-2009 Red Hat

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
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "providers/dp_backend.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_opts.h"
#include "providers/krb5/krb5_utils.h"

errno_t check_and_export_lifetime(struct dp_option *opts, const int opt_id,
                                  const char *env_name)
{
    int ret;
    char *str;
    krb5_deltat lifetime;
    bool free_str = false;

    str = dp_opt_get_string(opts, opt_id);
    if (str == NULL || *str == '\0') {
        DEBUG(5, ("No lifetime configured.\n"));
        return EOK;
    }

    if (isdigit(str[strlen(str)-1])) {
        str = talloc_asprintf(opts, "%ss", str);
        if (str == NULL) {
            DEBUG(1, ("talloc_asprintf failed\n"));
            return ENOMEM;
        }
        free_str = true;

        ret = dp_opt_set_string(opts, opt_id, str);
        if (ret != EOK) {
            DEBUG(1, ("dp_opt_set_string failed\n"));
            goto done;
        }
    }

    ret = krb5_string_to_deltat(str, &lifetime);
    if (ret != 0) {
        DEBUG(1, ("Invalid value [%s] for a lifetime.\n", str));
        ret = EINVAL;
        goto done;
    }

    ret = setenv(env_name, str, 1);
    if (ret != EOK) {
        ret = errno;
        DEBUG(2, ("setenv [%s] failed.\n", env_name));
        goto done;
    }

    ret = EOK;

done:
    if (free_str) {
        talloc_free(str);
    }

    return ret;
}


errno_t check_and_export_options(struct dp_option *opts,
                                 struct sss_domain_info *dom,
                                 struct krb5_ctx *krb5_ctx)
{
    int ret;
    const char *realm;
    const char *dummy;
    char *use_fast_str;
    char *fast_principal;
    enum sss_krb5_cc_type cc_be;

    realm = dp_opt_get_cstring(opts, KRB5_REALM);
    if (realm == NULL) {
        ret = dp_opt_set_string(opts, KRB5_REALM, dom->name);
        if (ret != EOK) {
            DEBUG(1, ("dp_opt_set_string failed.\n"));
            return ret;
        }
        realm = dom->name;
    }

    ret = setenv(SSSD_KRB5_REALM, realm, 1);
    if (ret != EOK) {
        DEBUG(2, ("setenv %s failed, authentication might fail.\n",
                  SSSD_KRB5_REALM));
    }

    ret = check_and_export_lifetime(opts, KRB5_RENEWABLE_LIFETIME,
                                    SSSD_KRB5_RENEWABLE_LIFETIME);
    if (ret != EOK) {
        DEBUG(1, ("Failed to check value of krb5_renewable_lifetime. [%d][%s]\n",
                  ret, strerror(ret)));
        return ret;
    }

    ret = check_and_export_lifetime(opts, KRB5_LIFETIME,
                                    SSSD_KRB5_LIFETIME);
    if (ret != EOK) {
        DEBUG(1, ("Failed to check value of krb5_lifetime. [%d][%s]\n",
                  ret, strerror(ret)));
        return ret;
    }


    use_fast_str = dp_opt_get_string(opts, KRB5_USE_FAST);
    if (use_fast_str != NULL) {
        ret = check_fast(use_fast_str, &krb5_ctx->use_fast);
        if (ret != EOK) {
            DEBUG(1, ("check_fast failed.\n"));
            return ret;
        }

        if (krb5_ctx->use_fast) {
            ret = setenv(SSSD_KRB5_USE_FAST, use_fast_str, 1);
            if (ret != EOK) {
                DEBUG(2, ("setenv [%s] failed.\n", SSSD_KRB5_USE_FAST));
            } else {
                fast_principal = dp_opt_get_string(opts, KRB5_FAST_PRINCIPAL);
                if (fast_principal != NULL) {
                    ret = setenv(SSSD_KRB5_FAST_PRINCIPAL, fast_principal, 1);
                    if (ret != EOK) {
                        DEBUG(2, ("setenv [%s] failed.\n", SSSD_KRB5_FAST_PRINCIPAL));
                    }
                }
            }
        }
    }

    if (dp_opt_get_bool(opts, KRB5_CANONICALIZE)) {
        ret = setenv(SSSD_KRB5_CANONICALIZE, "true", 1);
    } else {
        ret = setenv(SSSD_KRB5_CANONICALIZE, "false", 1);
    }
    if (ret != EOK) {
        DEBUG(2, ("setenv [%s] failed.\n", SSSD_KRB5_CANONICALIZE));
    }

    dummy = dp_opt_get_cstring(opts, KRB5_KDC);
    if (dummy == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, ("No KDC explicitly configured, using defaults.\n"));
    }

    dummy = dp_opt_get_cstring(opts, KRB5_KPASSWD);
    if (dummy == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, ("No kpasswd server explicitly configured, "
                                     "using the KDC or defaults.\n"));
    }

    dummy = dp_opt_get_cstring(opts, KRB5_CCNAME_TMPL);
    if (dummy == NULL) {
        DEBUG(1, ("Missing credential cache name template.\n"));
        return EINVAL;
    }

    cc_be = sss_krb5_get_type(dummy);
    switch (cc_be) {
    case SSS_KRB5_TYPE_FILE:
        DEBUG(SSSDBG_CONF_SETTINGS, ("ccache is of type FILE\n"));
        krb5_ctx->cc_be = &file_cc;
        if (dummy[0] != '/') {
            /* FILE:/path/to/cc */
            break;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, ("The ccname template was "
              "missing an explicit type, but is an absolute "
              "path specifier. Assuming FILE:\n"));

        dummy = talloc_asprintf(opts, "FILE:%s", dummy);
        if (!dummy) return ENOMEM;

        ret = dp_opt_set_string(opts, KRB5_CCNAME_TMPL, dummy);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("dp_opt_set_string failed.\n"));
            return ret;
        }
        break;

#ifdef HAVE_KRB5_DIRCACHE
    case SSS_KRB5_TYPE_DIR:
        DEBUG(SSSDBG_CONF_SETTINGS, ("ccache is of type DIR\n"));
        krb5_ctx->cc_be = &dir_cc;
        break;
#endif

    default:
        DEBUG(SSSDBG_OP_FAILURE, ("Unknown ccname database\n"));
        return EINVAL;
        break;
    }

    return EOK;
}

errno_t krb5_try_kdcip(struct confdb_ctx *cdb, const char *conf_path,
                       struct dp_option *opts, int opt_id)
{
    char *krb5_servers = NULL;
    errno_t ret;

    krb5_servers = dp_opt_get_string(opts, opt_id);
    if (krb5_servers == NULL) {
        DEBUG(4, ("No KDC found in configuration, trying legacy option\n"));
        ret = confdb_get_string(cdb, NULL, conf_path,
                                "krb5_kdcip", NULL, &krb5_servers);
        if (ret != EOK) {
            DEBUG(1, ("confdb_get_string failed.\n"));
            return ret;
        }

        if (krb5_servers != NULL)
        {
            ret = dp_opt_set_string(opts, opt_id, krb5_servers);
            if (ret != EOK) {
                DEBUG(1, ("dp_opt_set_string failed.\n"));
                talloc_free(krb5_servers);
                return ret;
            }

            DEBUG(SSSDBG_CONF_SETTINGS,
                  ("Set krb5 server [%s] based on legacy krb5_kdcip option\n",
                   krb5_servers));
            DEBUG(SSSDBG_FATAL_FAILURE,
                  ("Your configuration uses the deprecated option "
                   "'krb5_kdcip' to specify the KDC. Please change the "
                   "configuration to use the 'krb5_server' option "
                   "instead.\n"));
            talloc_free(krb5_servers);
        }
    }

    return EOK;
}

errno_t krb5_get_options(TALLOC_CTX *memctx, struct confdb_ctx *cdb,
                         const char *conf_path, struct dp_option **_opts)
{
    int ret;
    struct dp_option *opts;

    opts = talloc_zero(memctx, struct dp_option);
    if (opts == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    ret = dp_get_options(opts, cdb, conf_path, default_krb5_opts,
                         KRB5_OPTS, &opts);
    if (ret != EOK) {
        DEBUG(1, ("dp_get_options failed.\n"));
        goto done;
    }

    /* If there is no KDC, try the deprecated krb5_kdcip option, too */
    /* FIXME - this can be removed in a future version */
    ret = krb5_try_kdcip(cdb, conf_path, opts, KRB5_KDC);
    if (ret != EOK) {
        DEBUG(1, ("sss_krb5_try_kdcip failed.\n"));
        goto done;
    }

    *_opts = opts;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(opts);
    }

    return ret;
}

errno_t write_krb5info_file(const char *realm, const char *server,
                           const char *service)
{
    int ret;
    int fd = -1;
    char *tmp_name = NULL;
    char *krb5info_name = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *name_tmpl = NULL;
    int server_len;
    ssize_t written;
    mode_t old_umask;

    if (realm == NULL || *realm == '\0' || server == NULL || *server == '\0' ||
        service == NULL || service == '\0') {
        DEBUG(1, ("Missing or empty realm, server or service.\n"));
        return EINVAL;
    }

    if (strcmp(service, SSS_KRB5KDC_FO_SRV) == 0) {
        name_tmpl = KDCINFO_TMPL;
    } else if (strcmp(service, SSS_KRB5KPASSWD_FO_SRV) == 0) {
        name_tmpl = KPASSWDINFO_TMPL;
    } else {
        DEBUG(1, ("Unsupported service [%s]\n.", service));
        return EINVAL;
    }

    server_len = strlen(server);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    tmp_name = talloc_asprintf(tmp_ctx, PUBCONF_PATH"/.krb5info_dummy_XXXXXX");
    if (tmp_name == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    krb5info_name = talloc_asprintf(tmp_ctx, name_tmpl, realm);
    if (krb5info_name == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    old_umask = umask(077);
    fd = mkstemp(tmp_name);
    umask(old_umask);
    if (fd == -1) {
        ret = errno;
        DEBUG(1, ("mkstemp failed [%d][%s].\n", ret, strerror(ret)));
        goto done;
    }

    errno = 0;
    written = sss_atomic_write_s(fd, discard_const(server), server_len);
    if (written == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("write failed [%d][%s].\n", ret, strerror(ret)));
        goto done;
    }

    if (written != server_len) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Write error, wrote [%d] bytes, expected [%d]\n",
               written, server_len));
        ret = EIO;
        goto done;
    }

    ret = fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (ret == -1) {
        ret = errno;
        DEBUG(1, ("fchmod failed [%d][%s].\n", ret, strerror(ret)));
        goto done;
    }

    ret = close(fd);
    if (ret == -1) {
        ret = errno;
        DEBUG(1, ("close failed [%d][%s].\n", ret, strerror(ret)));
        goto done;
    }

    ret = rename(tmp_name, krb5info_name);
    if (ret == -1) {
        ret = errno;
        DEBUG(1, ("rename failed [%d][%s].\n", ret, strerror(ret)));
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void krb5_resolve_callback(void *private_data, struct fo_server *server)
{
    struct krb5_service *krb5_service;
    struct resolv_hostent *srvaddr;
    char *address;
    char *safe_address;
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed\n"));
        return;
    }

    krb5_service = talloc_get_type(private_data, struct krb5_service);
    if (!krb5_service) {
        DEBUG(1, ("FATAL: Bad private_data\n"));
        talloc_free(tmp_ctx);
        return;
    }

    srvaddr = fo_get_server_hostent(server);
    if (!srvaddr) {
        DEBUG(1, ("FATAL: No hostent available for server (%s)\n",
                  fo_get_server_str_name(server)));
        talloc_free(tmp_ctx);
        return;
    }

    address = resolv_get_string_address(tmp_ctx, srvaddr);
    if (address == NULL) {
        DEBUG(1, ("resolv_get_string_address failed.\n"));
        talloc_free(tmp_ctx);
        return;
    }

    safe_address = sss_escape_ip_address(tmp_ctx,
                                         srvaddr->family,
                                         address);
    if (safe_address == NULL) {
        DEBUG(1, ("sss_escape_ip_address failed.\n"));
        talloc_free(tmp_ctx);
        return;
    }

    safe_address = talloc_asprintf_append(safe_address, ":%d",
                                          fo_get_server_port(server));
    if (safe_address == NULL) {
        DEBUG(1, ("talloc_asprintf_append failed.\n"));
        talloc_free(tmp_ctx);
        return;
    }

    ret = write_krb5info_file(krb5_service->realm, safe_address,
                              krb5_service->name);
    if (ret != EOK) {
        DEBUG(2, ("write_krb5info_file failed, authentication might fail.\n"));
    }

    talloc_free(tmp_ctx);
    return;
}

errno_t krb5_servers_init(struct be_ctx *ctx,
                          struct krb5_service *service,
                          const char *service_name,
                          const char *servers,
                          bool primary)
{
    TALLOC_CTX *tmp_ctx;
    char **list = NULL;
    errno_t ret;
    int i;
    char *port_str;
    long port;
    char *server_spec;
    char *endptr;
    struct servent *servent;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = split_on_separator(tmp_ctx, servers, ',', true, &list, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to parse server list!\n"));
        goto done;
    }

    for (i = 0; list[i]; i++) {

        talloc_steal(service, list[i]);
        server_spec = talloc_strdup(service, list[i]);
        if (!server_spec) {
            ret = ENOMEM;
            goto done;
        }

        if (be_fo_is_srv_identifier(server_spec)) {
            ret = be_fo_add_srv_server(ctx, service_name, service_name, NULL,
                                       BE_FO_PROTO_UDP, true, NULL);
            if (ret) {
                DEBUG(SSSDBG_FATAL_FAILURE, ("Failed to add server\n"));
                goto done;
            }

            DEBUG(SSSDBG_TRACE_FUNC, ("Added service lookup\n"));
            continue;
        }

        port_str = strrchr(server_spec, ':');
        if (port_str == NULL) {
            port = 0;
        } else {
            *port_str = '\0';
            ++port_str;
            if (isdigit(*port_str)) {
                errno = 0;
                port = strtol(port_str, &endptr, 10);
                if (errno != 0) {
                    ret = errno;
                    DEBUG(SSSDBG_CRIT_FAILURE, ("strtol failed on [%s]: [%d][%s].\n", port_str,
                              ret, strerror(ret)));
                    goto done;
                }
                if (*endptr != '\0') {
                    DEBUG(SSSDBG_CRIT_FAILURE, ("Found additional characters [%s] in port number "
                              "[%s].\n", endptr, port_str));
                    ret = EINVAL;
                    goto done;
                }

                if (port < 1 || port > 65535) {
                    DEBUG(SSSDBG_CRIT_FAILURE, ("Illegal port number [%d].\n", port));
                    ret = EINVAL;
                    goto done;
                }
            } else if (isalpha(*port_str)) {
                servent = getservbyname(port_str, NULL);
                if (servent == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, ("getservbyname cannot find service [%s].\n",
                              port_str));
                    ret = EINVAL;
                    goto done;
                }

                port = servent->s_port;
            } else {
                DEBUG(SSSDBG_CRIT_FAILURE, ("Unsupported port specifier in [%s].\n", list[i]));
                ret = EINVAL;
                goto done;
            }
        }

        ret = be_fo_add_server(ctx, service_name, server_spec, (int) port,
                               list[i], primary);
        if (ret && ret != EEXIST) {
            DEBUG(SSSDBG_FATAL_FAILURE, ("Failed to add server\n"));
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, ("Added Server %s\n", list[i]));
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

int krb5_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                      const char *service_name,
                      const char *primary_servers,
                      const char *backup_servers,
                      const char *realm, struct krb5_service **_service)
{
    TALLOC_CTX *tmp_ctx;
    struct krb5_service *service;
    int ret;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    service = talloc_zero(tmp_ctx, struct krb5_service);
    if (!service) {
        ret = ENOMEM;
        goto done;
    }

    ret = be_fo_add_service(ctx, service_name);
    if (ret != EOK) {
        DEBUG(1, ("Failed to create failover service!\n"));
        goto done;
    }

    service->name = talloc_strdup(service, service_name);
    if (!service->name) {
        ret = ENOMEM;
        goto done;
    }

    service->realm = talloc_strdup(service, realm);
    if (!service->realm) {
        ret = ENOMEM;
        goto done;
    }

    if (!primary_servers) {
        if (backup_servers) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  ("No primary servers defined but backup are present, "
                   "setting backup servers as primary\n"));
            primary_servers = backup_servers;
            backup_servers = NULL;
        } else {
            DEBUG(SSSDBG_TRACE_FUNC,
                  ("No primary or backup servers defined, "
                   "using service discovery\n"));
            primary_servers = BE_SRV_IDENTIFIER;
        }
    }

    ret = krb5_servers_init(ctx, service, service_name, primary_servers, true);
    if (ret != EOK) {
        goto done;
    }

    if (backup_servers) {
        ret = krb5_servers_init(ctx, service, service_name, backup_servers, false);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = be_fo_service_add_callback(memctx, ctx, service_name,
                                     krb5_resolve_callback, service);
    if (ret != EOK) {
        DEBUG(1, ("Failed to add failover callback!\n"));
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *_service = talloc_steal(memctx, service);
    }
    talloc_zfree(tmp_ctx);
    return ret;
}


errno_t remove_krb5_info_files(TALLOC_CTX *mem_ctx, const char *realm)
{
    int ret;
    errno_t err;
    char *file;

    file = talloc_asprintf(mem_ctx, KDCINFO_TMPL, realm);
    if(file == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        return ENOMEM;
    }

    errno = 0;
    ret = unlink(file);
    if (ret == -1) {
        err = errno;
        DEBUG(5, ("Could not remove [%s], [%d][%s]\n", file,
                  err, strerror(err)));
    }

    file = talloc_asprintf(mem_ctx, KPASSWDINFO_TMPL, realm);
    if(file == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        return ENOMEM;
    }

    errno = 0;
    ret = unlink(file);
    if (ret == -1) {
        err = errno;
        DEBUG(5, ("Could not remove [%s], [%d][%s]\n", file,
                  err, strerror(err)));
    }

    return EOK;
}

void remove_krb5_info_files_callback(void *pvt)
{
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct remove_info_files_ctx *ctx = talloc_get_type(pvt,
                                                  struct remove_info_files_ctx);

    ret = be_fo_run_callbacks_at_next_request(ctx->be_ctx,
                                              ctx->kdc_service_name);
    if (ret != EOK) {
        DEBUG(1, ("be_fo_run_callbacks_at_next_request failed, "
                  "krb5 info files will not be removed, because "
                  "it is unclear if they will be recreated properly.\n"));
        return;
    }
    if (ctx->kpasswd_service_name != NULL) {
        ret = be_fo_run_callbacks_at_next_request(ctx->be_ctx,
                                            ctx->kpasswd_service_name);
        if (ret != EOK) {
            DEBUG(1, ("be_fo_run_callbacks_at_next_request failed, "
                      "krb5 info files will not be removed, because "
                      "it is unclear if they will be recreated properly.\n"));
            return;
        }
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed, cannot remove krb5 info files.\n"));
        return;
    }

    ret = remove_krb5_info_files(tmp_ctx, ctx->realm);
    if (ret != EOK) {
        DEBUG(1, ("remove_krb5_info_files failed.\n"));
    }

    talloc_zfree(tmp_ctx);
}

void krb5_finalize(struct tevent_context *ev,
                   struct tevent_signal *se,
                   int signum,
                   int count,
                   void *siginfo,
                   void *private_data)
{
    char *realm = (char *)private_data;
    int ret;

    ret = remove_krb5_info_files(se, realm);
    if (ret != EOK) {
        DEBUG(1, ("remove_krb5_info_files failed.\n"));
    }

    sig_term(signum);
}

errno_t krb5_install_offline_callback(struct be_ctx *be_ctx,
                                      struct krb5_ctx *krb5_ctx)
{
    int ret;
    struct remove_info_files_ctx *ctx;
    const char *krb5_realm;

    if (krb5_ctx->service == NULL || krb5_ctx->service->name == NULL) {
        DEBUG(1, ("Missing KDC service name!\n"));
        return EINVAL;
    }

    ctx = talloc_zero(krb5_ctx, struct remove_info_files_ctx);
    if (ctx == NULL) {
        DEBUG(1, ("talloc_zfree failed.\n"));
        return ENOMEM;
    }

    krb5_realm = dp_opt_get_cstring(krb5_ctx->opts, KRB5_REALM);
    if (krb5_realm == NULL) {
        DEBUG(1, ("Missing krb5_realm option!\n"));
        ret = EINVAL;
        goto done;
    }

    ctx->realm = talloc_strdup(ctx, krb5_realm);
    if (ctx->realm == NULL) {
        DEBUG(1, ("talloc_strdup failed!\n"));
        ret = ENOMEM;
        goto done;
    }

    ctx->be_ctx = be_ctx;
    ctx->kdc_service_name = krb5_ctx->service->name;
    if (krb5_ctx->kpasswd_service == NULL) {
        ctx->kpasswd_service_name =NULL;
    } else {
        ctx->kpasswd_service_name = krb5_ctx->kpasswd_service->name;
    }

    ret = be_add_offline_cb(ctx, be_ctx, remove_krb5_info_files_callback, ctx,
                            NULL);
    if (ret != EOK) {
        DEBUG(1, ("be_add_offline_cb failed.\n"));
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(ctx);
    }

    return ret;
}

errno_t krb5_install_sigterm_handler(struct tevent_context *ev,
                                     struct krb5_ctx *krb5_ctx)
{
    const char *krb5_realm;
    char *sig_realm;
    struct tevent_signal *sige;

    BlockSignals(false, SIGTERM);

    krb5_realm = dp_opt_get_cstring(krb5_ctx->opts, KRB5_REALM);
    if (krb5_realm == NULL) {
        DEBUG(1, ("Missing krb5_realm option!\n"));
        return EINVAL;
    }

    sig_realm = talloc_strdup(krb5_ctx, krb5_realm);
    if (sig_realm == NULL) {
        DEBUG(1, ("talloc_strdup failed!\n"));
        return ENOMEM;
    }

    sige = tevent_add_signal(ev, krb5_ctx, SIGTERM, SA_SIGINFO, krb5_finalize,
                             sig_realm);
    if (sige == NULL) {
        DEBUG(1, ("tevent_add_signal failed.\n"));
        talloc_free(sig_realm);
        return ENOMEM;
    }
    talloc_steal(sige, sig_realm);

    return EOK;
}

errno_t krb5_get_simple_upn(TALLOC_CTX *mem_ctx, struct krb5_ctx *krb5_ctx,
                            const char *username, const char **_upn)
{
    const char *realm;
    char *upn;

    realm = dp_opt_get_cstring(krb5_ctx->opts, KRB5_REALM);
    if (realm == NULL) {
        DEBUG(1, ("Missing Kerberos realm.\n"));
        return ENOENT;
    }

    /* NOTE: this is a hack, works only in some environments */
    upn = talloc_asprintf(mem_ctx, "%s@%s",  username, realm);
    if (upn == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        return ENOMEM;
    }

    DEBUG(9, ("Using simple UPN [%s].\n", upn));

    *_upn = upn;
    return EOK;
}
