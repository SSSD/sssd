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

struct dp_option default_krb5_opts[] = {
    { "krb5_kdcip", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_ccachedir", DP_OPT_STRING, { "/tmp" }, NULL_STRING },
    { "krb5_ccname_template", DP_OPT_STRING, { "FILE:%d/krb5cc_%U_XXXXXX" }, NULL_STRING},
    { "krb5_changepw_principal", DP_OPT_STRING, { "kadmin/changepw" }, NULL_STRING },
    { "krb5_auth_timeout", DP_OPT_NUMBER, { .number = 15 }, NULL_NUMBER },
    { "krb5_keytab", DP_OPT_STRING, { "/etc/krb5.keytab" }, NULL_STRING },
    { "krb5_validate", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_kpasswd", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_store_password_if_offline", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE }
};

errno_t check_and_export_options(struct dp_option *opts,
                                 struct sss_domain_info *dom)
{
    int ret;
    char *value;
    const char *realm;
    const char *dummy;

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

    dummy = dp_opt_get_cstring(opts, KRB5_KDC);
    if (dummy == NULL) {
        DEBUG(1, ("No KDC explicitly configured, using defaults.\n"));
    }

    dummy = dp_opt_get_cstring(opts, KRB5_KPASSWD);
    if (dummy == NULL) {
        DEBUG(1, ("No kpasswd server explicitly configured, "
                  "using the KDC or defaults.\n"));
    }

    dummy = dp_opt_get_cstring(opts, KRB5_CCNAME_TMPL);
    if (dummy == NULL) {
        DEBUG(1, ("Missing credential cache name template.\n"));
        return EINVAL;
    }
    if (dummy[0] != '/' && strncmp(dummy, "FILE:", 5) != 0) {
        DEBUG(1, ("Currently only file based credential caches are supported "
                  "and krb5ccname_template must start with '/' or 'FILE:'\n"));
        return EINVAL;
    }

    dummy = dp_opt_get_cstring(opts, KRB5_CHANGEPW_PRINC);
    if (dummy == NULL) {
        DEBUG(1, ("Missing change password principal.\n"));
        return EINVAL;
    }
    if (strchr(dummy, '@') == NULL) {
        value = talloc_asprintf(opts, "%s@%s", dummy, realm);
        if (value == NULL) {
            DEBUG(7, ("talloc_asprintf failed.\n"));
            return ENOMEM;
        }
        ret = dp_opt_set_string(opts, KRB5_CHANGEPW_PRINC, value);
        if (ret != EOK) {
            DEBUG(1, ("dp_opt_set_string failed.\n"));
            return ret;
        }
        dummy = value;
    }

    ret = setenv(SSSD_KRB5_CHANGEPW_PRINCIPAL, dummy, 1);
    if (ret != EOK) {
        DEBUG(2, ("setenv %s failed, password change might fail.\n",
                  SSSD_KRB5_CHANGEPW_PRINCIPAL));
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

    fd = mkstemp(tmp_name);
    if (fd == -1) {
        DEBUG(1, ("mkstemp failed [%d][%s].\n", errno, strerror(errno)));
        ret = errno;
        goto done;
    }

    written = 0;
    while (written < server_len) {
        ret = write(fd, server+written, server_len-written);
        if (ret == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            DEBUG(1, ("write failed [%d][%s].\n", errno, strerror(errno)));
            goto done;
        }
        else {
            written += ret;
        }
    }

    if (written != server_len) {
        DEBUG(1, ("Write error, wrote [%d] bytes, expected [%d]\n",
                   written, server_len));
        goto done;
    }

    ret = fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (ret == -1) {
        DEBUG(1, ("fchmod failed [%d][%s].\n", errno, strerror(errno)));
        goto done;
    }

    ret = close(fd);
    if (ret == -1) {
        DEBUG(1, ("close failed [%d][%s].\n", errno, strerror(errno)));
        goto done;
    }

    ret = rename(tmp_name, krb5info_name);
    if (ret == -1) {
        DEBUG(1, ("rename failed [%d][%s].\n", errno, strerror(errno)));
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void krb5_resolve_callback(void *private_data, struct fo_server *server)
{
    struct krb5_service *krb5_service;
    struct hostent *srvaddr;
    char *address;
    int ret;

    krb5_service = talloc_get_type(private_data, struct krb5_service);
    if (!krb5_service) {
        DEBUG(1, ("FATAL: Bad private_data\n"));
        return;
    }

    srvaddr = fo_get_server_hostent(server);
    if (!srvaddr) {
        DEBUG(1, ("FATAL: No hostent available for server (%s)\n",
                  fo_get_server_name(server)));
        return;
    }

    address = talloc_zero_size(krb5_service, 128);
    if (address == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        return;
    }

    if (inet_ntop(srvaddr->h_addrtype, srvaddr->h_addr_list[0],
                  address, 128) == NULL) {
        DEBUG(1, ("inet_ntop failed [%d][%s].\n", errno, strerror(errno)));
        return;
    }

    address = talloc_asprintf_append(address, ":%d",
                                     fo_get_server_port(server));
    if (address == NULL) {
        DEBUG(1, ("talloc_asprintf_append failed.\n"));
        return;
    }

    talloc_zfree(krb5_service->address);
    krb5_service->address = address;

    ret = write_krb5info_file(krb5_service->realm, address,
                              krb5_service->name);
    if (ret != EOK) {
        DEBUG(2, ("write_krb5info_file failed, authentication might fail.\n"));
    }

    return;
}


int krb5_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                      const char *service_name, const char *servers,
                      const char *realm, struct krb5_service **_service)
{
    TALLOC_CTX *tmp_ctx;
    struct krb5_service *service;
    char **list = NULL;
    int ret;
    int i;
    char *port_str;
    long port;
    char *server_spec;
    char *endptr;
    struct servent *servent;

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

    if (!servers) {
        servers = BE_SRV_IDENTIFIER;
    }

    ret = split_on_separator(tmp_ctx, servers, ',', true, &list, NULL);
    if (ret != EOK) {
        DEBUG(1, ("Failed to parse server list!\n"));
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
            ret = be_fo_add_srv_server(ctx, service_name, service_name,
                                       FO_PROTO_TCP, ctx->domain->name, NULL);
            if (ret) {
                DEBUG(0, ("Failed to add server\n"));
                goto done;
            }

            DEBUG(6, ("Added service lookup\n"));
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
                    DEBUG(1, ("strtol failed on [%s]: [%d][%s].\n", port_str,
                              ret, strerror(ret)));
                    goto done;
                }
                if (*endptr != '\0') {
                    DEBUG(1, ("Found additional characters [%s] in port number "
                              "[%s].\n", endptr, port_str));
                    ret = EINVAL;
                    goto done;
                }

                if (port < 1 || port > 65535) {
                    DEBUG(1, ("Illegal port number [%d].\n", port));
                    ret = EINVAL;
                    goto done;
                }
            } else if (isalpha(*port_str)) {
                servent = getservbyname(port_str, NULL);
                if (servent == NULL) {
                    DEBUG(1, ("getservbyname cannot find service [%s].\n",
                              port_str));
                    ret = EINVAL;
                    goto done;
                }

                port = servent->s_port;
            } else {
                DEBUG(1, ("Unsupported port specifier in [%s].\n", list[i]));
                ret = EINVAL;
                goto done;
            }
        }

        ret = be_fo_add_server(ctx, service_name, server_spec, (int) port,
                               list[i]);
        if (ret && ret != EEXIST) {
            DEBUG(0, ("Failed to add server\n"));
            goto done;
        }

        DEBUG(6, ("Added Server %s\n", list[i]));
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


static errno_t remove_krb5_info_files(TALLOC_CTX *mem_ctx, const char *realm)
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
