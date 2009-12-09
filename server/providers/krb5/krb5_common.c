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
    { "krb5_validate", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE }
};

errno_t check_and_export_options(struct dp_option *opts,
                                 struct sss_domain_info *dom)
{
    int ret;
    char *value;
    const char *realm;
    const char *dummy;
    struct stat stat_buf;
    char **list;

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
        DEBUG(1, ("No KDC expicitly configured, using defaults"));
    } else {
        ret = split_on_separator(opts, dummy, ',', true, &list, NULL);
        if (ret != EOK) {
            DEBUG(1, ("Failed to parse server list!\n"));
            return ret;
        }
        ret = write_kdcinfo_file(realm, list[0]);
        if (ret != EOK) {
            DEBUG(1, ("write_kdcinfo_file failed, "
                      "using kerberos defaults from /etc/krb5.conf"));
        }
        talloc_free(list);
    }

    dummy = dp_opt_get_cstring(opts, KRB5_CCACHEDIR);
    ret = lstat(dummy, &stat_buf);
    if (ret != EOK) {
        DEBUG(1, ("lstat for [%s] failed: [%d][%s].\n", dummy, errno,
                  strerror(errno)));
        return ret;
    }
    if ( !S_ISDIR(stat_buf.st_mode) ) {
        DEBUG(1, ("Value of krb5ccache_dir [%s] is not a directory.\n", dummy));
        return EINVAL;
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
        DEBUG(1, ("Missing change password principle.\n"));
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

    ret = setenv(SSSD_KRB5_CHANGEPW_PRINCIPLE, dummy, 1);
    if (ret != EOK) {
        DEBUG(2, ("setenv %s failed, password change might fail.\n",
                  SSSD_KRB5_CHANGEPW_PRINCIPLE));
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

errno_t write_kdcinfo_file(const char *realm, const char *kdc)
{
    int ret;
    int fd = -1;
    char *tmp_name = NULL;
    char *kdcinfo_name = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    int kdc_len;

    if (realm == NULL || *realm == '\0' || kdc == NULL || *kdc == '\0') {
        DEBUG(1, ("Missing or empty realm or kdc.\n"));
        return EINVAL;
    }

    kdc_len = strlen(kdc);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    tmp_name = talloc_asprintf(tmp_ctx, PUBCONF_PATH"/.kdcinfo_dummy_XXXXXX");
    if (tmp_name == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    kdcinfo_name = talloc_asprintf(tmp_ctx, KDCINFO_TMPL, realm);
    if (kdcinfo_name == NULL) {
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

    ret = write(fd, kdc, kdc_len);
    if (ret == -1) {
        DEBUG(1, ("write failed [%d][%s].\n", errno, strerror(errno)));
        goto done;
    }
    if (ret != kdc_len) {
        DEBUG(1, ("Partial write occured, this should never happen.\n"));
        ret = EINTR;
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

    ret = rename(tmp_name, kdcinfo_name);
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

    address = talloc_asprintf(krb5_service, srvaddr->h_name);
    if (!address) {
        DEBUG(1, ("Failed to copy address ...\n"));
        return;
    }

    talloc_zfree(krb5_service->address);
    krb5_service->address = address;

    ret = write_kdcinfo_file(krb5_service->realm, address);
    if (ret != EOK) {
        DEBUG(2, ("write_kdcinfo_file failed, authentication might fail.\n"));
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

    ret = split_on_separator(tmp_ctx, servers, ',', true, &list, NULL);
    if (ret != EOK) {
        DEBUG(1, ("Failed to parse server list!\n"));
        goto done;
    }

    for (i = 0; list[i]; i++) {

        talloc_steal(service, list[i]);

        ret = be_fo_add_server(ctx, service_name, list[i], 0, NULL);
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

