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

#include "providers/dp_backend.h"
#include "providers/krb5/krb5_common.h"

struct dp_option default_krb5_opts[] = {
    { "krb5_kdcip", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_ccachedir", DP_OPT_STRING, { "/tmp" }, NULL_STRING },
    { "krb5_ccname_template", DP_OPT_STRING, { "FILE:%d/krb5cc_%U_XXXXXX" }, NULL_STRING},
    { "krb5_changepw_principle", DP_OPT_STRING, { "kadmin/changepw" }, NULL_STRING },
    { "krb5_auth_timeout", DP_OPT_NUMBER, { .number = 15 }, NULL_NUMBER },
};

errno_t check_and_export_options(struct dp_option *opts,
                                 struct sss_domain_info *dom)
{
    int ret;
    char *value;
    const char *realm;
    const char *dummy;
    struct stat stat_buf;

    dummy = dp_opt_get_cstring(opts, KRB5_KDC);
    if (dummy == NULL) {
        DEBUG(1, ("No KDC configured, "
                  "using kerberos defaults from /etc/krb5.conf"));
    } else {
        ret = setenv(SSSD_KRB5_KDC, dummy, 1);
        if (ret != EOK) {
            DEBUG(2, ("setenv %s failed, authentication might fail.\n",
                      SSSD_KRB5_KDC));
        }
    }

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
