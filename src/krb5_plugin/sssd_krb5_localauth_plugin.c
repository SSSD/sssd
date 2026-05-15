/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include <nss.h>
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include <krb5/localauth_plugin.h>

enum nss_status _nss_sss_getpwnam_r(const char *name, struct passwd *result,
                                    char *buffer, size_t buflen, int *errnop);

#define DEFAULT_BUFSIZE 4096

static krb5_error_code sss_userok(krb5_context context,
                                  krb5_localauth_moddata data,
                                  krb5_const_principal aname,
                                  const char *lname)
{
    krb5_error_code kerr;
    char *princ_str;
    struct passwd pwd = { 0 };
    char *buffer = NULL;
    size_t buflen;
    enum nss_status nss_status;
    int nss_errno;
    uid_t princ_uid;
    int ret;
    struct passwd *result = NULL;

    kerr = krb5_unparse_name(context, aname, &princ_str);
    if (kerr != 0) {
        ret = kerr;
        goto done;
    }

    if (strcasecmp(princ_str, lname) == 0) {
        ret = 0;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = malloc(buflen);
    if (buffer == NULL) {
        ret = ENOMEM;
        goto done;
    }

    nss_status = _nss_sss_getpwnam_r(princ_str, &pwd, buffer, buflen,
                                     &nss_errno);
    if (nss_status != NSS_STATUS_SUCCESS) {
        if (nss_status == NSS_STATUS_NOTFOUND) {
            ret = KRB5_PLUGIN_NO_HANDLE;
        } else {
            ret = EIO;
        }
        goto done;
    }

    princ_uid = pwd.pw_uid;

    ret = getpwnam_r(lname, &pwd, buffer, buflen, &result);
    if (ret != 0 || result == NULL) {
        if (result == NULL) {
            ret = KRB5_PLUGIN_NO_HANDLE;
        } else {
            ret = EIO;
        }
        goto done;
    }

    if (princ_uid != pwd.pw_uid) {
        ret = EPERM;
        goto done;
    }

    ret = 0;

done:
    krb5_free_unparsed_name(context, princ_str);
    free(buffer);

    if (ret != 0) {
        return KRB5_PLUGIN_NO_HANDLE;
    }

    return ret;
}

static krb5_error_code sss_an2ln(krb5_context context,
                                 krb5_localauth_moddata data,
                                 const char *type, const char *residual,
                                 krb5_const_principal aname, char **lname_out)
{
    krb5_error_code kerr;
    char *princ_str;
    struct passwd pwd = { 0 };
    char *buffer = NULL;
    size_t buflen;
    enum nss_status nss_status;
    int nss_errno;
    int ret;
    char *str;

    kerr = krb5_unparse_name(context, aname, &princ_str);
    if (kerr != 0) {
        return kerr;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = malloc(buflen);
    if (buffer == NULL) {
        ret = ENOMEM;
        goto done;
    }

    nss_status = _nss_sss_getpwnam_r(princ_str, &pwd, buffer, buflen,
                                     &nss_errno);
    if (nss_status != NSS_STATUS_SUCCESS) {
        if (nss_status == NSS_STATUS_NOTFOUND) {
            ret = KRB5_LNAME_NOTRANS;
        } else {
            ret = EIO;
        }
        goto done;
    }

    if (pwd.pw_name == NULL) {
        ret = EINVAL;
        goto done;
    }

    str = strdup(pwd.pw_name);
    if (str == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *lname_out = str;

    ret = 0;

done:
    krb5_free_unparsed_name(context, princ_str);
    free(buffer);

    return ret;
}

static void sss_freestr(krb5_context context,
                        krb5_localauth_moddata data, char *str)
{
    free(str);
}

krb5_error_code
localauth_sssd_initvt(krb5_context context, int maj_ver, int min_ver,
                       krb5_plugin_vtable vtable)
{

    if (maj_ver != 1 || min_ver != 1) {
        return KRB5_PLUGIN_VER_NOTSUPP;
    }

    krb5_localauth_vtable vt = (krb5_localauth_vtable)vtable;

    vt->init = NULL;
    vt->fini = NULL;
    vt->name = "sssd";
    vt->an2ln = sss_an2ln;
    vt->userok = sss_userok;
    vt->free_string = sss_freestr;

    return 0;
}
