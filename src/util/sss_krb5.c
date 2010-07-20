/*
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
#include <stdio.h>
#include <errno.h>
#include <talloc.h>

#include "config.h"

#include "util/util.h"
#include "util/sss_krb5.h"

int sss_krb5_verify_keytab(const char *principal,
                           const char *realm_str,
                           const char *keytab_name)
{
    krb5_context context = NULL;
    krb5_keytab keytab = NULL;
    krb5_error_code krberr;
    int ret;
    char *full_princ = NULL;
    char *realm_name = NULL;
    char *default_realm = NULL;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    krberr = krb5_init_context(&context);
    if (krberr) {
        DEBUG(2, ("Failed to init kerberos context\n"));
        ret = EFAULT;
        goto done;
    }

    if (keytab_name) {
        krberr = krb5_kt_resolve(context, keytab_name, &keytab);
    } else {
        krberr = krb5_kt_default(context, &keytab);
    }

    if (krberr) {
        DEBUG(0, ("Failed to read keytab file: %s\n",
                  sss_krb5_get_error_message(context, krberr)));
        ret = EFAULT;
        goto done;
    }

    if (!realm_str) {
        krberr = krb5_get_default_realm(context, &default_realm);
        if (krberr) {
            DEBUG(2, ("Failed to get default realm name: %s\n",
                      sss_krb5_get_error_message(context, krberr)));
            ret = EFAULT;
            goto done;
        }

        realm_name = talloc_strdup(tmp_ctx, default_realm);
        krb5_free_default_realm(context, default_realm);
        if (!realm_name) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        realm_name = talloc_strdup(tmp_ctx, realm_str);
        if (!realm_name) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (principal) {
        if (!strchr(principal, '@')) {
            full_princ = talloc_asprintf(tmp_ctx, "%s@%s",
                                         principal, realm_name);
        } else {
            full_princ = talloc_strdup(tmp_ctx, principal);
        }
    } else {
        char hostname[512];

        ret = gethostname(hostname, 511);
        if (ret == -1) {
            ret = errno;
            goto done;
        }
        hostname[511] = '\0';

        full_princ = talloc_asprintf(tmp_ctx, "host/%s@%s",
                                     hostname, realm_name);
    }
    if (!full_princ) {
        ret = ENOMEM;
        goto done;
    }
    DEBUG(4, ("Principal name is: [%s]\n", full_princ));

    ret = sss_krb5_verify_keytab_ex(full_princ, keytab_name, context, keytab);
    if (ret) goto done;

    ret = EOK;
done:
    if (keytab) krb5_kt_close(context, keytab);
    if (context) krb5_free_context(context);
    talloc_free(tmp_ctx);
    return ret;
}

int sss_krb5_verify_keytab_ex(const char *principal, const char *keytab_name,
                              krb5_context context, krb5_keytab keytab)
{
    bool found;
    char *kt_principal;
    krb5_error_code krberr;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;

    krberr = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (krberr) {
        DEBUG(0, ("Cannot read keytab [%s].\n", keytab_name));

        sss_log(SSS_LOG_ERR, "Error reading keytab file [%s]: [%d][%s]. "
                             "Unable to create GSSAPI-encrypted LDAP connection.",
                             keytab_name, krberr,
                             sss_krb5_get_error_message(context, krberr));

        return EIO;
    }

    found = false;
    while((krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0){
        krb5_unparse_name(context, entry.principal, &kt_principal);
        if (strcmp(principal, kt_principal) == 0) {
            found = true;
        }
        free(kt_principal);
        krb5_free_keytab_entry_contents(context, &entry);

        if (found) {
            break;
        }
    }

    krberr = krb5_kt_end_seq_get(context, keytab, &cursor);
    if (krberr) {
        DEBUG(0, ("Could not close keytab.\n"));
        sss_log(SSS_LOG_ERR, "Could not close keytab file [%s].",
                             keytab_name);
        return EIO;
    }

    if (!found) {
        DEBUG(0, ("Principal [%s] not found in keytab [%s]\n",
                  principal, keytab_name ? keytab_name : "default"));
        sss_log(SSS_LOG_ERR, "Error processing keytab file [%s]: "
                             "Principal [%s] was not found. "
                             "Unable to create GSSAPI-encrypted LDAP connection.",
                             keytab_name, principal);

        return EFAULT;
    }

    return EOK;
}

const char *KRB5_CALLCONV sss_krb5_get_error_message(krb5_context ctx,
                                               krb5_error_code ec)
{
#ifdef HAVE_KRB5_GET_ERROR_MESSAGE
    return krb5_get_error_message(ctx, ec);
#else
    int ret;
    char *s = NULL;
    int size = sizeof("Kerberos error [XXXXXXXXXXXX]");

    s = malloc(sizeof(char) * (size));
    if (s == NULL) {
        return NULL;
    }

    ret = snprintf(s, size, "Kerberos error [%12d]", ec);

    if (ret < 0 || ret >= size) {
        return NULL;
    }

    return s;
#endif
}

void KRB5_CALLCONV sss_krb5_free_error_message(krb5_context ctx, const char *s)
{
#ifdef HAVE_KRB5_GET_ERROR_MESSAGE
    krb5_free_error_message(ctx, s);
#else
    free(s);
#endif

    return;
}

krb5_error_code KRB5_CALLCONV sss_krb5_get_init_creds_opt_alloc(
                                                  krb5_context context,
                                                  krb5_get_init_creds_opt **opt)
{
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
    return krb5_get_init_creds_opt_alloc(context, opt);
#else
    *opt = calloc(1, sizeof(krb5_get_init_creds_opt));
    if (*opt == NULL) {
        return ENOMEM;
    }
    krb5_get_init_creds_opt_init(*opt);

    return 0;
#endif
}

void KRB5_CALLCONV sss_krb5_get_init_creds_opt_free (krb5_context context,
                                                   krb5_get_init_creds_opt *opt)
{
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
    krb5_get_init_creds_opt_free(context, opt);
#else
    free(opt);
#endif

    return;
}

void KRB5_CALLCONV sss_krb5_free_unparsed_name(krb5_context context, char *name)
{
#ifdef HAVE_KRB5_FREE_UNPARSED_NAME
    krb5_free_unparsed_name(context, name);
#else
    if (name != NULL) {
        memset(name, 0, strlen(name));
        free(name);
    }
#endif
}


krb5_error_code check_for_valid_tgt(const char *ccname, const char *realm,
                                    const char *client_princ_str, bool *result)
{
    krb5_context context = NULL;
    krb5_ccache ccache = NULL;
    krb5_error_code krberr;
    TALLOC_CTX *tmp_ctx = NULL;
    krb5_creds mcred;
    krb5_creds cred;
    char *server_name = NULL;
    krb5_principal client_principal = NULL;
    krb5_principal server_principal = NULL;

    *result = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    krberr = krb5_init_context(&context);
    if (krberr) {
        DEBUG(1, ("Failed to init kerberos context\n"));
        goto done;
    }

    krberr = krb5_cc_resolve(context, ccname, &ccache);
    if (krberr != 0) {
        DEBUG(1, ("krb5_cc_resolve failed.\n"));
        goto done;
    }

    server_name = talloc_asprintf(tmp_ctx, "krbtgt/%s@%s", realm, realm);
    if (server_name == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        goto done;
    }

    krberr = krb5_parse_name(context, server_name, &server_principal);
    if (krberr != 0) {
        DEBUG(1, ("krb5_parse_name failed.\n"));
        goto done;
    }

    krberr = krb5_parse_name(context, client_princ_str, &client_principal);
    if (krberr != 0) {
        DEBUG(1, ("krb5_parse_name failed.\n"));
        goto done;
    }

    memset(&mcred, 0, sizeof(mcred));
    memset(&cred, 0, sizeof(mcred));
    mcred.client = client_principal;
    mcred.server = server_principal;

    krberr = krb5_cc_retrieve_cred(context, ccache, 0, &mcred, &cred);
    if (krberr != 0) {
        DEBUG(1, ("krb5_cc_retrieve_cred failed.\n"));
        krberr = 0;
        goto done;
    }

    DEBUG(7, ("TGT end time [%d].\n", cred.times.endtime));

    if (cred.times.endtime > time(NULL)) {
        DEBUG(3, ("TGT is valid.\n"));
        *result = true;
    }
    krb5_free_cred_contents(context, &cred);

    krberr = 0;

done:
    if (client_principal != NULL) {
        krb5_free_principal(context, client_principal);
    }
    if (server_principal != NULL) {
        krb5_free_principal(context, server_principal);
    }
    if (ccache != NULL) {
        krb5_cc_close(context, ccache);
    }
    if (context != NULL) krb5_free_context(context);
    talloc_free(tmp_ctx);
    return krberr;
}

