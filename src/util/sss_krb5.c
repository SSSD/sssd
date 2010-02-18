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

