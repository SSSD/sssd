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

#include "config.h"

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
