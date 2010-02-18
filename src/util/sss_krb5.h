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

#ifndef __SSS_KRB5_H__
#define __SSS_KRB5_H__

#include "config.h"

#include <stdbool.h>

#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#else
#include <krb5.h>
#endif

const char * KRB5_CALLCONV sss_krb5_get_error_message (krb5_context,
                                                   krb5_error_code);

void KRB5_CALLCONV sss_krb5_free_error_message(krb5_context, const char *);

krb5_error_code KRB5_CALLCONV sss_krb5_get_init_creds_opt_alloc(
                                                 krb5_context context,
                                                 krb5_get_init_creds_opt **opt);

void KRB5_CALLCONV sss_krb5_get_init_creds_opt_free (krb5_context context,
                                                  krb5_get_init_creds_opt *opt);

void KRB5_CALLCONV sss_krb5_free_unparsed_name(krb5_context context, char *name);

krb5_error_code check_for_valid_tgt(const char *ccname, const char *realm,
                                    const char *client_princ_str, bool *result);
#endif /* __SSS_KRB5_H__ */
