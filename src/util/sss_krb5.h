/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009-2010 Red Hat

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
#include <talloc.h>

#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#else
#include <krb5.h>
#endif

#include "util/sss_iobuf.h"
#include "util/util.h"
#include <uuid/uuid.h>

#define KRB5_CHILD_LOG_FILE     "krb5_child"
#define LDAP_CHILD_LOG_FILE     "ldap_child"

/* MIT Kerberos has the same hardcoded warning interval of 7 days. Due to the
 * fact that using the expiration time of a Kerberos password with LDAP
 * authentication is presumably a rare case a separate config option is not
 * necessary. */
#define KERBEROS_PWEXPIRE_WARNING_TIME (7 * 24 * 60 * 60)

const char *sss_printable_keytab_name(krb5_context ctx, const char *keytab_name);

#if defined HAVE_KRB5_CC_CACHE_MATCH && defined HAVE_KRB5_CC_GET_FULL_NAME
#define HAVE_KRB5_CC_COLLECTION 1
#endif

const char * KRB5_CALLCONV sss_krb5_get_error_message (krb5_context,
                                                   krb5_error_code);

void KRB5_CALLCONV sss_krb5_free_error_message(krb5_context, const char *);

#define KRB5_DEBUG(level, errctx, krb5_error) do { \
    const char *__krb5_error_msg; \
    __krb5_error_msg = sss_krb5_get_error_message(errctx, krb5_error); \
    DEBUG(level, "%d: [%d][%s]\n", __LINE__, krb5_error, __krb5_error_msg); \
    sss_log(SSS_LOG_ERR, "%s", __krb5_error_msg); \
    sss_krb5_free_error_message(errctx, __krb5_error_msg); \
} while(0)

krb5_error_code KRB5_CALLCONV sss_krb5_get_init_creds_opt_alloc(
                                                 krb5_context context,
                                                 krb5_get_init_creds_opt **opt);

void KRB5_CALLCONV sss_krb5_get_init_creds_opt_free (krb5_context context,
                                                  krb5_get_init_creds_opt *opt);

void KRB5_CALLCONV sss_krb5_free_unparsed_name(krb5_context context, char *name);

/* `find_principal_in_keytab()` that requires access to keytab file should
 * only be used in privileged 'krb5_/ldap_child'
 */
krb5_error_code find_principal_in_keytab(krb5_context ctx,
                                         krb5_keytab keytab,
                                         const char *pattern_primary,
                                         const char *pattern_realm,
                                         krb5_principal *princ);

#ifndef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_EXPIRE_CALLBACK
typedef void
(KRB5_CALLCONV *krb5_expire_callback_func)(krb5_context context, void *data,
                                           krb5_timestamp password_expiration,
                                           krb5_timestamp account_expiration,
                                           krb5_boolean is_last_req);
#endif
krb5_error_code KRB5_CALLCONV sss_krb5_get_init_creds_opt_set_expire_callback(
                                                   krb5_context context,
                                                   krb5_get_init_creds_opt *opt,
                                                   krb5_expire_callback_func cb,
                                                   void *data);

errno_t check_fast(const char *str, bool *use_fast);

krb5_error_code KRB5_CALLCONV sss_krb5_get_init_creds_opt_set_fast_ccache_name(
                                                  krb5_context context,
                                                  krb5_get_init_creds_opt *opt,
                                                  const char *fast_ccache_name);

krb5_error_code KRB5_CALLCONV sss_krb5_get_init_creds_opt_set_fast_flags(
                                                   krb5_context context,
                                                   krb5_get_init_creds_opt *opt,
                                                   krb5_flags flags);

#if HAVE_KRB5_GET_INIT_CREDS_OPT_SET_FAST_FLAGS
#define SSS_KRB5_FAST_REQUIRED KRB5_FAST_REQUIRED
#else
#define SSS_KRB5_FAST_REQUIRED 0
#endif


#ifndef HAVE_KRB5_PARSE_NAME_FLAGS
#define KRB5_PRINCIPAL_PARSE_NO_REALM           0x1
#define KRB5_PRINCIPAL_PARSE_REQUIRE_REALM      0x2
#define KRB5_PRINCIPAL_PARSE_ENTERPRISE         0x4
#endif
krb5_error_code
sss_krb5_parse_name_flags(krb5_context context, const char *name, int flags,
                          krb5_principal *principal);

#ifndef HAVE_KRB5_UNPARSE_NAME_FLAGS
#define KRB5_PRINCIPAL_UNPARSE_SHORT 0x1
#define KRB5_PRINCIPAL_UNPARSE_NO_REALM 0x2
#define KRB5_PRINCIPAL_UNPARSE_DISPLAY 0x4
#endif
krb5_error_code
sss_krb5_unparse_name_flags(krb5_context context, krb5_const_principal principal,
                            int flags, char **name);

void sss_krb5_get_init_creds_opt_set_canonicalize(krb5_get_init_creds_opt *opts,
                                                  int canonicalize);

enum sss_krb5_cc_type {
    SSS_KRB5_TYPE_FILE,
#ifdef HAVE_KRB5_CC_COLLECTION
    SSS_KRB5_TYPE_DIR,
    SSS_KRB5_TYPE_KEYRING,
#endif /* HAVE_KRB5_CC_COLLECTION */

    SSS_KRB5_TYPE_UNKNOWN
};

/* === Compatibility routines for the Heimdal Kerberos implementation === */

void sss_krb5_princ_realm(krb5_context context, krb5_const_principal princ,
                          const char **realm, int *len);

krb5_error_code
sss_krb5_free_keytab_entry_contents(krb5_context context,
                                    krb5_keytab_entry *entry);

#ifdef HAVE_KRB5_TICKET_TIMES
typedef krb5_ticket_times sss_krb5_ticket_times;
#elif defined(HAVE_KRB5_TIMES)
typedef krb5_times sss_krb5_ticket_times;
#endif

/* Redirect libkrb5 tracing towards our DEBUG statements */
errno_t sss_child_set_krb5_tracing(krb5_context ctx);

krb5_error_code sss_krb5_find_authdata(krb5_context context,
                                       krb5_authdata *const *ticket_authdata,
                                       krb5_authdata *const *ap_req_authdata,
                                       krb5_authdatatype ad_type,
                                       krb5_authdata ***results);

krb5_error_code sss_extract_pac(krb5_context ctx,
                                krb5_ccache ccache,
                                krb5_principal server_principal,
                                krb5_principal client_principal,
                                krb5_keytab keytab,
                                uint32_t check_pac_flags,
                                krb5_authdata ***_pac_authdata);

char * sss_get_ccache_name_for_principal(TALLOC_CTX *mem_ctx,
                                         krb5_context ctx,
                                         krb5_principal principal,
                                         const char *location);

krb5_error_code sss_krb5_kt_have_content(krb5_context context,
                                         krb5_keytab keytab);

bool sss_krb5_realm_has_proxy(const char *realm);

krb5_error_code sss_krb5_marshal_princ(krb5_principal princ,
                                       struct sss_iobuf *iobuf);

krb5_error_code sss_krb5_unmarshal_princ(TALLOC_CTX *mem_ctx,
                                         struct sss_iobuf *iobuf,
                                         krb5_principal *_princ);

krb5_error_code sss_krb5_init_context(krb5_context *context);

void get_krb5_data_from_cred(struct sss_iobuf *iobuf, krb5_data *k5data);

bool sss_krb5_creds_compare(krb5_context kctx, krb5_creds *a, krb5_creds *b);
#endif /* __SSS_KRB5_H__ */
