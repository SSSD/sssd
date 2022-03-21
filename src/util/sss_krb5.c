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
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <talloc.h>
#include <profile.h>

#include "config.h"

#include "util/sss_iobuf.h"
#include "util/util.h"
#include "util/util_errors.h"
#include "util/sss_krb5.h"

static char *
sss_krb5_get_primary(TALLOC_CTX *mem_ctx,
                     const char *pattern,
                     const char *hostname)
{
    char *primary;
    char *dot;
    char *c;
    char *shortname;

    if (strcmp(pattern, "%S$") == 0) {
        shortname = talloc_strdup(mem_ctx, hostname);
        if (!shortname) return NULL;

        dot = strchr(shortname, '.');
        if (dot) {
            *dot = '\0';
        }

        for (c=shortname; *c != '\0'; ++c) {
            *c = toupper(*c);
        }

        /* The samAccountName is recommended to be less than 20 characters.
         * This is only for users and groups. For machine accounts,
         * the real limit is caused by NetBIOS protocol.
         * NetBIOS names are limited to 16 (15 + $)
         * https://support.microsoft.com/en-us/help/163409/netbios-suffixes-16th-character-of-the-netbios-name
         */
        primary = talloc_asprintf(mem_ctx, "%.15s$", shortname);
        talloc_free(shortname);
        return primary;
    }

    return talloc_asprintf(mem_ctx, pattern, hostname);
}

const char *sss_printable_keytab_name(krb5_context ctx, const char *keytab_name)
{
    /* sss_printable_keytab_name() output is expected to be used
       for logging purposes only. Thus it is non-critical to provide
       krb5_kt_default_name() with a buffer which is potentially less then
       actual file path. 1024 is chosen to be 'large enough' to fit default
       keytab name for any sensible configuration.
       (And while it is tempting to use PATH_MAX here it would be misuse
        of this posix limit.)
    */
    static char buff[1024];

    if (keytab_name) {
        return keytab_name;
    }

    if (krb5_kt_default_name(ctx, buff, sizeof(buff)) != 0) {
        return "-default keytab-";
    }

    return buff;
}

errno_t select_principal_from_keytab(TALLOC_CTX *mem_ctx,
                                     const char *hostname,
                                     const char *desired_realm,
                                     const char *keytab_name,
                                     char **_principal,
                                     char **_primary,
                                     char **_realm)
{
    krb5_error_code kerr = 0;
    krb5_context krb_ctx = NULL;
    krb5_keytab keytab = NULL;
    krb5_principal client_princ = NULL;
    TALLOC_CTX *tmp_ctx;
    char *primary = NULL;
    char *realm = NULL;
    int i = 0;
    errno_t ret;
    char *principal_string;
    const char *realm_name;
    int realm_len;
    const char *error_message = NULL;

    /**
     * The %s conversion is passed as-is, the %S conversion is translated to
     * "short host name"
     *
     * Priority of lookup:
     * - our.hostname@REALM or host/our.hostname@REALM depending on the input
     * - SHORT.HOSTNAME$@REALM (AD domain)
     * - host/our.hostname@REALM
     * - foobar$@REALM (AD domain)
     * - host/foobar@REALM
     * - host/foo@BAR
     * - pick the first principal in the keytab
     */
    const char *primary_patterns[] = {"%s", "%S$", "host/%s", "*$", "host/*",
                                      "host/*", NULL};
    const char *realm_patterns[] =   {"%s", "%s",  "%s",      "%s", "%s",
                                      NULL,     NULL};

    DEBUG(SSSDBG_FUNC_DATA,
          "trying to select the most appropriate principal from keytab\n");
    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed\n");
        return ENOMEM;
    }

    kerr = sss_krb5_init_context(&krb_ctx);
    if (kerr) {
        error_message = "Failed to init Kerberos context";
        ret = EFAULT;
        goto done;
    }

    if (keytab_name != NULL) {
        kerr = krb5_kt_resolve(krb_ctx, keytab_name, &keytab);
    } else {
        kerr = krb5_kt_default(krb_ctx, &keytab);
    }
    if (kerr) {
        const char *krb5_err_msg = sss_krb5_get_error_message(krb_ctx, kerr);
        error_message = talloc_strdup(tmp_ctx, krb5_err_msg);
        sss_krb5_free_error_message(krb_ctx, krb5_err_msg);
        ret = EFAULT;
        goto done;
    }

    if (!desired_realm) {
        desired_realm = "*";
    }
    if (!hostname) {
        hostname = "*";
    }

    do {
        if (primary_patterns[i]) {
            primary = sss_krb5_get_primary(tmp_ctx,
                                           primary_patterns[i],
                                           hostname);
            if (primary == NULL) {
                ret = ENOMEM;
                goto done;
            }
        } else {
            primary = NULL;
        }
        if (realm_patterns[i]) {
            realm = talloc_asprintf(tmp_ctx, realm_patterns[i], desired_realm);
            if (realm == NULL) {
                ret = ENOMEM;
                goto done;
            }
        } else {
            realm = NULL;
        }

        kerr = find_principal_in_keytab(krb_ctx, keytab, primary, realm,
                                        &client_princ);
        talloc_zfree(primary);
        talloc_zfree(realm);
        if (kerr == 0) {
            break;
        }
        if (client_princ != NULL) {
            krb5_free_principal(krb_ctx, client_princ);
            client_princ = NULL;
        }
        i++;
    } while(primary_patterns[i-1] != NULL || realm_patterns[i-1] != NULL);

    if (kerr == 0) {
        if (_principal) {
            kerr = krb5_unparse_name(krb_ctx, client_princ, &principal_string);
            if (kerr) {
                error_message = "krb5_unparse_name failed (_principal)";
                ret = EINVAL;
                goto done;
            }

            *_principal = talloc_strdup(mem_ctx, principal_string);
            sss_krb5_free_unparsed_name(krb_ctx, principal_string);
            if (!*_principal) {
                ret = ENOMEM;
                goto done;
            }
            DEBUG(SSSDBG_FUNC_DATA, "Selected principal: %s\n", *_principal);
        }

        if (_primary) {
            kerr = sss_krb5_unparse_name_flags(krb_ctx, client_princ,
                                               KRB5_PRINCIPAL_UNPARSE_NO_REALM,
                                               &principal_string);
            if (kerr) {
                if (_principal) talloc_zfree(*_principal);
                error_message = "krb5_unparse_name failed (_primary)";
                ret = EINVAL;
                goto done;
            }

            *_primary = talloc_strdup(mem_ctx, principal_string);
            sss_krb5_free_unparsed_name(krb_ctx, principal_string);
            if (!*_primary) {
                if (_principal) talloc_zfree(*_principal);
                ret = ENOMEM;
                goto done;
            }
            DEBUG(SSSDBG_FUNC_DATA, "Selected primary: %s\n", *_primary);
        }

        if (_realm) {
            sss_krb5_princ_realm(krb_ctx, client_princ,
                                 &realm_name,
                                 &realm_len);
            if (realm_len == 0) {
                error_message = "sss_krb5_princ_realm failed";
                if (_principal) talloc_zfree(*_principal);
                if (_primary) talloc_zfree(*_primary);
                ret = EINVAL;
                goto done;
            }

            *_realm = talloc_asprintf(mem_ctx, "%.*s",
                                      realm_len, realm_name);
            if (!*_realm) {
                if (_principal) talloc_zfree(*_principal);
                if (_primary) talloc_zfree(*_primary);
                ret = ENOMEM;
                goto done;
            }
            DEBUG(SSSDBG_FUNC_DATA, "Selected realm: %s\n", *_realm);
        }

        ret = EOK;
    } else {
        ret = ERR_KRB5_PRINCIPAL_NOT_FOUND;
    }

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to read keytab [%s]: %s\n",
              sss_printable_keytab_name(krb_ctx, keytab_name),
              (error_message ? error_message : sss_strerror(ret)));

        sss_log(SSS_LOG_ERR, "Failed to read keytab [%s]: %s\n",
                sss_printable_keytab_name(krb_ctx, keytab_name),
                (error_message ? error_message : sss_strerror(ret)));
    }
    if (keytab) krb5_kt_close(krb_ctx, keytab);
    if (krb_ctx) krb5_free_context(krb_ctx);
    if (client_princ) krb5_free_principal(krb_ctx, client_princ);
    talloc_free(tmp_ctx);
    return ret;
}

enum matching_mode {MODE_NORMAL, MODE_PREFIX, MODE_POSTFIX};
/**
 * We only have primary and instances stored separately, we need to
 * join them to one string and compare that string.
 *
 * @param ctx Kerberos context
 * @param principal principal we want to match
 * @param pattern_primary primary part of the principal we want to
 *        perform matching against. It is possible to use * wildcard
 *        at the beginning or at the end of the string. If NULL, it
 *        will act as "*"
 * @param pattern_realm realm part of the principal we want to perform
 *        the matching against. If NULL, it will act as "*"
 */
static bool match_principal(krb5_context ctx,
                     krb5_principal principal,
                     const char *pattern_primary,
                     const char *pattern_realm)
{
    char *primary = NULL;
    char *primary_str = NULL;
    int primary_str_len = 0;
    int tmp_len;
    int len_diff;
    const char *realm_name;
    int realm_len;

    enum matching_mode mode = MODE_NORMAL;
    TALLOC_CTX *tmp_ctx;
    bool ret = false;

    sss_krb5_princ_realm(ctx, principal, &realm_name, &realm_len);
    if (realm_len == 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sss_krb5_princ_realm failed.\n");
        return false;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed\n");
        return false;
    }

    if (pattern_primary) {
        tmp_len = strlen(pattern_primary);
        if (pattern_primary[tmp_len-1] == '*') {
            mode = MODE_PREFIX;
            primary_str = talloc_strdup(tmp_ctx, pattern_primary);
            primary_str[tmp_len-1] = '\0';
            primary_str_len = tmp_len-1;
        } else if (pattern_primary[0] == '*') {
            mode = MODE_POSTFIX;
            primary_str = talloc_strdup(tmp_ctx, pattern_primary+1);
            primary_str_len = tmp_len-1;
        }

        sss_krb5_unparse_name_flags(ctx, principal, KRB5_PRINCIPAL_UNPARSE_NO_REALM,
                                    &primary);

        len_diff = strlen(primary)-primary_str_len;

        if ((mode == MODE_NORMAL &&
                strcmp(primary, pattern_primary) != 0) ||
            (mode == MODE_PREFIX &&
                strncmp(primary, primary_str, primary_str_len) != 0) ||
            (mode == MODE_POSTFIX &&
                strcmp(primary+len_diff, primary_str) != 0)) {
            goto done;
        }
    }

    if (!pattern_realm || (realm_len == strlen(pattern_realm) &&
        strncmp(realm_name, pattern_realm, realm_len) == 0)) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Principal matched to the sample (%s@%s).\n", pattern_primary,
                                                                pattern_realm);
        ret = true;
    }

done:
    free(primary);
    talloc_free(tmp_ctx);
    return ret;
}

krb5_error_code find_principal_in_keytab(krb5_context ctx,
                                         krb5_keytab keytab,
                                         const char *pattern_primary,
                                         const char *pattern_realm,
                                         krb5_principal *princ)
{
    krb5_error_code kerr;
    krb5_error_code kerr_dbg;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    bool principal_found = false;

    memset(&cursor, 0, sizeof(cursor));
    memset(&entry, 0, sizeof(entry));

    kerr = krb5_kt_start_seq_get(ctx, keytab, &cursor);
    if (kerr != 0) {
        const char *krb5_err_msg = sss_krb5_get_error_message(ctx, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_kt_start_seq_get failed: %s\n",
              krb5_err_msg);
        sss_log(SSS_LOG_ERR, "krb5_kt_start_seq_get failed: %s\n",
                krb5_err_msg);
        sss_krb5_free_error_message(ctx, krb5_err_msg);
        return kerr;
    }

    DEBUG(SSSDBG_TRACE_ALL,
          "Trying to find principal %s@%s in keytab.\n", pattern_primary, pattern_realm);
    while ((kerr = krb5_kt_next_entry(ctx, keytab, &entry, &cursor)) == 0) {
        principal_found = match_principal(ctx, entry.principal, pattern_primary, pattern_realm);
        if (principal_found) {
            break;
        }

        kerr_dbg = sss_krb5_free_keytab_entry_contents(ctx, &entry);
        if (kerr_dbg != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to free keytab entry.\n");
        }
        memset(&entry, 0, sizeof(entry));
    }

    /* Close the keytab here.  Even though we're using cursors, the file
     * handle is stored in the krb5_keytab structure, and it gets
     * overwritten by other keytab calls, creating a leak. */
    kerr_dbg = krb5_kt_end_seq_get(ctx, keytab, &cursor);
    if (kerr_dbg != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_kt_end_seq_get failed.\n");
    }

    if (principal_found) {
        kerr = krb5_copy_principal(ctx, entry.principal, princ);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "krb5_copy_principal failed.\n");
            sss_log(SSS_LOG_ERR, "krb5_copy_principal failed.\n");
        }
        kerr_dbg = sss_krb5_free_keytab_entry_contents(ctx, &entry);
        if (kerr_dbg != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to free keytab entry.\n");
        }
    } else {
        /* If principal was not found then 'kerr' was set */
        if (kerr != KRB5_KT_END) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Error while reading keytab using krb5_kt_next_entry()\n");
            sss_log(SSS_LOG_ERR,
                    "Error while reading keytab using krb5_kt_next_entry()\n");
        } else {
            kerr = KRB5_KT_NOTFOUND;
            DEBUG(SSSDBG_TRACE_FUNC,
                  "No principal matching %s@%s found in keytab.\n",
                   pattern_primary, pattern_realm);
        }
    }

    return kerr;
}

static const char *__SSS_KRB5_NO_ERR_MSG_AVAILABLE = "- no krb5 error message available -";

const char *KRB5_CALLCONV sss_krb5_get_error_message(krb5_context ctx,
                                                     krb5_error_code ec)
{
#ifdef HAVE_KRB5_GET_ERROR_MESSAGE
    return krb5_get_error_message(ctx, ec);
#else
    int size = sizeof("Kerberos error [XXXXXXXXXXXX]");
    char *s = malloc(sizeof(char) * size);
    if (s != NULL) {
        int ret = snprintf(s, size, "Kerberos error [%12d]", ec);
        if (ret < 0 || ret >= size) {
            free(s);
            s = NULL;
        }
    }
    return (s ? s : __SSS_KRB5_NO_ERR_MSG_AVAILABLE);
#endif
}

void KRB5_CALLCONV sss_krb5_free_error_message(krb5_context ctx, const char *s)
{
    if (s == __SSS_KRB5_NO_ERR_MSG_AVAILABLE) {
        return;
    }

#ifdef HAVE_KRB5_GET_ERROR_MESSAGE
    if (s != NULL) {
        krb5_free_error_message(ctx, s);
    }
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
    if (name != NULL) {
        krb5_free_unparsed_name(context, name);
    }
#else
    if (name != NULL) {
        memset(name, 0, strlen(name));
        free(name);
    }
#endif
}


krb5_error_code KRB5_CALLCONV sss_krb5_get_init_creds_opt_set_expire_callback(
                                                   krb5_context context,
                                                   krb5_get_init_creds_opt *opt,
                                                   krb5_expire_callback_func cb,
                                                   void *data)
{
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_EXPIRE_CALLBACK
    return krb5_get_init_creds_opt_set_expire_callback(context, opt, cb, data);
#else
    DEBUG(SSSDBG_FUNC_DATA,
          "krb5_get_init_creds_opt_set_expire_callback not available.\n");
    return 0;
#endif
}

errno_t check_fast(const char *str, bool *use_fast)
{
#if HAVE_KRB5_GET_INIT_CREDS_OPT_SET_FAST_FLAGS
    if (strcasecmp(str, "never") == 0 ) {
        *use_fast = false;
    } else if (strcasecmp(str, "try") == 0 || strcasecmp(str, "demand") == 0) {
        *use_fast = true;
    } else {
        sss_log(SSS_LOG_ALERT, "Unsupported value [%s] for option krb5_use_fast,"
                               "please use never, try, or demand.\n", str);
        return EINVAL;
    }

    return EOK;
#else
    sss_log(SSS_LOG_ALERT, "This build of sssd does not support FAST. "
                           "Please remove option krb5_use_fast.\n");
    return EINVAL;
#endif
}

krb5_error_code KRB5_CALLCONV sss_krb5_get_init_creds_opt_set_fast_ccache_name(
                                                   krb5_context context,
                                                   krb5_get_init_creds_opt *opt,
                                                   const char *fast_ccache_name)
{
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_FAST_CCACHE_NAME
    return krb5_get_init_creds_opt_set_fast_ccache_name(context, opt,
                                                        fast_ccache_name);
#else
    DEBUG(SSSDBG_FUNC_DATA,
          "krb5_get_init_creds_opt_set_fast_ccache_name not available.\n");
    return 0;
#endif
}

krb5_error_code KRB5_CALLCONV sss_krb5_get_init_creds_opt_set_fast_flags(
                                                   krb5_context context,
                                                   krb5_get_init_creds_opt *opt,
                                                   krb5_flags flags)
{
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_FAST_FLAGS
    return krb5_get_init_creds_opt_set_fast_flags(context, opt, flags);
#else
    DEBUG(SSSDBG_FUNC_DATA,
          "krb5_get_init_creds_opt_set_fast_flags not available.\n");
    return 0;
#endif
}


#ifndef HAVE_KRB5_UNPARSE_NAME_FLAGS
#ifndef REALM_SEP
#define REALM_SEP       '@'
#endif
#ifndef COMPONENT_SEP
#define COMPONENT_SEP   '/'
#endif

static int
sss_krb5_copy_component_quoting(char *dest, const krb5_data *src, int flags)
{
    int j;
    const char *cp = src->data;
    char *q = dest;
    int length = src->length;

    if (flags & KRB5_PRINCIPAL_UNPARSE_DISPLAY) {
        memcpy(dest, src->data, src->length);
        return src->length;
    }

    for (j=0; j < length; j++,cp++) {
        int no_realm = (flags & KRB5_PRINCIPAL_UNPARSE_NO_REALM) &&
            !(flags & KRB5_PRINCIPAL_UNPARSE_SHORT);

        switch (*cp) {
        case REALM_SEP:
            if (no_realm) {
                *q++ = *cp;
                break;
            }
        case COMPONENT_SEP:
        case '\\':
            *q++ = '\\';
            *q++ = *cp;
            break;
        case '\t':
            *q++ = '\\';
            *q++ = 't';
            break;
        case '\n':
            *q++ = '\\';
            *q++ = 'n';
            break;
        case '\b':
            *q++ = '\\';
            *q++ = 'b';
            break;
        case '\0':
            *q++ = '\\';
            *q++ = '0';
            break;
        default:
            *q++ = *cp;
        }
    }
    return q - dest;
}

static int
sss_krb5_component_length_quoted(const krb5_data *src, int flags)
{
    const char *cp = src->data;
    int length = src->length;
    int j;
    int size = length;

    if ((flags & KRB5_PRINCIPAL_UNPARSE_DISPLAY) == 0) {
        int no_realm = (flags & KRB5_PRINCIPAL_UNPARSE_NO_REALM) &&
            !(flags & KRB5_PRINCIPAL_UNPARSE_SHORT);

        for (j = 0; j < length; j++,cp++)
            if ((!no_realm && *cp == REALM_SEP) ||
                *cp == COMPONENT_SEP ||
                *cp == '\0' || *cp == '\\' || *cp == '\t' ||
                *cp == '\n' || *cp == '\b')
                size++;
    }

    return size;
}

#endif /* HAVE_KRB5_UNPARSE_NAME_FLAGS */


krb5_error_code
sss_krb5_parse_name_flags(krb5_context context, const char *name, int flags,
                          krb5_principal *principal)
{
#ifdef HAVE_KRB5_PARSE_NAME_FLAGS
    return krb5_parse_name_flags(context, name, flags, principal);
#else
    if (flags != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "krb5_parse_name_flags not available on " \
                                     "this plattform, names are parsed " \
                                     "without flags. Some features like " \
                                     "enterprise principals might not work " \
                                     "as expected.\n");
    }

    return krb5_parse_name(context, name, principal);
#endif
}

krb5_error_code
sss_krb5_unparse_name_flags(krb5_context context, krb5_const_principal principal,
                        int flags, char **name)
{
#ifdef HAVE_KRB5_UNPARSE_NAME_FLAGS
    return krb5_unparse_name_flags(context, principal, flags, name);
#else
    char *cp, *q;
    int i;
    int length;
    krb5_int32 nelem;
    unsigned int totalsize = 0;
    char *default_realm = NULL;
    krb5_error_code ret = 0;

    if (name != NULL)
        *name = NULL;

    if (!principal || !name)
        return KRB5_PARSE_MALFORMED;

    if (flags & KRB5_PRINCIPAL_UNPARSE_SHORT) {
        /* omit realm if local realm */
        krb5_principal_data p;

        ret = krb5_get_default_realm(context, &default_realm);
        if (ret != 0)
            goto cleanup;

        krb5_princ_realm(context, &p)->length = strlen(default_realm);
        krb5_princ_realm(context, &p)->data = default_realm;

        if (krb5_realm_compare(context, &p, principal))
            flags |= KRB5_PRINCIPAL_UNPARSE_NO_REALM;
    }

    if ((flags & KRB5_PRINCIPAL_UNPARSE_NO_REALM) == 0) {
        totalsize += sss_krb5_component_length_quoted(krb5_princ_realm(context,
                                                              principal),
                                             flags);
        totalsize++;
    }

    nelem = krb5_princ_size(context, principal);
    for (i = 0; i < (int) nelem; i++) {
        cp = krb5_princ_component(context, principal, i)->data;
        totalsize += sss_krb5_component_length_quoted(krb5_princ_component(context, principal, i), flags);
        totalsize++;
    }
    if (nelem == 0)
        totalsize++;

    *name = malloc(totalsize);

    if (!*name) {
        ret = ENOMEM;
        goto cleanup;
    }

    q = *name;

    for (i = 0; i < (int) nelem; i++) {
        cp = krb5_princ_component(context, principal, i)->data;
        length = krb5_princ_component(context, principal, i)->length;
        q += sss_krb5_copy_component_quoting(q,
                                    krb5_princ_component(context,
                                                         principal,
                                                         i),
                                    flags);
        *q++ = COMPONENT_SEP;
    }

    if (i > 0)
        q--;
    if ((flags & KRB5_PRINCIPAL_UNPARSE_NO_REALM) == 0) {
        *q++ = REALM_SEP;
        q += sss_krb5_copy_component_quoting(q, krb5_princ_realm(context, principal), flags);
    }
    *q++ = '\0';

cleanup:
    free(default_realm);

    return ret;
#endif /* HAVE_KRB5_UNPARSE_NAME_FLAGS */
}

void sss_krb5_get_init_creds_opt_set_canonicalize(krb5_get_init_creds_opt *opts,
                                                  int canonicalize)
{
    /* FIXME: The extra check for HAVE_KRB5_TICKET_TIMES is a workaround due to Heimdal
     * defining krb5_get_init_creds_opt_set_canonicalize() with a different set of
     * arguments. We should use a better configure check in the future.
     */
#if defined(HAVE_KRB5_GET_INIT_CREDS_OPT_SET_CANONICALIZE) && defined(HAVE_KRB5_TICKET_TIMES)
    krb5_get_init_creds_opt_set_canonicalize(opts, canonicalize);
#else
    DEBUG(SSSDBG_OP_FAILURE, "Kerberos principal canonicalization is not available!\n");
#endif
}

#ifdef HAVE_KRB5_PRINCIPAL_GET_REALM
void sss_krb5_princ_realm(krb5_context context, krb5_const_principal princ,
                          const char **realm, int *len)
{
    const char *realm_str = krb5_principal_get_realm(context, princ);

    if (realm_str != NULL) {
        *realm = realm_str;
        *len = strlen(realm_str);
    } else {
        *realm = NULL;
        *len = 0;
    }
}
#else
void sss_krb5_princ_realm(krb5_context context, krb5_const_principal princ,
                          const char **realm, int *len)
{
    const krb5_data *data;

    data = krb5_princ_realm(context, princ);
    if (data) {
        *realm = data->data;
        *len = data->length;
    } else {
        *realm = NULL;
        *len = 0;
    }
}
#endif

krb5_error_code
sss_krb5_free_keytab_entry_contents(krb5_context context,
                                    krb5_keytab_entry *entry)
{
#ifdef HAVE_KRB5_FREE_KEYTAB_ENTRY_CONTENTS
    return krb5_free_keytab_entry_contents(context, entry);
#else
    return krb5_kt_free_entry(context, entry);
#endif
}


#ifdef HAVE_KRB5_SET_TRACE_CALLBACK

#ifndef HAVE_KRB5_TRACE_INFO
/* krb5-1.10 had struct krb5_trace_info, 1.11 has type named krb5_trace_info */
typedef struct krb5_trace_info krb5_trace_info;
#endif  /* HAVE_KRB5_TRACE_INFO */

static void
sss_child_krb5_trace_cb(krb5_context context,
                        const krb5_trace_info *info, void *data)
{
    if (info == NULL) {
        /* Null info means destroy the callback data. */
        return;
    }

    DEBUG(SSSDBG_TRACE_ALL, "%s\n", info->message);
}

errno_t
sss_child_set_krb5_tracing(krb5_context ctx)
{
    return krb5_set_trace_callback(ctx, sss_child_krb5_trace_cb, NULL);
}
#else /* HAVE_KRB5_SET_TRACE_CALLBACK */
errno_t
sss_child_set_krb5_tracing(krb5_context ctx)
{
    DEBUG(SSSDBG_CONF_SETTINGS, "krb5 tracing is not available\n");
    return 0;
}
#endif /* HAVE_KRB5_SET_TRACE_CALLBACK */

krb5_error_code sss_krb5_find_authdata(krb5_context context,
                                       krb5_authdata *const *ticket_authdata,
                                       krb5_authdata *const *ap_req_authdata,
                                       krb5_authdatatype ad_type,
                                       krb5_authdata ***results)
{
#ifdef HAVE_KRB5_FIND_AUTHDATA
    return krb5_find_authdata(context, ticket_authdata, ap_req_authdata,
                              ad_type, results);
#else
    return ENOTSUP;
#endif
}

krb5_error_code sss_extract_pac(krb5_context ctx,
                                krb5_ccache ccache,
                                krb5_principal server_principal,
                                krb5_principal client_principal,
                                krb5_keytab keytab,
                                uint32_t check_pac_flags,
                                krb5_authdata ***_pac_authdata)
{
    krb5_error_code kerr;
    krb5_creds mcred;
    krb5_creds cred;
    krb5_authdata **pac_authdata = NULL;
    krb5_pac pac = NULL;
    krb5_ticket *ticket = NULL;
    krb5_keytab_entry entry;

    memset(&entry, 0, sizeof(entry));
    memset(&mcred, 0, sizeof(mcred));
    memset(&cred, 0, sizeof(mcred));

    mcred.server = server_principal;
    mcred.client = client_principal;

    kerr = krb5_cc_retrieve_cred(ctx, ccache, 0, &mcred, &cred);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_cc_retrieve_cred failed.\n");
        goto done;
    }

    kerr = krb5_decode_ticket(&cred.ticket, &ticket);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_decode_ticket failed.\n");
        goto done;
    }

    kerr = krb5_server_decrypt_ticket_keytab(ctx, keytab, ticket);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_server_decrypt_ticket_keytab failed.\n");
        goto done;
    }

    kerr = sss_krb5_find_authdata(ctx,
                                  ticket->enc_part2->authorization_data, NULL,
                                  KRB5_AUTHDATA_WIN2K_PAC, &pac_authdata);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_find_authdata failed.\n");
        goto done;
    }

    if (pac_authdata == NULL || pac_authdata[0] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "No PAC authdata available.\n");
        if (check_pac_flags & CHECK_PAC_PRESENT) {
            kerr = ERR_CHECK_PAC_FAILED;
        } else {
            kerr = ENOENT;
        }
        goto done;
    }

    if (pac_authdata[1] != NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "More than one PAC autdata found.\n");
        kerr = EINVAL;
        goto done;
    }

    kerr = krb5_pac_parse(ctx, pac_authdata[0]->contents,
                          pac_authdata[0]->length, &pac);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_pac_parse failed.\n");
        goto done;
    }

    kerr = krb5_kt_get_entry(ctx, keytab, ticket->server,
                             ticket->enc_part.kvno, ticket->enc_part.enctype,
                             &entry);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_kt_get_entry failed.\n");
        goto done;
    }

    kerr = krb5_pac_verify(ctx, pac, 0, NULL, &entry.key, NULL);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_pac_verify failed.\n");
        goto done;
    }

    *_pac_authdata = pac_authdata;
    kerr = 0;

done:
    if (kerr != 0) {
        krb5_free_authdata(ctx, pac_authdata);
    }
    if (entry.magic != 0) {
        krb5_free_keytab_entry_contents(ctx, &entry);
    }
    krb5_pac_free(ctx, pac);
    if (ticket != NULL) {
        krb5_free_ticket(ctx, ticket);
    }

    krb5_free_cred_contents(ctx, &cred);
    return kerr;
}

char * sss_get_ccache_name_for_principal(TALLOC_CTX *mem_ctx,
                                         krb5_context ctx,
                                         krb5_principal principal,
                                         const char *location)
{
#ifdef HAVE_KRB5_CC_COLLECTION
    krb5_error_code kerr;
    krb5_ccache tmp_cc = NULL;
    char *tmp_ccname = NULL;
    char *ret_ccname = NULL;

    DEBUG(SSSDBG_TRACE_ALL,
          "Location: [%s]\n", location);

    kerr = krb5_cc_set_default_name(ctx, location);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_MINOR_FAILURE, ctx, kerr);
        return NULL;
    }

    kerr = krb5_cc_cache_match(ctx, principal, &tmp_cc);
    if (kerr != 0) {
        const char *err_msg = sss_krb5_get_error_message(ctx, kerr);
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "krb5_cc_cache_match failed: [%d][%s]\n", kerr, err_msg);
        sss_krb5_free_error_message(ctx, err_msg);
        return NULL;
    }

    kerr = krb5_cc_get_full_name(ctx, tmp_cc, &tmp_ccname);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_MINOR_FAILURE, ctx, kerr);
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL,
          "tmp_ccname: [%s]\n", tmp_ccname);

    ret_ccname = talloc_strdup(mem_ctx, tmp_ccname);
    if (ret_ccname == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed (ENOMEM).\n");
    }

done:
    if (tmp_cc != NULL) {
        kerr = krb5_cc_close(ctx, tmp_cc);
        if (kerr != 0) {
            KRB5_DEBUG(SSSDBG_MINOR_FAILURE, ctx, kerr);
        }
    }
    krb5_free_string(ctx, tmp_ccname);

    return ret_ccname;
#else
    return NULL;
#endif /* HAVE_KRB5_CC_COLLECTION */
}

krb5_error_code sss_krb5_kt_have_content(krb5_context context,
                                         krb5_keytab keytab)
{
#ifdef HAVE_KRB5_KT_HAVE_CONTENT
    return krb5_kt_have_content(context, keytab);
#else
    krb5_keytab_entry entry;
    krb5_kt_cursor cursor;
    krb5_error_code kerr;
    krb5_error_code kerr_end;

    kerr = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "krb5_kt_start_seq_get failed, assuming no entries.\n");
        return KRB5_KT_NOTFOUND;
    }

    kerr = krb5_kt_next_entry(context, keytab, &entry, &cursor);
    kerr_end = krb5_kt_end_seq_get(context, keytab, &cursor);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "krb5_kt_next_entry failed, assuming no entries.\n");
        return KRB5_KT_NOTFOUND;
    }
    kerr = krb5_free_keytab_entry_contents(context, &entry);

    if (kerr_end != 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "krb5_kt_end_seq_get failed, ignored.\n");
    }
    if (kerr != 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "krb5_free_keytab_entry_contents failed, ignored.\n");
    }

    return 0;
#endif
}

#define KDC_PROXY_INDICATOR "https://"
#define KDC_PROXY_INDICATOR_LEN (sizeof(KDC_PROXY_INDICATOR) - 1)

bool sss_krb5_realm_has_proxy(const char *realm)
{
    krb5_context context = NULL;
    krb5_error_code kerr;
    struct _profile_t *profile = NULL;
    const char  *profile_path[4] = {"realms", NULL, "kdc", NULL};
    char **list = NULL;
    bool res = false;
    size_t c;

    if (realm == NULL) {
        return false;
    }

    kerr = sss_krb5_init_context(&context);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_krb5_init_context failed.\n");
        return false;
    }

    kerr = krb5_get_profile(context, &profile);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_get_profile failed.\n");
        goto done;
    }

    profile_path[1] = realm;

    kerr = profile_get_values(profile, profile_path, &list);
    if (kerr == PROF_NO_RELATION || kerr == PROF_NO_SECTION) {
        goto done;
    } else if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "profile_get_values failed.\n");
        goto done;
    }

    for (c = 0; list[c] != NULL; c++) {
        if (strncasecmp(KDC_PROXY_INDICATOR, list[c],
                        KDC_PROXY_INDICATOR_LEN) == 0) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Found KDC Proxy indicator [%s] in [%s].\n",
                  KDC_PROXY_INDICATOR, list[c]);
            res = true;
            break;
        }
    }

done:
    profile_free_list(list);
    profile_release(profile);
    krb5_free_context(context);

    return res;
}

static errno_t iobuf_read_uint32be(struct sss_iobuf *iobuf,
                                   uint32_t *_val)
{
    uint32_t beval;
    errno_t ret;

    ret = sss_iobuf_read_uint32(iobuf, &beval);
    if (ret != EOK) {
        return ret;
    }

    *_val = be32toh(beval);
    return EOK;
}

static errno_t iobuf_write_uint32be(struct sss_iobuf *iobuf,
                                    uint32_t val)
{
    uint32_t beval;

    beval = htobe32(val);
    return sss_iobuf_write_uint32(iobuf, beval);
}

static errno_t iobuf_get_len_bytes(TALLOC_CTX *mem_ctx,
                                   struct sss_iobuf *iobuf,
                                   uint32_t *_nbytes,
                                   uint8_t **_bytes)
{
    errno_t ret;
    uint32_t nbytes;
    uint8_t *bytes = NULL;

    ret = iobuf_read_uint32be(iobuf, &nbytes);
    if (ret != EOK) {
        return ret;
    }

    bytes = talloc_zero_size(mem_ctx, nbytes);
    if (bytes == NULL) {
        return ENOMEM;
    }

    ret = sss_iobuf_read_len(iobuf, nbytes, bytes);
    if (ret != EOK) {
        talloc_free(bytes);
        return ret;
    }

    *_bytes = bytes;
    *_nbytes = nbytes;
    return EOK;
}

void get_krb5_data_from_cred(struct sss_iobuf *iobuf, krb5_data *k5data)
{
    k5data->data = (char *) sss_iobuf_get_data(iobuf);
    k5data->length = sss_iobuf_get_size(iobuf);
}

static errno_t get_krb5_data(TALLOC_CTX *mem_ctx,
                             struct sss_iobuf *iobuf,
                             krb5_data *k5data)
{
    errno_t ret;
    uint32_t nbytes;
    uint8_t *bytes = NULL;

    ret = iobuf_get_len_bytes(mem_ctx, iobuf,  &nbytes, &bytes);
    if (ret != EOK) {
        talloc_free(bytes);
        return ret;
    }

    k5data->data = (char *) bytes; /* FIXME - the cast is ugly */
    k5data->length = nbytes;
    return EOK;
}

static errno_t set_krb5_data(struct sss_iobuf *iobuf,
                             krb5_data *k5data)
{
    errno_t ret;

    ret = iobuf_write_uint32be(iobuf, k5data->length);
    if (ret != EOK) {
        return ret;
    }

    if (k5data->length > 0) {
        ret = sss_iobuf_write_len(iobuf,
                                  (uint8_t *) k5data->data,
                                  k5data->length);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

/* FIXME - it would be nice if Kerberos exported these APIs.. */
krb5_error_code sss_krb5_unmarshal_princ(TALLOC_CTX *mem_ctx,
                                         struct sss_iobuf *iobuf,
                                         krb5_principal *_princ)
{
    krb5_principal princ = NULL;
    krb5_error_code ret;
    uint32_t ncomps;

    if (iobuf == NULL || _princ == NULL) {
        return EINVAL;
    }

    princ = talloc_zero(mem_ctx, struct krb5_principal_data);
    if (princ == NULL) {
        return ENOMEM;
    }

    princ->magic = KV5M_PRINCIPAL;

    ret = iobuf_read_uint32be(iobuf, (uint32_t *) &princ->type);
    if (ret != EOK) {
        goto fail;
    }

    ret = iobuf_read_uint32be(iobuf, &ncomps);
    if (ret != EOK) {
        goto fail;
    }

    if (ncomps > sss_iobuf_get_capacity(iobuf)) {
        /* Sanity check to avoid large allocations */
        ret = EINVAL;
        goto fail;
    }

    if (ncomps != 0) {
        princ->data = talloc_zero_array(princ, krb5_data, ncomps);
        if (princ->data == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        princ->length = ncomps;
    }

    ret = get_krb5_data(princ, iobuf, &princ->realm);
    if (ret != EOK) {
        goto fail;
    }

    for (size_t i = 0; i < ncomps; i++) {
        ret = get_krb5_data(princ->data, iobuf, &princ->data[i]);
        if (ret != EOK) {
            goto fail;
        }
    }

    *_princ = princ;
    return 0;

fail:
    talloc_free(princ);
    return ret;
}

krb5_error_code sss_krb5_marshal_princ(krb5_principal princ,
                                       struct sss_iobuf *iobuf)
{
    krb5_error_code ret;

    if (iobuf == NULL || princ == NULL) {
        return EINVAL;
    }

    ret = iobuf_write_uint32be(iobuf, princ->type);
    if (ret != EOK) {
        return ret;
    }

    ret = iobuf_write_uint32be(iobuf, princ->length);
    if (ret != EOK) {
        return ret;
    }

    ret = set_krb5_data(iobuf, &princ->realm);
    if (ret != EOK) {
        return ret;
    }

    for (int i = 0; i < princ->length; i++) {
        ret = set_krb5_data(iobuf, &princ->data[i]);
        if (ret != EOK) {
            return ret;
        }
    }
    return EOK;
}

krb5_error_code sss_krb5_init_context(krb5_context *context)
{
    krb5_error_code kerr;
    const char *msg;

    kerr = krb5_init_context(context);
    if (kerr != 0) {
        /* It is safe to call (sss_)krb5_get_error_message() with NULL as first
         * argument. */
        msg = sss_krb5_get_error_message(NULL, kerr);
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to init Kerberos context [%s]\n", msg);
        sss_log(SSS_LOG_CRIT, "Failed to init Kerberos context [%s]\n", msg);
        sss_krb5_free_error_message(NULL, msg);
    }

    return kerr;
}

bool sss_krb5_creds_compare(krb5_context kctx, krb5_creds *a, krb5_creds *b)
{
    if (!krb5_principal_compare(kctx, a->client, b->client)) {
        return false;
    }

    if (!krb5_principal_compare(kctx, a->server, b->server)) {
        return false;
    }

    return true;
}
