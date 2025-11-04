/*
    SSSD

    LDAP Backend Module -- prime ccache with TGT in a child process

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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

#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <signal.h>
#include <popt.h>

#include "shared/io.h"
#include "util/util.h"
#include "util/sss_krb5.h"
#include "providers/backend.h"
#include "providers/ldap/ldap_common.h"
#include "providers/krb5/krb5_common.h"

char *global_ccname_file_dummy = NULL;

static void sig_term_handler(int sig)
{
    if (global_ccname_file_dummy != NULL) {
        /* Cast to void to avoid a complaint by Coverity */
        (void) unlink(global_ccname_file_dummy);
    }

    _exit(CHILD_TIMEOUT_EXIT_CODE);
}

static krb5_context krb5_error_ctx;
#define LDAP_CHILD_DEBUG(level, error) KRB5_DEBUG(level, krb5_error_ctx, error)

struct input_buffer {
    enum ldap_child_command cmd;
    const char *realm_str;
    const char *princ_str;
    char *keytab_name;
    krb5_deltat lifetime;
    krb5_context context;
};

static inline const char *command_to_str(enum ldap_child_command cmd)
{
    if (cmd == LDAP_CHILD_GET_TGT) {
        return "Get TGT";
    } else if (cmd == LDAP_CHILD_SELECT_PRINCIPAL) {
        return "Select principal";
    } else {
        return "-unknown-";
    }
};

static errno_t unpack_buffer(uint8_t *buf, size_t size,
                             struct input_buffer *ibuf)
{
    size_t p = 0;
    uint32_t len;
    uint32_t value = 0;

    DEBUG(SSSDBG_TRACE_LIBS, "total buffer size: %zu\n", size);

    /* command */
    SAFEALIGN_COPY_UINT32_CHECK(&value, buf + p, size, &p);
    ibuf->cmd = value;
    DEBUG(SSSDBG_TRACE_LIBS, "command: %s\n", command_to_str(ibuf->cmd));

    /* realm_str size and length */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    DEBUG(SSSDBG_TRACE_LIBS, "realm_str size: %d\n", len);
    if (len) {
        if (len > size - p) return EINVAL;
        ibuf->realm_str = talloc_strndup(ibuf, (char *)(buf + p), len);
        DEBUG(SSSDBG_TRACE_LIBS, "got realm_str: %s\n", ibuf->realm_str);
        if (ibuf->realm_str == NULL) return ENOMEM;
        p += len;
    }

    /* princ_str size and length */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    DEBUG(SSSDBG_TRACE_LIBS, "princ_str size: %d\n", len);
    if (len) {
        if (len > size - p) return EINVAL;
        ibuf->princ_str = talloc_strndup(ibuf, (char *)(buf + p), len);
        DEBUG(SSSDBG_TRACE_LIBS, "got princ_str: %s\n", ibuf->princ_str);
        if (ibuf->princ_str == NULL) return ENOMEM;
        p += len;
    }

    /* keytab_name size and length */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    DEBUG(SSSDBG_TRACE_LIBS, "keytab_name size: %d\n", len);
    if (len) {
        if (len > size - p) return EINVAL;
        ibuf->keytab_name = talloc_strndup(ibuf, (char *)(buf + p), len);
        DEBUG(SSSDBG_TRACE_LIBS, "got keytab_name: %s\n", ibuf->keytab_name);
        if (ibuf->keytab_name == NULL) return ENOMEM;
        p += len;
    }

    if (ibuf->cmd == LDAP_CHILD_SELECT_PRINCIPAL) {
        return EOK;
    }

    /* ticket lifetime */
    SAFEALIGN_COPY_UINT32_CHECK(&value, buf + p, size, &p);
    ibuf->lifetime = (krb5_deltat)value;
    DEBUG(SSSDBG_TRACE_LIBS, "lifetime: %u\n", ibuf->lifetime);

    return EOK;
}

static int pack_buffer(struct io_buffer *r, int result, krb5_error_code krberr,
                       const char *msg, time_t expire_time)
{
    int len;
    size_t p = 0;

    len = strlen(msg);
    r->size = 2 * sizeof(uint32_t) + sizeof(krb5_error_code) +
              len + sizeof(time_t);

    DEBUG(SSSDBG_TRACE_INTERNAL, "response size: %zu\n",r->size);

    r->data = talloc_array(r, uint8_t, r->size);
    if (!r->data) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          "result [%d] krberr [%d] msgsize [%d] msg [%s]\n",
           result, krberr, len, msg);

    /* result */
    SAFEALIGN_SET_UINT32(&r->data[p], result, &p);

    /* krb5 error code */
    safealign_memcpy(&r->data[p], &krberr, sizeof(krberr), &p);

    /* message size */
    SAFEALIGN_SET_UINT32(&r->data[p], len, &p);

    /* message itself */
    safealign_memcpy(&r->data[p], msg, len, &p);

    /* ticket expiration time */
    safealign_memcpy(&r->data[p], &expire_time, sizeof(expire_time), &p);

    return EOK;
}

static errno_t
set_child_debugging(krb5_context ctx)
{
    krb5_error_code kerr;

    /* Set the global error context */
    krb5_error_ctx = ctx;

    if (debug_level & SSSDBG_TRACE_ALL) {
        kerr = sss_child_set_krb5_tracing(ctx);
        if (kerr) {
            LDAP_CHILD_DEBUG(SSSDBG_MINOR_FAILURE, kerr);
            return EIO;
        }
    }

    return EOK;
}


static char *sss_krb5_get_primary(TALLOC_CTX *mem_ctx,
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

static errno_t select_principal_from_keytab(TALLOC_CTX *mem_ctx,
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
     * - SHORT.HOSTNAME$/@
     * - host/foobar@
     * - pick the first principal in the keytab
     */
    const char *primary_patterns[] = {"%s", "%S$", "host/%s", "*$", "host/*",
                                      "%S$", "host/*", NULL};
    const char *realm_patterns[] =   {"%s", "%s",  "%s",      "%s", "%s",
                                      NULL, NULL,     NULL};

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
    if (client_princ) krb5_free_principal(krb_ctx, client_princ);
    if (krb_ctx) krb5_free_context(krb_ctx);
    talloc_free(tmp_ctx);
    return ret;
}

static int lc_verify_keytab_ex(const char *principal,
                               const char *keytab_name,
                               krb5_context context,
                               krb5_keytab keytab)
{
    bool found;
    char *kt_principal;
    krb5_error_code krberr;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;

    krberr = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (krberr) {
        const char *__err_msg = sss_krb5_get_error_message(context, krberr);

        DEBUG(SSSDBG_FATAL_FAILURE,
              "Cannot read keytab [%s]: [%d][%s].\n",
              sss_printable_keytab_name(context, keytab_name),
              krberr, __err_msg);

        sss_log(SSS_LOG_ERR, "Error reading keytab file [%s]: [%d][%s]. "
                             "Unable to create GSSAPI-encrypted LDAP "
                             "connection.",
                             sss_printable_keytab_name(context, keytab_name),
                             krberr, __err_msg);

        sss_krb5_free_error_message(context, __err_msg);
        return EIO;
    }

    found = false;
    while ((krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0) {
        krberr = krb5_unparse_name(context, entry.principal, &kt_principal);
        if (krberr) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Could not parse keytab entry\n");
            sss_log(SSS_LOG_ERR, "Could not parse keytab entry\n");
            krb5_kt_end_seq_get(context, keytab, &cursor);
            return EIO;
        }

        if (strcmp(principal, kt_principal) == 0) {
            found = true;
        }
        free(kt_principal);
        krberr = sss_krb5_free_keytab_entry_contents(context, &entry);
        if (krberr) {
            /* This should never happen. The API docs for this function
             * specify only success for this function
             */
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not free keytab entry contents\n");
            /* This is non-fatal, so we'll continue here */
        }

        if (found) {
            break;
        }
    }

    krberr = krb5_kt_end_seq_get(context, keytab, &cursor);
    if (krberr) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not close keytab.\n");
        sss_log(SSS_LOG_ERR, "Could not close keytab file [%s].",
                             sss_printable_keytab_name(context, keytab_name));
        return EIO;
    }

    if (!found) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Principal [%s] not found in keytab [%s]\n",
               principal,
               sss_printable_keytab_name(context, keytab_name));
        sss_log(SSS_LOG_ERR, "Error processing keytab file [%s]: "
                             "Principal [%s] was not found. "
                             "Unable to create GSSAPI-encrypted LDAP connection.",
                             sss_printable_keytab_name(context, keytab_name),
                             principal);

        return EFAULT;
    }

    return EOK;
}

static krb5_error_code ldap_child_get_tgt_sync(TALLOC_CTX *memctx,
                                               krb5_context context,
                                               const char *realm_str,
                                               const char *princ_str,
                                               const char *keytab_name,
                                               const krb5_deltat lifetime,
                                               const char **ccname_out,
                                               time_t *expire_time_out,
                                               char **_krb5_msg)
{
    char *ccname;
    char *ccname_dummy;
    char *realm_name = NULL;
    char *full_princ = NULL;
    char *default_realm = NULL;
    char *tmp_str = NULL;
    krb5_keytab keytab = NULL;
    krb5_ccache ccache = NULL;
    krb5_principal kprinc;
    krb5_creds my_creds;
    krb5_get_init_creds_opt *options = NULL;
    krb5_error_code krberr;
    krb5_timestamp kdc_time_offset;
    int canonicalize = 0;
    int kdc_time_offset_usec;
    int ret;
    errno_t error_code;
    TALLOC_CTX *tmp_ctx;
    char *ccname_file_dummy = NULL;
    char *ccname_file;

    *_krb5_msg = NULL;

    tmp_ctx = talloc_new(memctx);
    if (tmp_ctx == NULL) {
        krberr = KRB5KRB_ERR_GENERIC;
        *_krb5_msg = talloc_strdup(memctx, strerror(ENOMEM));
        goto done;
    }

    error_code = set_child_debugging(context);
    if (error_code != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot set krb5_child debugging\n");
    }

    if (!realm_str) {
        krberr = krb5_get_default_realm(context, &default_realm);
        if (krberr != 0) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "krb5_get_default_realm() failed: %d\n", krberr);
            goto done;
        }

        realm_name = talloc_strdup(tmp_ctx, default_realm);
        krb5_free_default_realm(context, default_realm);
        if (!realm_name) {
            krberr = KRB5KRB_ERR_GENERIC;
            *_krb5_msg = talloc_strdup(memctx, strerror(ENOMEM));
            goto done;
        }
    } else {
        realm_name = talloc_strdup(tmp_ctx, realm_str);
        if (!realm_name) {
            krberr = KRB5KRB_ERR_GENERIC;
            *_krb5_msg = talloc_strdup(memctx, strerror(ENOMEM));
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "got realm_name: [%s]\n", realm_name);

    if (princ_str) {
        if (!strchr(princ_str, '@')) {
            full_princ = talloc_asprintf(tmp_ctx, "%s@%s",
                                         princ_str, realm_name);
        } else {
            full_princ = talloc_strdup(tmp_ctx, princ_str);
        }
    } else {
        char hostname[HOST_NAME_MAX + 1];

        ret = gethostname(hostname, sizeof(hostname));
        if (ret == -1) {
            krberr = KRB5KRB_ERR_GENERIC;
            *_krb5_msg = talloc_asprintf(memctx, "hostname() failed: [%d][%s]",
                                         errno, strerror(errno));
            goto done;
        }
        hostname[HOST_NAME_MAX] = '\0';

        DEBUG(SSSDBG_TRACE_LIBS, "got hostname: [%s]\n", hostname);

        ret = select_principal_from_keytab(tmp_ctx, hostname, realm_name,
                keytab_name, &full_princ, NULL, NULL);
        if (ret) {
            krberr = KRB5_KT_IOERR;
            *_krb5_msg = talloc_strdup(memctx,
                                       "select_principal_from_keytab() failed");
            goto done;
        }
    }
    if (!full_princ) {
        krberr = KRB5KRB_ERR_GENERIC;
        *_krb5_msg = talloc_strdup(memctx, strerror(ENOMEM));
        goto done;
    }
    DEBUG(SSSDBG_CONF_SETTINGS, "Principal name is: [%s]\n", full_princ);

    if (keytab_name) {
        krberr = krb5_kt_resolve(context, keytab_name, &keytab);
    } else {
        krberr = krb5_kt_default(context, &keytab);
    }
    DEBUG(SSSDBG_CONF_SETTINGS, "Using keytab [%s]\n",
          sss_printable_keytab_name(context, keytab_name));
    if (krberr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read keytab file: %d\n", krberr);
        goto done;
    }

    /* Verify the keytab */
    ret = lc_verify_keytab_ex(full_princ, keytab_name, context, keytab);
    if (ret) {
        krberr = KRB5_KT_IOERR;
        *_krb5_msg = talloc_strdup(memctx, "Unable to verify principal is present in the keytab");
        goto done;
    }

    memset(&my_creds, 0, sizeof(my_creds));

    krberr = krb5_get_init_creds_opt_alloc(context, &options);
    if (krberr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_get_init_creds_opt_alloc failed.\n");
        goto done;
    }

    krb5_get_init_creds_opt_set_address_list(options, NULL);
    krb5_get_init_creds_opt_set_forwardable(options, 0);
    krb5_get_init_creds_opt_set_proxiable(options, 0);
    krb5_get_init_creds_opt_set_tkt_life(options, lifetime);
    krberr = krb5_get_init_creds_opt_set_pa(context, options,
                                            "X509_user_identity", "");
    if (krberr != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "krb5_get_init_creds_opt_set_pa failed [%d], ignored.\n",
              krberr);
    }


    tmp_str = getenv("KRB5_CANONICALIZE");
    if (tmp_str != NULL && strcasecmp(tmp_str, "true") == 0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Will canonicalize principals\n");
        canonicalize = 1;
    }
    sss_krb5_get_init_creds_opt_set_canonicalize(options, canonicalize);

    ccname_file = talloc_asprintf(tmp_ctx, "%s/ccache_%s",
                                  DB_PATH, realm_name);
    if (ccname_file == NULL) {
        krberr = KRB5KRB_ERR_GENERIC;
        *_krb5_msg = talloc_strdup(memctx, strerror(ENOMEM));
        goto done;
    }

    ccname_file_dummy = talloc_asprintf(tmp_ctx, "%s/ccache_%s_XXXXXX",
                                        DB_PATH, realm_name);
    if (ccname_file_dummy == NULL) {
        krberr = KRB5KRB_ERR_GENERIC;
        *_krb5_msg = talloc_strdup(memctx, strerror(ENOMEM));
        goto done;
    }
    global_ccname_file_dummy = ccname_file_dummy;

    ret = sss_unique_filename(tmp_ctx, ccname_file_dummy);
    if (ret != EOK) {
        krberr = KRB5KRB_ERR_GENERIC;
        *_krb5_msg = talloc_asprintf(memctx,
                                     "sss_unique_filename() failed: [%d][%s]",
                                     ret, strerror(ret));
        goto done;
    }

    krberr = krb5_parse_name(context, full_princ, &kprinc);
    if (krberr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_parse_name() failed: %d\n", krberr);
        goto done;
    }
    krberr = krb5_get_init_creds_keytab(context, &my_creds, kprinc,
                                        keytab, 0, NULL, options);
    krb5_free_principal(context, kprinc);
    if (krberr != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "krb5_get_init_creds_keytab() failed: %d\n", krberr);
        goto done;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "credentials initialized\n");
    krb5_kt_close(context, keytab);
    keytab = NULL;

    ccname_dummy = talloc_asprintf(tmp_ctx, "FILE:%s", ccname_file_dummy);
    ccname = talloc_asprintf(tmp_ctx, "FILE:%s", ccname_file);
    if (ccname_dummy == NULL || ccname == NULL) {
        krberr = KRB5KRB_ERR_GENERIC;
        *_krb5_msg = talloc_strdup(memctx, strerror(ENOMEM));
        goto done;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "keytab ccname: [%s]\n", ccname_dummy);

    krberr = krb5_cc_resolve(context, ccname_dummy, &ccache);
    if (krberr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_cc_resolve() failed: %d\n", krberr);
        goto done;
    }

    /* Use updated principal if changed due to canonicalization. */
    krberr = krb5_cc_initialize(context, ccache, my_creds.client);
    if (krberr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_cc_initialize() failed: %d\n", krberr);
        goto done;
    }

    krberr = krb5_cc_store_cred(context, ccache, &my_creds);
    if (krberr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_cc_store_cred() failed: %d\n", krberr);
        goto done;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "credentials stored\n");

#ifdef HAVE_KRB5_GET_TIME_OFFSETS
    krberr = krb5_get_time_offsets(context, &kdc_time_offset,
            &kdc_time_offset_usec);
    if (krberr != 0) {
        const char *__err_msg = sss_krb5_get_error_message(context, krberr);
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get KDC time offset: %s\n",
              __err_msg);
        sss_krb5_free_error_message(context, __err_msg);
        kdc_time_offset = 0;
    } else {
        if (kdc_time_offset_usec > 0) {
            kdc_time_offset++;
        }
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "Got KDC time offset\n");
#else
    /* If we don't have this function, just assume no offset */
    kdc_time_offset = 0;
#endif

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Renaming [%s] to [%s]\n", ccname_file_dummy, ccname_file);
    ret = rename(ccname_file_dummy, ccname_file);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "rename failed [%d][%s].\n", ret, strerror(ret));
        krberr = KRB5KRB_ERR_GENERIC;
        *_krb5_msg = talloc_asprintf(memctx,
                                     "rename() failed: [%d][%s]",
                                     ret, strerror(ret));

        goto done;
    }
    global_ccname_file_dummy = NULL;

    krberr = 0;
    *ccname_out = talloc_steal(memctx, ccname);
    *expire_time_out = my_creds.times.endtime - kdc_time_offset;

done:
    krb5_get_init_creds_opt_free(context, options);
    if (krberr != 0) {
        if (*_krb5_msg == NULL) {
            /* no custom error message provided hence get one from libkrb5 */
            const char *__krberr_msg = sss_krb5_get_error_message(context, krberr);
            *_krb5_msg = talloc_strdup(memctx, __krberr_msg);
            sss_krb5_free_error_message(context, __krberr_msg);
        }

        sss_log(SSS_LOG_ERR,
                "Failed to initialize credentials using keytab [%s]: %s. "
                "Unable to create GSSAPI-encrypted LDAP connection.",
                sss_printable_keytab_name(context, keytab_name), *_krb5_msg);

        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to initialize credentials using keytab [%s]: %s. "
              "Unable to create GSSAPI-encrypted LDAP connection.\n",
              sss_printable_keytab_name(context, keytab_name), *_krb5_msg);
    }
    if (keytab) krb5_kt_close(context, keytab);
    if (context) krb5_free_context(context);
    talloc_free(tmp_ctx);
    return krberr;
}

static int prepare_select_principal_response(TALLOC_CTX *mem_ctx,
                                             const char *sasl_primary,
                                             const char *sasl_realm,
                                             struct io_buffer **rsp)
{
    size_t p = 0;
    size_t len_primary, len_realm;
    struct io_buffer *r = NULL;

    r = talloc_zero(mem_ctx, struct io_buffer);
    if (r == NULL) {
        return ENOMEM;
    }

    len_primary = strlen(sasl_primary);
    len_realm = strlen(sasl_realm);
    r->size = 2 * sizeof(uint32_t) + len_primary + len_realm;

    r->data = talloc_array(r, uint8_t, r->size);
    if (r->data == NULL) {
        talloc_free(r);
        return ENOMEM;
    }

    SAFEALIGN_SET_UINT32(&r->data[p], len_primary, &p);
    safealign_memcpy(&r->data[p], sasl_primary, len_primary, &p);

    SAFEALIGN_SET_UINT32(&r->data[p], len_realm, &p);
    safealign_memcpy(&r->data[p], sasl_realm, len_realm, &p);

    DEBUG(SSSDBG_TRACE_LIBS, "result: '%s', '%s'\n", sasl_primary, sasl_realm);

    *rsp = r;
    return EOK;
}

static int prepare_get_tgt_response(TALLOC_CTX *mem_ctx,
                                    const char *ccname,
                                    time_t expire_time,
                                    krb5_error_code kerr,
                                    char *krb5_msg,
                                    struct io_buffer **rsp)
{
    int ret;
    struct io_buffer *r = NULL;

    r = talloc_zero(mem_ctx, struct io_buffer);
    if (r == NULL) {
        return ENOMEM;
    }

    r->data = NULL;
    r->size = 0;

    DEBUG(SSSDBG_TRACE_FUNC, "Building GET_TGT response for result [%d]\n", kerr);

    if (kerr == 0) {
        ret = pack_buffer(r, EOK, kerr, ccname, expire_time);
    } else {
        if (krb5_msg == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Empty krb5 error message for non-zero kerr: %"PRIi32"\n",
                  kerr);
            return ENOMEM;
        }
        ret = pack_buffer(r, EFAULT, kerr, krb5_msg, 0);
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pack_buffer failed\n");
        return ret;
    }

    *rsp = r;
    return EOK;
}

static krb5_error_code privileged_krb5_setup(struct input_buffer *ibuf)
{
    krb5_error_code kerr;
    char *keytab_name;

    kerr = sss_krb5_init_context(&ibuf->context);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to init kerberos context\n");
        return kerr;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "Kerberos context initialized\n");

    sss_set_cap_effective(CAP_DAC_READ_SEARCH, true);
    kerr = copy_keytab_into_memory(ibuf, ibuf->context, ibuf->keytab_name,
                                   &keytab_name, NULL);
    sss_drop_all_caps();
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "copy_keytab_into_memory failed.\n");
        return kerr;
    }
    talloc_free(ibuf->keytab_name);
    ibuf->keytab_name = keytab_name;

    return 0;
}

static errno_t handle_select_principal(TALLOC_CTX *mem_ctx,
                                       const struct input_buffer *ibuf,
                                       struct io_buffer **resp)
{
    int ret;
    char *sasl_primary = NULL;
    char *sasl_realm = NULL;

    sss_set_cap_effective(CAP_DAC_READ_SEARCH, true);
    ret = select_principal_from_keytab(mem_ctx,
                                       ibuf->princ_str, ibuf->realm_str,
                                       ibuf->keytab_name,
                                       NULL, &sasl_primary, &sasl_realm);
    sss_drop_all_caps();
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "select_principal_from_keytab() failed\n");
        return ret;
    }

    ret = prepare_select_principal_response(mem_ctx, sasl_primary, sasl_realm, resp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "prepare_select_principal_response() failed\n");
        return ret;
    }

    return EOK;
}

static errno_t handle_get_tgt(TALLOC_CTX *mem_ctx,
                              struct input_buffer *ibuf,
                              struct io_buffer **resp)
{
    int kerr;
    const char *ccname = NULL;
    char *krb5_msg = NULL;
    time_t expire_time = 0;

    kerr = privileged_krb5_setup(ibuf);
    if (kerr != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "privileged_krb5_setup() failed.\n");
        return kerr;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Kerberos context initialized\n");

    sss_log_process_caps("Running");

    DEBUG(SSSDBG_TRACE_INTERNAL, "getting TGT sync\n");
    kerr = ldap_child_get_tgt_sync(mem_ctx, ibuf->context,
                                   ibuf->realm_str, ibuf->princ_str,
                                   ibuf->keytab_name, ibuf->lifetime,
                                   &ccname, &expire_time, &krb5_msg);
    if (kerr != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ldap_child_get_tgt_sync() failed.\n");
        /* Do not return, must report failure */
    }

    kerr = prepare_get_tgt_response(mem_ctx, ccname, expire_time, kerr, krb5_msg,
                                    resp);
    if (kerr != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "prepare_get_tgt_response() failed.\n");
        return kerr;
    }

    return EOK;
}

int main(int argc, const char *argv[])
{
    static const size_t IN_BUF_SIZE = 2048;
    int ret;
    int opt;
    int dummy = 1;
    int backtrace = 1;
    int debug_fd = -1;
    long dummy_chain_id;
    const char *opt_logger = NULL;
    poptContext pc;
    TALLOC_CTX *main_ctx = NULL;
    uint8_t *buf = NULL;
    ssize_t len = 0;
    struct input_buffer *ibuf = NULL;
    struct io_buffer *resp = NULL;
    ssize_t written;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"dumpable", 0, POPT_ARG_INT, &dummy, 0,
         _("Ignored, /proc/sys/fs/suid_dumpable setting is in force"), NULL },
        {"backtrace", 0, POPT_ARG_INT, &backtrace, 0,
         _("Enable debug backtrace"), NULL },
        {"chain-id", 0, POPT_ARG_LONG, &dummy_chain_id,
         0, _("Tevent chain ID used for logging purposes"), NULL},
        {"debug-fd", 0, POPT_ARG_INT, &debug_fd, 0,
         _("An open file descriptor for the debug logs"), NULL},
        SSSD_LOGGER_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
        fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            _exit(-1);
        }
    }

    poptFreeContext(pc);

    /* Don't touch PR_SET_DUMPABLE as 'ldap_child' handles host keytab.
     * Rely on system settings instead: this flag "is reset to the
     * current value contained in the file /proc/sys/fs/suid_dumpable"
     * when "the process executes a program that has file capabilities".
     */

    debug_prg_name = talloc_asprintf(NULL, "ldap_child[%d]", getpid());
    if (!debug_prg_name) {
        debug_prg_name = "ldap_child";
        ERROR("talloc_asprintf failed.\n");
        goto fail;
    }

    if (debug_fd != -1) {
        opt_logger = sss_logger_str[FILES_LOGGER];
        ret = set_debug_file_from_fd(debug_fd);
        if (ret != EOK) {
            opt_logger = sss_logger_str[STDERR_LOGGER];
            ERROR("set_debug_file_from_fd failed.\n");
        }
    }

    DEBUG_INIT(debug_level, opt_logger);
    sss_set_debug_backtrace_enable((backtrace == 0) ? false : true);

    BlockSignals(false, SIGTERM);
    CatchSignal(SIGTERM, sig_term_handler);

    sss_log_process_caps("Starting");

    main_ctx = talloc_new(NULL);
    if (main_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        talloc_free(discard_const(debug_prg_name));
        goto fail;
    }
    talloc_steal(main_ctx, debug_prg_name);

    buf = talloc_size(main_ctx, sizeof(uint8_t)*IN_BUF_SIZE);
    if (buf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        goto fail;
    }

    ibuf = talloc_zero(main_ctx, struct input_buffer);
    if (ibuf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "context initialized\n");

    errno = 0;
    len = sss_atomic_read_s(STDIN_FILENO, buf, IN_BUF_SIZE);
    if (len == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "read failed [%d][%s].\n", ret, strerror(ret));
        goto fail;
    }

    close(STDIN_FILENO);

    ret = unpack_buffer(buf, len, ibuf);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "unpack_buffer failed.[%d][%s].\n", ret, strerror(ret));
        goto fail;
    }

    if (ibuf->cmd == LDAP_CHILD_SELECT_PRINCIPAL) {
        ret = handle_select_principal(main_ctx, ibuf, &resp);
        if (ret != 0) {
            goto fail;
        }
    } else if (ibuf->cmd == LDAP_CHILD_GET_TGT) {
        ret = handle_get_tgt(main_ctx, ibuf, &resp);
        if (ret != 0) {
            goto fail;
        }
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected command [%d]\n", ibuf->cmd);
        goto fail;
    }

    errno = 0;
    written = sss_atomic_write_s(STDOUT_FILENO, resp->data, resp->size);
    if (written == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "write failed [%d][%s].\n", ret,
                    strerror(ret));
        goto fail;
    }

    if (written != resp->size) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Expected to write %zu bytes, wrote %zu\n",
              resp->size, written);
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "ldap_child completed successfully\n");
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    _exit(0);

fail:
    DEBUG(SSSDBG_CRIT_FAILURE, "ldap_child failed!\n");
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    _exit(-1);
}
