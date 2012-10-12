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
#include <sys/stat.h>
#include <popt.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "util/sss_krb5.h"
#include "util/child_common.h"
#include "providers/dp_backend.h"

static krb5_context krb5_error_ctx;
#define LDAP_CHILD_DEBUG(level, error) KRB5_DEBUG(level, krb5_error_ctx, error)

static const char *__ldap_child_krb5_error_msg;
#define KRB5_SYSLOG(krb5_error) do { \
    __ldap_child_krb5_error_msg = sss_krb5_get_error_message(krb5_error_ctx, krb5_error); \
    sss_log(SSS_LOG_ERR, "%s", __ldap_child_krb5_error_msg); \
    sss_krb5_free_error_message(krb5_error_ctx, __ldap_child_krb5_error_msg); \
} while(0)

struct input_buffer {
    const char *realm_str;
    const char *princ_str;
    const char *keytab_name;
    krb5_deltat lifetime;
};

static errno_t unpack_buffer(uint8_t *buf, size_t size,
                             struct input_buffer *ibuf)
{
    size_t p = 0;
    uint32_t len;

    DEBUG(SSSDBG_TRACE_LIBS, ("total buffer size: %d\n", size));

    /* realm_str size and length */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    DEBUG(SSSDBG_TRACE_LIBS, ("realm_str size: %d\n", len));
    if (len) {
        if ((p + len ) > size) return EINVAL;
        ibuf->realm_str = talloc_strndup(ibuf, (char *)(buf + p), len);
        DEBUG(SSSDBG_TRACE_LIBS, ("got realm_str: %s\n", ibuf->realm_str));
        if (ibuf->realm_str == NULL) return ENOMEM;
        p += len;
    }

    /* princ_str size and length */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    DEBUG(SSSDBG_TRACE_LIBS, ("princ_str size: %d\n", len));
    if (len) {
        if ((p + len ) > size) return EINVAL;
        ibuf->princ_str = talloc_strndup(ibuf, (char *)(buf + p), len);
        DEBUG(SSSDBG_TRACE_LIBS, ("got princ_str: %s\n", ibuf->princ_str));
        if (ibuf->princ_str == NULL) return ENOMEM;
        p += len;
    }

    /* keytab_name size and length */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    DEBUG(SSSDBG_TRACE_LIBS, ("keytab_name size: %d\n", len));
    if (len) {
        if ((p + len ) > size) return EINVAL;
        ibuf->keytab_name = talloc_strndup(ibuf, (char *)(buf + p), len);
        DEBUG(SSSDBG_TRACE_LIBS, ("got keytab_name: %s\n", ibuf->keytab_name));
        if (ibuf->keytab_name == NULL) return ENOMEM;
        p += len;
    }

    /* ticket lifetime */
    SAFEALIGN_COPY_INT32_CHECK(&ibuf->lifetime, buf + p, size, &p);
    DEBUG(SSSDBG_TRACE_LIBS, ("lifetime: %d\n", ibuf->lifetime));

    return EOK;
}

static int pack_buffer(struct response *r, int result, krb5_error_code krberr,
                       const char *msg, time_t expire_time)
{
    int len;
    size_t p = 0;

    len = strlen(msg);
    r->size = 2 * sizeof(uint32_t) + sizeof(krb5_error_code) +
              len + sizeof(time_t);

    DEBUG(SSSDBG_TRACE_INTERNAL, ("response size: %d\n",r->size));

    r->buf = talloc_array(r, uint8_t, r->size);
    if(!r->buf) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          ("result [%d] krberr [%d] msgsize [%d] msg [%s]\n",
           result, krberr, len, msg));

    /* result */
    SAFEALIGN_SET_UINT32(&r->buf[p], result, &p);

    /* krb5 error code */
    safealign_memcpy(&r->buf[p], &krberr, sizeof(krberr), &p);

    /* message size */
    SAFEALIGN_SET_UINT32(&r->buf[p], len, &p);

    /* message itself */
    safealign_memcpy(&r->buf[p], msg, len, &p);

    /* ticket expiration time */
    safealign_memcpy(&r->buf[p], &expire_time, sizeof(expire_time), &p);

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

static krb5_error_code ldap_child_get_tgt_sync(TALLOC_CTX *memctx,
                                               const char *realm_str,
                                               const char *princ_str,
                                               const char *keytab_name,
                                               const krb5_deltat lifetime,
                                               const char **ccname_out,
                                               time_t *expire_time_out)
{
    char *ccname;
    char *realm_name = NULL;
    char *full_princ = NULL;
    char *default_realm = NULL;
    char *tmp_str = NULL;
    krb5_context context = NULL;
    krb5_keytab keytab = NULL;
    krb5_ccache ccache = NULL;
    krb5_principal kprinc;
    krb5_creds my_creds;
    krb5_get_init_creds_opt options;
    krb5_error_code krberr;
    krb5_timestamp kdc_time_offset;
    int canonicalize = 0;
    int kdc_time_offset_usec;
    int ret;

    krberr = krb5_init_context(&context);
    if (krberr) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to init kerberos context\n"));
        return krberr;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, ("Kerberos context initialized\n"));

    krberr = set_child_debugging(context);
    if (krberr != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Cannot set krb5_child debugging\n"));
    }

    if (!realm_str) {
        krberr = krb5_get_default_realm(context, &default_realm);
        if (krberr) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to get default realm name: %s\n",
                      sss_krb5_get_error_message(context, krberr)));
            goto done;
        }

        realm_name = talloc_strdup(memctx, default_realm);
        krb5_free_default_realm(context, default_realm);
        if (!realm_name) {
            krberr = KRB5KRB_ERR_GENERIC;
            goto done;
        }
    } else {
        realm_name = talloc_strdup(memctx, realm_str);
        if (!realm_name) {
            krberr = KRB5KRB_ERR_GENERIC;
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, ("got realm_name: [%s]\n", realm_name));

    if (princ_str) {
        if (!strchr(princ_str, '@')) {
            full_princ = talloc_asprintf(memctx, "%s@%s",
                                         princ_str, realm_name);
        } else {
            full_princ = talloc_strdup(memctx, princ_str);
        }
    } else {
        char hostname[512];

        ret = gethostname(hostname, 511);
        if (ret == -1) {
            krberr = KRB5KRB_ERR_GENERIC;
            goto done;
        }
        hostname[511] = '\0';

        DEBUG(SSSDBG_TRACE_LIBS, ("got hostname: [%s]\n", hostname));

        ret = select_principal_from_keytab(memctx, hostname, realm_name,
                keytab_name, &full_princ, NULL, NULL);
        if (ret) goto done;
    }
    if (!full_princ) {
        krberr = KRB5KRB_ERR_GENERIC;
        goto done;
    }
    DEBUG(SSSDBG_CONF_SETTINGS, ("Principal name is: [%s]\n", full_princ));

    krberr = krb5_parse_name(context, full_princ, &kprinc);
    if (krberr) {
        DEBUG(2, ("Unable to build principal: %s\n",
                  sss_krb5_get_error_message(context, krberr)));
        goto done;
    }

    if (keytab_name) {
        krberr = krb5_kt_resolve(context, keytab_name, &keytab);
    } else {
        krberr = krb5_kt_default(context, &keytab);
    }
    DEBUG(SSSDBG_CONF_SETTINGS, ("Using keytab [%s]\n", KEYTAB_CLEAN_NAME));
    if (krberr) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Failed to read keytab file [%s]: %s\n",
               KEYTAB_CLEAN_NAME,
               sss_krb5_get_error_message(context, krberr)));
        goto done;
    }

    /* Verify the keytab */
    ret = sss_krb5_verify_keytab_ex(full_princ, keytab_name, context, keytab);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
                ("Unable to verify principal is present in the keytab\n"));
        krberr = KRB5_KT_IOERR;
        goto done;
    }

    ccname = talloc_asprintf(memctx, "FILE:%s/ccache_%s", DB_PATH, realm_name);
    if (!ccname) {
        krberr = KRB5KRB_ERR_GENERIC;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, ("keytab ccname: [%s]\n", ccname));

    krberr = krb5_cc_resolve(context, ccname, &ccache);
    if (krberr) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to set cache name: %s\n",
                  sss_krb5_get_error_message(context, krberr)));
        goto done;
    }

    memset(&my_creds, 0, sizeof(my_creds));
    memset(&options, 0, sizeof(options));

    krb5_get_init_creds_opt_set_address_list(&options, NULL);
    krb5_get_init_creds_opt_set_forwardable(&options, 0);
    krb5_get_init_creds_opt_set_proxiable(&options, 0);
    krb5_get_init_creds_opt_set_tkt_life(&options, lifetime);

    tmp_str = getenv("KRB5_CANONICALIZE");
    if (tmp_str != NULL && strcasecmp(tmp_str, "true") == 0) {
        DEBUG(SSSDBG_CONF_SETTINGS, ("Will canonicalize principals\n"));
        canonicalize = 1;
    }
    sss_krb5_get_init_creds_opt_set_canonicalize(&options, canonicalize);

    krberr = krb5_get_init_creds_keytab(context, &my_creds, kprinc,
                                        keytab, 0, NULL, &options);
    if (krberr) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Failed to init credentials: %s\n",
               sss_krb5_get_error_message(context, krberr)));
        sss_log(SSS_LOG_ERR,
                "Failed to initialize credentials using keytab [%s]: %s. "
                "Unable to create GSSAPI-encrypted LDAP connection.",
                KEYTAB_CLEAN_NAME,
                sss_krb5_get_error_message(context, krberr));
        goto done;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, ("credentials initialized\n"));

    /* Use updated principal if changed due to canonicalization. */
    krberr = krb5_cc_initialize(context, ccache, my_creds.client);
    if (krberr) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to init ccache: %s\n",
                  sss_krb5_get_error_message(context, krberr)));
        goto done;
    }

    krberr = krb5_cc_store_cred(context, ccache, &my_creds);
    if (krberr) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to store creds: %s\n",
                  sss_krb5_get_error_message(context, krberr)));
        goto done;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, ("credentials stored\n"));

#ifdef HAVE_KRB5_GET_TIME_OFFSETS
    krberr = krb5_get_time_offsets(context, &kdc_time_offset,
            &kdc_time_offset_usec);
    if (krberr) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to get KDC time offset: %s\n",
                  sss_krb5_get_error_message(context, krberr)));
        kdc_time_offset = 0;
    } else {
        if (kdc_time_offset_usec > 0) {
            kdc_time_offset++;
        }
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, ("Got KDC time offset\n"));
#else
    /* If we don't have this function, just assume no offset */
    kdc_time_offset = 0;
#endif

    krberr = 0;
    *ccname_out = ccname;
    *expire_time_out = my_creds.times.endtime - kdc_time_offset;

done:
    if (krberr != 0) KRB5_SYSLOG(krberr);
    if (keytab) krb5_kt_close(context, keytab);
    if (context) krb5_free_context(context);
    return krberr;
}

static int prepare_response(TALLOC_CTX *mem_ctx,
                            const char *ccname,
                            time_t expire_time,
                            krb5_error_code kerr,
                            struct response **rsp)
{
    int ret;
    struct response *r = NULL;
    const char *krb5_msg = NULL;

    r = talloc_zero(mem_ctx, struct response);
    if (!r) return ENOMEM;

    r->buf = NULL;
    r->size = 0;

    DEBUG(SSSDBG_TRACE_FUNC, ("Building response for result [%d]\n", kerr));

    if (kerr == 0) {
        ret = pack_buffer(r, EOK, kerr, ccname, expire_time);
    } else {
        krb5_msg = sss_krb5_get_error_message(krb5_error_ctx, kerr);
        if (krb5_msg == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                    ("sss_krb5_get_error_message failed.\n"));
            return ENOMEM;
        }

        ret = pack_buffer(r, EFAULT, kerr, krb5_msg, 0);
        sss_krb5_free_error_message(krb5_error_ctx, krb5_msg);
    }

    if (ret != EOK) {
        DEBUG(1, ("pack_buffer failed\n"));
        return ret;
    }

    *rsp = r;
    return EOK;
}

int main(int argc, const char *argv[])
{
    int ret;
    int kerr;
    int opt;
    int debug_fd = -1;
    poptContext pc;
    TALLOC_CTX *main_ctx = NULL;
    uint8_t *buf = NULL;
    ssize_t len = 0;
    const char *ccname = NULL;
    time_t expire_time = 0;
    struct input_buffer *ibuf = NULL;
    struct response *resp = NULL;
    size_t written;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"debug-level", 'd', POPT_ARG_INT, &debug_level, 0,
         _("Debug level"), NULL},
        {"debug-timestamps", 0, POPT_ARG_INT, &debug_timestamps, 0,
         _("Add debug timestamps"), NULL},
        {"debug-microseconds", 0, POPT_ARG_INT, &debug_microseconds, 0,
         _("Show timestamps with microseconds"), NULL},
        {"debug-fd", 0, POPT_ARG_INT, &debug_fd, 0,
         _("An open file descriptor for the debug logs"), NULL},
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

    CONVERT_AND_SET_DEBUG_LEVEL(debug_level);

    debug_prg_name = talloc_asprintf(NULL, "[sssd[ldap_child[%d]]]", getpid());
    if (!debug_prg_name) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_asprintf failed.\n"));
        goto fail;
    }

    if (debug_fd != -1) {
        ret = set_debug_file_from_fd(debug_fd);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("set_debug_file_from_fd failed.\n"));
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("ldap_child started.\n"));

    main_ctx = talloc_new(NULL);
    if (main_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new failed.\n"));
        talloc_free(discard_const(debug_prg_name));
        goto fail;
    }
    talloc_steal(main_ctx, debug_prg_name);

    buf = talloc_size(main_ctx, sizeof(uint8_t)*IN_BUF_SIZE);
    if (buf == NULL) {
        DEBUG(1, ("talloc_size failed.\n"));
        goto fail;
    }

    ibuf = talloc_zero(main_ctx, struct input_buffer);
    if (ibuf == NULL) {
        DEBUG(1, ("talloc_size failed.\n"));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, ("context initialized\n"));

    errno = 0;
    len = sss_atomic_read_s(STDIN_FILENO, buf, IN_BUF_SIZE);
    if (len == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, ("read failed [%d][%s].\n", ret, strerror(ret)));
        goto fail;
    }

    close(STDIN_FILENO);

    ret = unpack_buffer(buf, len, ibuf);
    if (ret != EOK) {
        DEBUG(1, ("unpack_buffer failed.[%d][%s].\n", ret, strerror(ret)));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, ("getting TGT sync\n"));
    kerr = ldap_child_get_tgt_sync(main_ctx,
                                   ibuf->realm_str, ibuf->princ_str,
                                   ibuf->keytab_name, ibuf->lifetime,
                                   &ccname, &expire_time);
    if (kerr != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("ldap_child_get_tgt_sync failed.\n"));
        /* Do not return, must report failure */
    }

    ret = prepare_response(main_ctx, ccname, expire_time, kerr, &resp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("prepare_response failed. [%d][%s].\n",
                    ret, strerror(ret)));
        goto fail;
    }

    errno = 0;
    written = sss_atomic_write_s(STDOUT_FILENO, resp->buf, resp->size);
    if (written == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, ("write failed [%d][%s].\n", ret,
                    strerror(ret)));
        goto fail;
    }

    if (written != resp->size) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Expected to write %d bytes, wrote %d\n",
              resp->size, written));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("ldap_child completed successfully\n"));
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    _exit(0);

fail:
    DEBUG(SSSDBG_CRIT_FAILURE, ("ldap_child failed!\n"));
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    _exit(-1);
}
