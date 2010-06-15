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
#include "providers/child_common.h"
#include "providers/dp_backend.h"

static krb5_context krb5_error_ctx;

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

    DEBUG(7, ("total buffer size: %d\n", size));

    /* realm_str size and length */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    DEBUG(7, ("realm_str size: %d\n", len));
    if (len) {
        if ((p + len ) > size) return EINVAL;
        ibuf->realm_str = talloc_strndup(ibuf, (char *)(buf + p), len);
        DEBUG(7, ("got realm_str: %s\n", ibuf->realm_str));
        if (ibuf->realm_str == NULL) return ENOMEM;
        p += len;
    }

    /* princ_str size and length */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    DEBUG(7, ("princ_str size: %d\n", len));
    if (len) {
        if ((p + len ) > size) return EINVAL;
        ibuf->princ_str = talloc_strndup(ibuf, (char *)(buf + p), len);
        DEBUG(7, ("got princ_str: %s\n", ibuf->princ_str));
        if (ibuf->princ_str == NULL) return ENOMEM;
        p += len;
    }

    /* keytab_name size and length */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    DEBUG(7, ("keytab_name size: %d\n", len));
    if (len) {
        if ((p + len ) > size) return EINVAL;
        ibuf->keytab_name = talloc_strndup(ibuf, (char *)(buf + p), len);
        DEBUG(7, ("got keytab_name: %s\n", ibuf->keytab_name));
        if (ibuf->keytab_name == NULL) return ENOMEM;
        p += len;
    }

    /* ticket lifetime */
    SAFEALIGN_COPY_INT32_CHECK(&ibuf->lifetime, buf + p, size, &p);
    DEBUG(7, ("lifetime: %d\n", ibuf->lifetime));

    return EOK;
}

static int pack_buffer(struct response *r, int result, const char *msg)
{
    int len;
    size_t p = 0;

    len = strlen(msg);
    r->size = 2 * sizeof(uint32_t) + len;

    r->buf = talloc_array(r, uint8_t, r->size);
    if(!r->buf) {
        return ENOMEM;
    }

    /* result */
    SAFEALIGN_SET_UINT32(&r->buf[p], result, &p);

    /* message size */
    SAFEALIGN_SET_UINT32(&r->buf[p], len, &p);

    /* message itself */
    safealign_memcpy(&r->buf[p], msg, len, &p);

    return EOK;
}

static int ldap_child_get_tgt_sync(TALLOC_CTX *memctx,
                                  const char *realm_str,
                                  const char *princ_str,
                                  const char *keytab_name,
                                  const krb5_deltat lifetime,
                                  const char **ccname_out)
{
    char *ccname;
    char *realm_name = NULL;
    char *full_princ = NULL;
    krb5_context context = NULL;
    krb5_keytab keytab = NULL;
    krb5_ccache ccache = NULL;
    krb5_principal kprinc;
    krb5_creds my_creds;
    krb5_get_init_creds_opt options;
    krb5_error_code krberr;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    char *principal;
    bool found;
    int ret;

    krberr = krb5_init_context(&context);
    if (krberr) {
        DEBUG(2, ("Failed to init kerberos context\n"));
        return EFAULT;
    }

    if (!realm_str) {
        krberr = krb5_get_default_realm(context, &realm_name);
        if (krberr) {
            DEBUG(2, ("Failed to get default realm name: %s\n",
                      sss_krb5_get_error_message(context, krberr)));
            ret = EFAULT;
            goto done;
        }
    } else {
        realm_name = talloc_strdup(memctx, realm_str);
        if (!realm_name) {
            ret = ENOMEM;
            goto done;
        }
    }

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
            ret = errno;
            goto done;
        }
        hostname[511] = '\0';

        full_princ = talloc_asprintf(memctx, "host/%s@%s",
                                     hostname, realm_name);
    }
    if (!full_princ) {
        ret = ENOMEM;
        goto done;
    }
    DEBUG(4, ("Principal name is: [%s]\n", full_princ));

    krberr = krb5_parse_name(context, full_princ, &kprinc);
    if (krberr) {
        DEBUG(2, ("Unable to build principal: %s\n",
                  sss_krb5_get_error_message(context, krberr)));
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

    /* Verify the keytab */
    krberr = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (krberr) {
        DEBUG(0, ("Cannot read keytab [%s].\n", keytab_name));

        sss_log(SSS_LOG_ERR, "Error reading keytab file [%s]: [%d][%s]. "
                             "Unable to create GSSAPI-encrypted LDAP connection.",
                             keytab_name, krberr,
                             sss_krb5_get_error_message(context, krberr));

        ret = EFAULT;
        goto done;
    }

    found = false;
    while((ret = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0){
        krb5_unparse_name(context, entry.principal, &principal);
        if (strcmp(full_princ, principal) == 0) {
            found = true;
        }
        free(principal);
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
        ret = EFAULT;
        goto done;
    }

    if (!found) {
        DEBUG(0, ("Principal [%s] not found in keytab [%s]\n",
                  full_princ, keytab_name));
        sss_log(SSS_LOG_ERR, "Error processing keytab file [%s]: "
                             "Principal [%s] was not found. "
                             "Unable to create GSSAPI-encrypted LDAP connection.",
                             keytab_name, full_princ);

        ret = EFAULT;
        goto done;
    }

    ccname = talloc_asprintf(memctx, "FILE:%s/ccache_%s", DB_PATH, realm_name);
    if (!ccname) {
        ret = ENOMEM;
        goto done;
    }

    krberr = krb5_cc_resolve(context, ccname, &ccache);
    if (krberr) {
        DEBUG(2, ("Failed to set cache name: %s\n",
                  sss_krb5_get_error_message(context, krberr)));
        ret = EFAULT;
        goto done;
    }

    memset(&my_creds, 0, sizeof(my_creds));
    memset(&options, 0, sizeof(options));

    krb5_get_init_creds_opt_set_address_list(&options, NULL);
    krb5_get_init_creds_opt_set_forwardable(&options, 0);
    krb5_get_init_creds_opt_set_proxiable(&options, 0);
    krb5_get_init_creds_opt_set_tkt_life(&options, lifetime);

    krberr = krb5_get_init_creds_keytab(context, &my_creds, kprinc,
                                        keytab, 0, NULL, &options);

    if (krberr) {
        DEBUG(0, ("Failed to init credentials: %s\n",
                  sss_krb5_get_error_message(context, krberr)));
        sss_log(SSS_LOG_ERR, "Failed to initialize credentials using keytab [%s]: %s. "
                             "Unable to create GSSAPI-encrypted LDAP connection.",
                             keytab_name, sss_krb5_get_error_message(context, krberr));
        ret = EFAULT;
        goto done;
    }

    krberr = krb5_cc_initialize(context, ccache, kprinc);
    if (krberr) {
        DEBUG(2, ("Failed to init ccache: %s\n",
                  sss_krb5_get_error_message(context, krberr)));
        ret = EFAULT;
        goto done;
    }

    krberr = krb5_cc_store_cred(context, ccache, &my_creds);
    if (krberr) {
        DEBUG(2, ("Failed to store creds: %s\n",
                  sss_krb5_get_error_message(context, krberr)));
        ret = EFAULT;
        goto done;
    }

    ret = EOK;
    *ccname_out = ccname;

done:
    if (keytab) krb5_kt_close(context, keytab);
    if (context) krb5_free_context(context);
    return ret;
}

static int prepare_response(TALLOC_CTX *mem_ctx,
                            const char *ccname,
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

    if (kerr == 0) {
        ret = pack_buffer(r, EOK, ccname);
    } else {
        krb5_msg = sss_krb5_get_error_message(krb5_error_ctx, kerr);
        if (krb5_msg == NULL) {
            DEBUG(1, ("sss_krb5_get_error_message failed.\n"));
            return ENOMEM;
        }

        ret = pack_buffer(r, EFAULT, krb5_msg);
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
    TALLOC_CTX *main_ctx;
    uint8_t *buf = NULL;
    ssize_t len = 0;
    const char *ccname = NULL;
    struct input_buffer *ibuf = NULL;
    struct response *resp = NULL;
    size_t written;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"debug-level", 'd', POPT_ARG_INT, &debug_level, 0,
         _("Debug level"), NULL},
        {"debug-timestamps", 0, POPT_ARG_INT, &debug_timestamps, 0,
         _("Add debug timestamps"), NULL},
        {"debug-fd", 0, POPT_ARG_INT, &debug_fd, 0,
         _("An open file descriptor for the debug logs"), NULL},
        POPT_TABLEEND
    };

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

    DEBUG(7, ("ldap_child started.\n"));

    main_ctx = talloc_new(NULL);
    if (main_ctx == NULL) {
        DEBUG(1, ("talloc_new failed.\n"));
        _exit(-1);
    }

    debug_prg_name = talloc_asprintf(main_ctx, "[sssd[ldap_child[%d]]]", getpid());

    if (debug_fd != -1) {
        ret = set_debug_file_from_fd(debug_fd);
        if (ret != EOK) {
            DEBUG(1, ("set_debug_file_from_fd failed.\n"));
        }
    }

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

    while ((ret = read(STDIN_FILENO, buf + len, IN_BUF_SIZE - len)) != 0) {
        if (ret == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            DEBUG(1, ("read failed [%d][%s].\n", errno, strerror(errno)));
            goto fail;
        } else if (ret > 0) {
            len += ret;
            if (len > IN_BUF_SIZE) {
                DEBUG(1, ("read too much, this should never happen.\n"));
                goto fail;
            }
            continue;
        } else {
            DEBUG(1, ("unexpected return code of read [%d].\n", ret));
            goto fail;
        }
    }
    close(STDIN_FILENO);

    ret = unpack_buffer(buf, len, ibuf);
    if (ret != EOK) {
        DEBUG(1, ("unpack_buffer failed.[%d][%s].\n", ret, strerror(ret)));
        goto fail;
    }

    kerr = ldap_child_get_tgt_sync(main_ctx,
                                   ibuf->realm_str, ibuf->princ_str,
                                   ibuf->keytab_name, ibuf->lifetime, &ccname);
    if (kerr != EOK) {
        DEBUG(1, ("ldap_child_get_tgt_sync failed.\n"));
        /* Do not return, must report failure */
    }

    ret = prepare_response(main_ctx, ccname, kerr, &resp);
    if (ret != EOK) {
        DEBUG(1, ("prepare_response failed. [%d][%s].\n", ret, strerror(ret)));
        return ENOMEM;
    }

    written = 0;
    while (written < resp->size) {
        ret = write(STDOUT_FILENO, resp->buf + written, resp->size - written);
        if (ret == -1) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            ret = errno;
            DEBUG(1, ("write failed [%d][%s].\n", ret, strerror(ret)));
            return ret;
        }
        written += ret;
    }

    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    _exit(0);

fail:
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    _exit(-1);
}
