/*
    SSSD

    Kerberos 5 Backend Module -- tgt_req and changepw child

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

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <popt.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "util/sss_krb5.h"
#include "util/user_info_msg.h"
#include "util/child_common.h"
#include "providers/dp_backend.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_utils.h"

#define SSSD_KRB5_CHANGEPW_PRINCIPAL "kadmin/changepw"

struct krb5_child_ctx {
    /* opts taken from kinit */
    /* in seconds */
    krb5_deltat starttime;
    krb5_deltat lifetime;
    krb5_deltat rlife;

    int forwardable;
    int proxiable;
    int addresses;

    int not_forwardable;
    int not_proxiable;
    int no_addresses;

    int verbose;

    char* principal_name;
    char* service_name;
    char* keytab_name;
    char* k5_cache_name;
    char* k4_cache_name;

    action_type action;

    char *kdcip;
    char *realm;
    char *ccache_dir;
    char *ccname_template;
    int auth_timeout;

    int child_debug_fd;
};

struct krb5_req {
    krb5_context ctx;
    krb5_principal princ;
    char* name;
    krb5_creds *creds;
    krb5_get_init_creds_opt *options;
    pid_t child_pid;
    int read_from_child_fd;
    int write_to_child_fd;

    struct be_req *req;
    struct pam_data *pd;
    struct krb5_child_ctx *krb5_ctx;
    errno_t (*child_req)(int fd, struct krb5_req *kr);

    char *ccname;
    char *keytab;
    bool validate;
    char *fast_ccname;

    const char *upn;
    uid_t uid;
    gid_t gid;
};

static krb5_context krb5_error_ctx;
static const char *__krb5_error_msg;
#define KRB5_DEBUG(level, krb5_error) do { \
    __krb5_error_msg = sss_krb5_get_error_message(krb5_error_ctx, krb5_error); \
    DEBUG(level, ("%d: [%d][%s]\n", __LINE__, krb5_error, __krb5_error_msg)); \
    sss_log(SSS_LOG_ERR, "%s", __krb5_error_msg); \
    sss_krb5_free_error_message(krb5_error_ctx, __krb5_error_msg); \
} while(0)

static void sss_krb5_expire_callback_func(krb5_context context, void *data,
                                          krb5_timestamp password_expiration,
                                          krb5_timestamp account_expiration,
                                          krb5_boolean is_last_req)
{
    int ret;
    uint32_t *blob;
    long exp_time;
    struct krb5_req *kr = talloc_get_type(data, struct krb5_req);

    if (password_expiration == 0) {
        return;
    }

    exp_time = password_expiration - time(NULL);
    if (exp_time < 0 || exp_time > UINT32_MAX) {
        DEBUG(1, ("Time to expire out of range.\n"));
        return;
    }

    blob = talloc_array(kr->pd, uint32_t, 2);
    if (blob == NULL) {
        DEBUG(1, ("talloc_size failed.\n"));
        return;
    }

    blob[0] = SSS_PAM_USER_INFO_EXPIRE_WARN;
    blob[1] = (uint32_t) exp_time;

    ret = pam_add_response(kr->pd, SSS_PAM_USER_INFO, 2 * sizeof(uint32_t),
                           (uint8_t *) blob);
    if (ret != EOK) {
        DEBUG(1, ("pam_add_response failed.\n"));
    }

    return;
}

static krb5_error_code sss_krb5_prompter(krb5_context context, void *data,
                                         const char *name, const char *banner,
                                         int num_prompts, krb5_prompt prompts[])
{
    int ret;
    struct krb5_req *kr = talloc_get_type(data, struct krb5_req);

    if (num_prompts != 0) {
        DEBUG(1, ("Cannot handle password prompts.\n"));
        return KRB5_LIBOS_CANTREADPWD;
    }

    if (banner == NULL || *banner == '\0') {
        DEBUG(5, ("Prompter called with empty banner, nothing to do.\n"));
        return EOK;
    }

    DEBUG(9, ("Prompter called with [%s].\n", banner));

    ret = pam_add_response(kr->pd, SSS_PAM_TEXT_MSG, strlen(banner)+1,
                           (const uint8_t *) banner);
    if (ret != EOK) {
        DEBUG(1, ("pam_add_response failed.\n"));
    }

    return EOK;
}


static krb5_error_code create_empty_cred(krb5_context ctx, krb5_principal princ,
                                         krb5_creds **_cred)
{
    krb5_error_code kerr;
    krb5_creds *cred = NULL;
    krb5_data *krb5_realm;

    cred = calloc(sizeof(krb5_creds), 1);
    if (cred == NULL) {
        DEBUG(1, ("calloc failed.\n"));
        return ENOMEM;
    }

    kerr = krb5_copy_principal(ctx, princ, &cred->client);
    if (kerr != 0) {
        DEBUG(1, ("krb5_copy_principal failed.\n"));
        goto done;
    }

    krb5_realm = krb5_princ_realm(ctx, princ);

    kerr = krb5_build_principal_ext(ctx, &cred->server,
                                    krb5_realm->length, krb5_realm->data,
                                    KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
                                    krb5_realm->length, krb5_realm->data, 0);
    if (kerr != 0) {
        DEBUG(1, ("krb5_build_principal_ext failed.\n"));
        goto done;
    }

done:
    if (kerr != 0) {
        if (cred != NULL && cred->client != NULL) {
            krb5_free_principal(ctx, cred->client);
        }

        free(cred);
    } else {
        *_cred = cred;
    }

    return kerr;
}

static krb5_error_code create_ccache_file(krb5_context ctx,
                                          krb5_principal princ,
                                          char *ccname, krb5_creds *creds)
{
    krb5_error_code kerr;
    krb5_ccache tmp_cc = NULL;
    char *cc_file_name;
    int fd = -1;
    size_t ccname_len;
    char *dummy;
    char *tmp_ccname;
    krb5_creds *l_cred;
    TALLOC_CTX *tmp_ctx = NULL;
    mode_t old_umask;

    if (strncmp(ccname, "FILE:", 5) == 0) {
        cc_file_name = ccname + 5;
    } else {
        cc_file_name = ccname;
    }

    if (cc_file_name[0] != '/') {
        DEBUG(1, ("Ccache filename is not an absolute path.\n"));
        return EINVAL;
    }

    tmp_ctx = talloc_new(tmp_ctx);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    dummy = strrchr(cc_file_name, '/');
    tmp_ccname = talloc_strndup(tmp_ctx, cc_file_name,
                                (size_t) (dummy-cc_file_name));
    if (tmp_ccname == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        kerr = ENOMEM;
        goto done;
    }
    tmp_ccname = talloc_asprintf_append(tmp_ccname, "/.krb5cc_dummy_XXXXXX");

    old_umask = umask(077);
    fd = mkstemp(tmp_ccname);
    umask(old_umask);
    if (fd == -1) {
        DEBUG(1, ("mkstemp failed [%d][%s].\n", errno, strerror(errno)));
        kerr = errno;
        goto done;
    }

    kerr = krb5_cc_resolve(ctx, tmp_ccname, &tmp_cc);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto done;
    }

    kerr = krb5_cc_initialize(ctx, tmp_cc, princ);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto done;
    }
    if (fd != -1) {
        close(fd);
        fd = -1;
    }

    if (creds == NULL) {
        kerr = create_empty_cred(ctx, princ, &l_cred);
        if (kerr != 0) {
            KRB5_DEBUG(1, kerr);
            goto done;
        }
    } else {
        l_cred = creds;
    }

    kerr = krb5_cc_store_cred(ctx, tmp_cc, l_cred);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto done;
    }

    kerr = krb5_cc_close(ctx, tmp_cc);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto done;
    }
    tmp_cc = NULL;

    ccname_len = strlen(cc_file_name);
    if (ccname_len >= 6 && strcmp(cc_file_name + (ccname_len-6), "XXXXXX")==0 ) {
        fd = mkstemp(cc_file_name);
        if (fd == -1) {
            DEBUG(1, ("mkstemp failed [%d][%s].\n", errno, strerror(errno)));
            kerr = errno;
            goto done;
        }
    }

    kerr = rename(tmp_ccname, cc_file_name);
    if (kerr == -1) {
        DEBUG(1, ("rename failed [%d][%s].\n", errno, strerror(errno)));
    }

done:
    if (fd != -1) {
        close(fd);
    }
    if (kerr != 0 && tmp_cc != NULL) {
        krb5_cc_destroy(ctx, tmp_cc);
    }

    talloc_free(tmp_ctx);

    return kerr;
}

static errno_t pack_response_packet(struct response *resp, int status,
                                    struct pam_data *pd)
{
    size_t size = 0;
    size_t p = 0;
    struct response_data *pdr;

    /* A buffer with the following structure must be created:
     * int32_t status of the request (required)
     * message (zero or more)
     *
     * A message consists of:
     * int32_t type of the message
     * int32_t length of the following data
     * uint8_t[len] data
     */

    size = sizeof(int32_t);

    pdr = pd->resp_list;
    while (pdr != NULL) {
        size += 2*sizeof(int32_t) + pdr->len;
        pdr = pdr->next;
    }


    resp->buf = talloc_array(resp, uint8_t, size);
    if (!resp->buf) {
        DEBUG(1, ("Insufficient memory to create message.\n"));
        return ENOMEM;
    }

    SAFEALIGN_SET_INT32(&resp->buf[p], status, &p);

    pdr = pd->resp_list;
    while(pdr != NULL) {
        SAFEALIGN_SET_INT32(&resp->buf[p], pdr->type, &p);
        SAFEALIGN_SET_INT32(&resp->buf[p], pdr->len, &p);
        safealign_memcpy(&resp->buf[p], pdr->data, pdr->len, &p);

        pdr = pdr->next;
    }


    resp->size = p;

    return EOK;
}

static struct response *prepare_response_message(struct krb5_req *kr,
                                                 krb5_error_code kerr,
                                                 int pam_status)
{
    char *msg = NULL;
    const char *krb5_msg = NULL;
    int ret;
    struct response *resp;

    resp = talloc_zero(kr, struct response);
    if (resp == NULL) {
        DEBUG(1, ("Initializing response failed.\n"));
        return NULL;
    }

    if (kerr == 0) {
        if (kr->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) {
            pam_status = PAM_SUCCESS;
            ret = EOK;
        } else if (kr->pd->cmd == SSS_PAM_ACCT_MGMT) {
            ret = EOK;
        } else {
            if (kr->ccname == NULL) {
                DEBUG(1, ("Error obtaining ccname.\n"));
                return NULL;
            }

            msg = talloc_asprintf(kr, "%s=%s",CCACHE_ENV_NAME, kr->ccname);
            if (msg == NULL) {
                DEBUG(1, ("talloc_asprintf failed.\n"));
                return NULL;
            }

            pam_status = PAM_SUCCESS;
            ret = pam_add_response(kr->pd, SSS_PAM_ENV_ITEM, strlen(msg) + 1,
                                   (uint8_t *) msg);
            talloc_zfree(msg);
        }
    } else {
        krb5_msg = sss_krb5_get_error_message(krb5_error_ctx, kerr);
        if (krb5_msg == NULL) {
            DEBUG(1, ("sss_krb5_get_error_message failed.\n"));
            return NULL;
        }

        ret = pam_add_response(kr->pd, SSS_PAM_SYSTEM_INFO,
                               strlen(krb5_msg) + 1,
                               (const uint8_t *) krb5_msg);
        sss_krb5_free_error_message(krb5_error_ctx, krb5_msg);
    }
    if (ret != EOK) {
        DEBUG(1, ("pam_add_response failed.\n"));
    }

    ret = pack_response_packet(resp, pam_status, kr->pd);
    if (ret != EOK) {
        DEBUG(1, ("pack_response_packet failed.\n"));
        return NULL;
    }

    return resp;
}

static errno_t sendresponse(int fd, krb5_error_code kerr, int pam_status,
                            struct krb5_req *kr)
{
    struct response *resp;
    size_t written;
    int ret;

    resp = prepare_response_message(kr, kerr, pam_status);
    if (resp == NULL) {
        DEBUG(1, ("prepare_response_message failed.\n"));
        return ENOMEM;
    }

    written = 0;
    while (written < resp->size) {
        ret = write(fd, resp->buf + written, resp->size - written);
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

    return EOK;
}

static errno_t add_ticket_times_to_response(struct krb5_req *kr)
{
    int ret;
    int64_t t[4];

    t[0] = (int64_t) kr->creds->times.authtime;
    t[1] = (int64_t) kr->creds->times.starttime;
    t[2] = (int64_t) kr->creds->times.endtime;
    t[3] = (int64_t) kr->creds->times.renew_till;

    ret = pam_add_response(kr->pd, SSS_KRB5_INFO_TGT_LIFETIME,
                           4*sizeof(int64_t), (uint8_t *) t);
    if (ret != EOK) {
        DEBUG(1, ("pack_response_packet failed.\n"));
    }

    return ret;
}

static krb5_error_code validate_tgt(struct krb5_req *kr)
{
    krb5_error_code kerr;
    krb5_error_code kt_err;
    char *principal = NULL;
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_verify_init_creds_opt opt;

    memset(&keytab, 0, sizeof(keytab));
    kerr = krb5_kt_resolve(kr->ctx, kr->keytab, &keytab);
    if (kerr != 0) {
        DEBUG(1, ("error resolving keytab [%s], not verifying TGT.\n",
                  kr->keytab));
        return kerr;
    }

    memset(&cursor, 0, sizeof(cursor));
    kerr = krb5_kt_start_seq_get(kr->ctx, keytab, &cursor);
    if (kerr != 0) {
        DEBUG(1, ("error reading keytab [%s], not verifying TGT.\n",
                  kr->keytab));
        return kerr;
    }

    /* We look for the first entry from our realm or take the last one */
    memset(&entry, 0, sizeof(entry));
    while ((kt_err = krb5_kt_next_entry(kr->ctx, keytab, &entry, &cursor)) == 0) {
        if (krb5_realm_compare(kr->ctx, entry.principal, kr->princ)) {
            DEBUG(9, ("Found keytab entry with the realm of the credential.\n"));
            break;
        }

        kerr = sss_krb5_free_keytab_entry_contents(kr->ctx, &entry);
        if (kerr != 0) {
            DEBUG(1, ("Failed to free keytab entry.\n"));
        }
        memset(&entry, 0, sizeof(entry));
    }

    /* Close the keytab here.  Even though we're using cursors, the file
     * handle is stored in the krb5_keytab structure, and it gets
     * overwritten when the verify_init_creds() call below creates its own
     * cursor, creating a leak. */
    kerr = krb5_kt_end_seq_get(kr->ctx, keytab, &cursor);
    if (kerr != 0) {
        DEBUG(1, ("krb5_kt_end_seq_get failed, not verifying TGT.\n"));
        goto done;
    }

    /* check if we got any errors from krb5_kt_next_entry */
    if (kt_err != 0 && kt_err != KRB5_KT_END) {
        DEBUG(1, ("error reading keytab [%s], not verifying TGT.\n",
                  kr->keytab));
        goto done;
    }

    /* Get the principal to which the key belongs, for logging purposes. */
    principal = NULL;
    kerr = krb5_unparse_name(kr->ctx, entry.principal, &principal);
    if (kerr != 0) {
        DEBUG(1, ("internal error parsing principal name, "
                  "not verifying TGT.\n"));
        goto done;
    }


    krb5_verify_init_creds_opt_init(&opt);
    kerr = krb5_verify_init_creds(kr->ctx, kr->creds, entry.principal, keytab,
                                  NULL, &opt);

    if (kerr == 0) {
        DEBUG(5, ("TGT verified using key for [%s].\n", principal));
    } else {
        DEBUG(1 ,("TGT failed verification using key for [%s].\n", principal));
    }

done:
    if (krb5_kt_close(kr->ctx, keytab) != 0) {
        DEBUG(1, ("krb5_kt_close failed"));
    }
    if (sss_krb5_free_keytab_entry_contents(kr->ctx, &entry) != 0) {
        DEBUG(1, ("Failed to free keytab entry.\n"));
    }
    if (principal != NULL) {
        sss_krb5_free_unparsed_name(kr->ctx, principal);
    }

    return kerr;

}

static void krb5_set_canonicalize(krb5_get_init_creds_opt *opts)
{
    int canonicalize = 0;
    char *tmp_str;

    tmp_str = getenv(SSSD_KRB5_CANONICALIZE);
    if (tmp_str != NULL && strcasecmp(tmp_str, "true") == 0) {
        canonicalize = 1;
    }
    sss_krb5_get_init_creds_opt_set_canonicalize(opts, canonicalize);
}

static krb5_error_code get_and_save_tgt_with_keytab(krb5_context ctx,
                                                    krb5_principal princ,
                                                    krb5_keytab keytab,
                                                    char *ccname)
{
    krb5_error_code kerr = 0;
    krb5_creds creds;
    krb5_get_init_creds_opt options;

    memset(&creds, 0, sizeof(creds));
    memset(&options, 0, sizeof(options));

    krb5_get_init_creds_opt_set_address_list(&options, NULL);
    krb5_get_init_creds_opt_set_forwardable(&options, 0);
    krb5_get_init_creds_opt_set_proxiable(&options, 0);
    krb5_set_canonicalize(&options);

    kerr = krb5_get_init_creds_keytab(ctx, &creds, princ, keytab, 0, NULL,
                                      &options);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        return kerr;
    }

    kerr = create_ccache_file(ctx, princ, ccname, &creds);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto done;
    }
    kerr = 0;

done:
    krb5_free_cred_contents(ctx, &creds);

    return kerr;

}

static krb5_error_code get_and_save_tgt(struct krb5_req *kr,
                                        char *password)
{
    krb5_error_code kerr = 0;
    int ret;

    kerr = sss_krb5_get_init_creds_opt_set_expire_callback(kr->ctx, kr->options,
                                                  sss_krb5_expire_callback_func,
                                                  kr);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        DEBUG(1, ("Failed to set expire callback, continue without.\n"));
    }
    kerr = krb5_get_init_creds_password(kr->ctx, kr->creds, kr->princ,
                                        password, sss_krb5_prompter, kr, 0,
                                        NULL, kr->options);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        return kerr;
    }

    if (kr->validate) {
        kerr = validate_tgt(kr);
        if (kerr != 0) {
            KRB5_DEBUG(1, kerr);
            return kerr;
        }

    } else {
        DEBUG(9, ("TGT validation is disabled.\n"));
    }

    if (kr->validate || kr->fast_ccname != NULL) {
        /* We drop root privileges which were needed to read the keytab file
         * for the validation of the credentials or for FAST here to run the
         * ccache I/O operations with user privileges. */
        ret = become_user(kr->uid, kr->gid);
        if (ret != EOK) {
            DEBUG(1, ("become_user failed.\n"));
            return ret;
        }
    }

    kerr = create_ccache_file(kr->ctx, kr->princ, kr->ccname, kr->creds);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto done;
    }

    ret = add_ticket_times_to_response(kr);
    if (ret != EOK) {
        DEBUG(1, ("add_ticket_times_to_response failed.\n"));
    }

    kerr = 0;

done:
    krb5_free_cred_contents(kr->ctx, kr->creds);

    return kerr;

}

static errno_t changepw_child(int fd, struct krb5_req *kr)
{
    int ret;
    krb5_error_code kerr = 0;
    char *pass_str = NULL;
    char *newpass_str = NULL;
    int pam_status = PAM_SYSTEM_ERR;
    int result_code = -1;
    krb5_data result_code_string;
    krb5_data result_string;
    char *user_error_message = NULL;
    size_t user_resp_len;
    uint8_t *user_resp;
    char *changepw_princ = NULL;
    krb5_prompter_fct prompter = sss_krb5_prompter;

    if (kr->pd->authtok_type != SSS_AUTHTOK_TYPE_PASSWORD) {
        pam_status = PAM_CRED_INSUFFICIENT;
        kerr = KRB5KRB_ERR_GENERIC;
        goto sendresponse;
    }

    pass_str = talloc_strndup(kr, (const char *) kr->pd->authtok,
                              kr->pd->authtok_size);
    if (pass_str == NULL) {
        DEBUG(1, ("talloc_strndup failed.\n"));
        kerr = KRB5KRB_ERR_GENERIC;
        goto sendresponse;
    }

    changepw_princ = talloc_asprintf(kr, "%s@%s", SSSD_KRB5_CHANGEPW_PRINCIPAL,
                                                  kr->krb5_ctx->realm);
    if (changepw_princ == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        kerr = KRB5KRB_ERR_GENERIC;
        goto sendresponse;
    }

    if (kr->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) {
        /* We do not need a password expiration warning here. */
        prompter = NULL;
    }

    kerr = krb5_get_init_creds_password(kr->ctx, kr->creds, kr->princ,
                                        pass_str, prompter, kr, 0,
                                        changepw_princ,
                                        kr->options);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        if (kerr == KRB5_KDC_UNREACH) {
            pam_status = PAM_AUTHINFO_UNAVAIL;
        }
        goto sendresponse;
    }

    memset(pass_str, 0, kr->pd->authtok_size);
    talloc_zfree(pass_str);
    memset(kr->pd->authtok, 0, kr->pd->authtok_size);

    if (kr->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) {
        DEBUG(9, ("Initial authentication for change password operation "
                  "successfull.\n"));
        krb5_free_cred_contents(kr->ctx, kr->creds);
        pam_status = PAM_SUCCESS;
        goto sendresponse;
    }

    newpass_str = talloc_strndup(kr, (const char *) kr->pd->newauthtok,
                              kr->pd->newauthtok_size);
    if (newpass_str == NULL) {
        DEBUG(1, ("talloc_strndup failed.\n"));
        kerr = KRB5KRB_ERR_GENERIC;
        goto sendresponse;
    }

    memset(&result_code_string, 0, sizeof(krb5_data));
    memset(&result_string, 0, sizeof(krb5_data));
    kerr = krb5_change_password(kr->ctx, kr->creds, newpass_str, &result_code,
                                &result_code_string, &result_string);

    if (kerr == KRB5_KDC_UNREACH) {
        pam_status = PAM_AUTHTOK_LOCK_BUSY;
        goto sendresponse;
    }

    if (kerr != 0 || result_code != 0) {
        if (kerr != 0) {
            KRB5_DEBUG(1, kerr);
        } else {
            kerr = KRB5KRB_ERR_GENERIC;
        }

        if (result_code_string.length > 0) {
            DEBUG(1, ("krb5_change_password failed [%d][%.*s].\n", result_code,
                      result_code_string.length, result_code_string.data));
            user_error_message = talloc_strndup(kr->pd, result_code_string.data,
                                                result_code_string.length);
            if (user_error_message == NULL) {
                DEBUG(1, ("talloc_strndup failed.\n"));
            }
        }

        if (result_string.length > 0) {
            DEBUG(1, ("krb5_change_password failed [%d][%.*s].\n", result_code,
                      result_string.length, result_string.data));
            talloc_free(user_error_message);
            user_error_message = talloc_strndup(kr->pd, result_string.data,
                                                result_string.length);
            if (user_error_message == NULL) {
                DEBUG(1, ("talloc_strndup failed.\n"));
            }
        }

        if (user_error_message != NULL) {
            ret = pack_user_info_chpass_error(kr->pd, user_error_message,
                                              &user_resp_len, &user_resp);
            if (ret != EOK) {
                DEBUG(1, ("pack_user_info_chpass_error failed.\n"));
            } else {
                ret = pam_add_response(kr->pd, SSS_PAM_USER_INFO, user_resp_len,
                                       user_resp);
                if (ret != EOK) {
                    DEBUG(1, ("pack_response_packet failed.\n"));
                }
            }
        }

        pam_status = PAM_AUTHTOK_ERR;
        goto sendresponse;
    }

    krb5_free_cred_contents(kr->ctx, kr->creds);

    kerr = get_and_save_tgt(kr, newpass_str);
    memset(newpass_str, 0, kr->pd->newauthtok_size);
    talloc_zfree(newpass_str);
    memset(kr->pd->newauthtok, 0, kr->pd->newauthtok_size);

    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        if (kerr == KRB5_KDC_UNREACH) {
            pam_status = PAM_AUTHINFO_UNAVAIL;
        }
    }

sendresponse:
    ret = sendresponse(fd, kerr, pam_status, kr);
    if (ret != EOK) {
        DEBUG(1, ("sendresponse failed.\n"));
    }

    return ret;
}

static errno_t tgt_req_child(int fd, struct krb5_req *kr)
{
    int ret;
    krb5_error_code kerr = 0;
    char *pass_str = NULL;
    char *changepw_princ = NULL;
    int pam_status = PAM_SYSTEM_ERR;

    if (kr->pd->authtok_type != SSS_AUTHTOK_TYPE_PASSWORD) {
        pam_status = PAM_CRED_INSUFFICIENT;
        kerr = KRB5KRB_ERR_GENERIC;
        goto sendresponse;
    }

    pass_str = talloc_strndup(kr, (const char *) kr->pd->authtok,
                              kr->pd->authtok_size);
    if (pass_str == NULL) {
        DEBUG(1, ("talloc_strndup failed.\n"));
        kerr = KRB5KRB_ERR_GENERIC;
        goto sendresponse;
    }

    changepw_princ = talloc_asprintf(kr, "%s@%s", SSSD_KRB5_CHANGEPW_PRINCIPAL,
                                                  kr->krb5_ctx->realm);
    if (changepw_princ == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        kerr = KRB5KRB_ERR_GENERIC;
        goto sendresponse;
    }

    kerr = get_and_save_tgt(kr, pass_str);

    /* If the password is expired the KDC will always return
       KRB5KDC_ERR_KEY_EXP regardless if the supplied password is correct or
       not. In general the password can still be used to get a changepw ticket.
       So we validate the password by trying to get a changepw ticket. */
    if (kerr == KRB5KDC_ERR_KEY_EXP) {
        kerr = sss_krb5_get_init_creds_opt_set_expire_callback(kr->ctx,
                                                               kr->options,
                                                               NULL, NULL);
        if (kerr != 0) {
            KRB5_DEBUG(1, kerr);
            DEBUG(1, ("Failed to unset expire callback, continue ...\n"));
        }
        kerr = krb5_get_init_creds_password(kr->ctx, kr->creds, kr->princ,
                                            pass_str, sss_krb5_prompter, kr, 0,
                                            changepw_princ,
                                            kr->options);
        krb5_free_cred_contents(kr->ctx, kr->creds);
        if (kerr == 0) {
            kerr = KRB5KDC_ERR_KEY_EXP;
        }
    }

    memset(pass_str, 0, kr->pd->authtok_size);
    talloc_zfree(pass_str);
    memset(kr->pd->authtok, 0, kr->pd->authtok_size);

    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        switch (kerr) {
            case KRB5_KDC_UNREACH:
                    pam_status = PAM_AUTHINFO_UNAVAIL;
                    break;
            case KRB5KDC_ERR_KEY_EXP:
                    pam_status = PAM_NEW_AUTHTOK_REQD;
                    break;
            case KRB5KDC_ERR_PREAUTH_FAILED:
                    pam_status = PAM_CRED_ERR;
                    break;
            default:
                    pam_status = PAM_SYSTEM_ERR;
        }
    }

sendresponse:
    ret = sendresponse(fd, kerr, pam_status, kr);
    if (ret != EOK) {
        DEBUG(1, ("sendresponse failed.\n"));
    }

    return ret;
}

static errno_t kuserok_child(int fd, struct krb5_req *kr)
{
    krb5_boolean access_allowed;
    int status;
    int ret;
    krb5_error_code kerr;

    /* krb5_kuserok tries to verify that kr->pd->user is a locally known
     * account, so we have to unset _SSS_LOOPS to make getpwnam() work. */
    ret = unsetenv("_SSS_LOOPS");
    if (ret != EOK) {
        DEBUG(1, ("Failed to unset _SSS_LOOPS, "
                  "krb5_kuserok will most certainly fail.\n"));
    }

    kerr = krb5_set_default_realm(kr->ctx, kr->krb5_ctx->realm);
    if (kerr != 0) {
        DEBUG(1, ("krb5_set_default_realm failed, "
                  "krb5_kuserok may fail.\n"));
    }

    access_allowed = krb5_kuserok(kr->ctx, kr->princ, kr->pd->user);

    status = access_allowed ? 0 : 1;

    ret = sendresponse(fd, 0, status, kr);
    if (ret != EOK) {
        DEBUG(1, ("sendresponse failed.\n"));
    }

    return ret;
}

static errno_t renew_tgt_child(int fd, struct krb5_req *kr)
{
    int ret;
    int status = PAM_AUTHTOK_ERR;
    int kerr;
    char *ccname;
    krb5_ccache ccache = NULL;

    if (kr->pd->authtok_type != SSS_AUTHTOK_TYPE_CCFILE) {
        DEBUG(1, ("Unsupported authtok type for TGT renewal [%d].\n",
                  kr->pd->authtok_type));
        kerr = EINVAL;
        goto done;
    }

    ccname = talloc_strndup(kr, (char *) kr->pd->authtok, kr->pd->authtok_size);
    if (ccname == NULL) {
        DEBUG(1, ("talloc_strndup failed.\n"));
        kerr = ENOMEM;
        goto done;
    }

    kerr = krb5_cc_resolve(kr->ctx, ccname, &ccache);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto done;
    }

    kerr = krb5_get_renewed_creds(kr->ctx, kr->creds, kr->princ, ccache, NULL);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        if (kerr == KRB5_KDC_UNREACH) {
            status = PAM_AUTHINFO_UNAVAIL;
        }
        goto done;
    }

    if (kr->validate) {
        kerr = validate_tgt(kr);
        if (kerr != 0) {
            KRB5_DEBUG(1, kerr);
            goto done;
        }

    } else {
        DEBUG(9, ("TGT validation is disabled.\n"));
    }

    if (kr->validate || kr->fast_ccname != NULL) {
        /* We drop root privileges which were needed to read the keytab file
         * for the validation of the credentials or for FAST here to run the
         * ccache I/O operations with user privileges. */
        ret = become_user(kr->uid, kr->gid);
        if (ret != EOK) {
            DEBUG(1, ("become_user failed.\n"));
            kerr = ret;
            goto done;
        }
    }

    kerr = krb5_cc_initialize(kr->ctx, ccache, kr->princ);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto done;
    }

    kerr = krb5_cc_store_cred(kr->ctx, ccache, kr->creds);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto done;
    }

    ret = add_ticket_times_to_response(kr);
    if (ret != EOK) {
        DEBUG(1, ("add_ticket_times_to_response failed.\n"));
    }

    status = PAM_SUCCESS;
    kerr = 0;

done:
    krb5_free_cred_contents(kr->ctx, kr->creds);

    if (ccache != NULL) {
        krb5_cc_close(kr->ctx, ccache);
    }

    ret = sendresponse(fd, kerr, status, kr);
    if (ret != EOK) {
        DEBUG(1, ("sendresponse failed.\n"));
    }

    return ret;
}

static errno_t create_empty_ccache(int fd, struct krb5_req *kr)
{
    int ret;
    int pam_status = PAM_SUCCESS;

    ret = create_ccache_file(kr->ctx, kr->princ, kr->ccname, NULL);
    if (ret != 0) {
        KRB5_DEBUG(1, ret);
        pam_status = PAM_SYSTEM_ERR;
    }

    ret = sendresponse(fd, ret, pam_status, kr);
    if (ret != EOK) {
        DEBUG(1, ("sendresponse failed.\n"));
    }

    return ret;
}

static errno_t unpack_buffer(uint8_t *buf, size_t size, struct pam_data *pd,
                             struct krb5_req *kr, uint32_t *offline)
{
    size_t p = 0;
    uint32_t len;
    uint32_t validate;

    SAFEALIGN_COPY_UINT32_CHECK(&pd->cmd, buf + p, size, &p);
    SAFEALIGN_COPY_UINT32_CHECK(&kr->uid, buf + p, size, &p);
    SAFEALIGN_COPY_UINT32_CHECK(&kr->gid, buf + p, size, &p);
    SAFEALIGN_COPY_UINT32_CHECK(&validate, buf + p, size, &p);
    kr->validate = (validate == 0) ? false : true;
    SAFEALIGN_COPY_UINT32_CHECK(offline, buf + p, size, &p);

    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
    if ((p + len ) > size) return EINVAL;
    kr->upn = talloc_strndup(pd, (char *)(buf + p), len);
    if (kr->upn == NULL) return ENOMEM;
    p += len;

    if (pd->cmd == SSS_PAM_AUTHENTICATE ||
        pd->cmd == SSS_CMD_RENEW ||
        pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM || pd->cmd == SSS_PAM_CHAUTHTOK) {
        SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
        if ((p + len ) > size) return EINVAL;
        kr->ccname = talloc_strndup(pd, (char *)(buf + p), len);
        if (kr->ccname == NULL) return ENOMEM;
        p += len;

        SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
        if ((p + len ) > size) return EINVAL;
        kr->keytab = talloc_strndup(pd, (char *)(buf + p), len);
        if (kr->keytab == NULL) return ENOMEM;
        p += len;

        SAFEALIGN_COPY_UINT32_CHECK(&pd->authtok_type, buf + p, size, &p);
        SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
        if ((p + len) > size) return EINVAL;
        pd->authtok = (uint8_t *)talloc_strndup(pd, (char *)(buf + p), len);
        if (pd->authtok == NULL) return ENOMEM;
        pd->authtok_size = len + 1;
        p += len;
    } else {
        kr->ccname = NULL;
        kr->keytab = NULL;
        pd->authtok = NULL;
        pd->authtok_size = 0;
    }

    if (pd->cmd == SSS_PAM_CHAUTHTOK) {
        SAFEALIGN_COPY_UINT32_CHECK(&pd->newauthtok_type, buf + p, size, &p);
        SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

        if ((p + len) > size) return EINVAL;
        pd->newauthtok = (uint8_t *)talloc_strndup(pd, (char *)(buf + p), len);
        if (pd->newauthtok == NULL) return ENOMEM;
        pd->newauthtok_size = len + 1;
        p += len;
    } else {
        pd->newauthtok = NULL;
        pd->newauthtok_size = 0;
    }

    if (pd->cmd == SSS_PAM_ACCT_MGMT) {
        SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
        if ((p + len ) > size) return EINVAL;
        pd->user = talloc_strndup(pd, (char *)(buf + p), len);
        if (pd->user == NULL) return ENOMEM;
        p += len;
    } else {
        pd->user = NULL;
    }

    return EOK;
}

static int krb5_cleanup(void *ptr)
{
    struct krb5_req *kr = talloc_get_type(ptr, struct krb5_req);
    if (kr == NULL) return EOK;

    if (kr->options != NULL) {
        sss_krb5_get_init_creds_opt_free(kr->ctx, kr->options);
    }

    if (kr->creds != NULL) {
        krb5_free_cred_contents(kr->ctx, kr->creds);
        krb5_free_creds(kr->ctx, kr->creds);
    }
    if (kr->name != NULL)
        sss_krb5_free_unparsed_name(kr->ctx, kr->name);
    if (kr->princ != NULL)
        krb5_free_principal(kr->ctx, kr->princ);
    if (kr->ctx != NULL)
        krb5_free_context(kr->ctx);

    if (kr->krb5_ctx != NULL) {
        memset(kr->krb5_ctx, 0, sizeof(struct krb5_child_ctx));
    }
    memset(kr, 0, sizeof(struct krb5_req));

    return EOK;
}

static krb5_error_code get_tgt_times(krb5_context ctx, const char *ccname,
                                     krb5_principal server_principal,
                                     krb5_principal client_principal,
                                     sss_krb5_ticket_times *tgtt)
{
    krb5_error_code krberr;
    krb5_ccache ccache = NULL;
    krb5_creds mcred;
    krb5_creds cred;

    krberr = krb5_cc_resolve(ctx, ccname, &ccache);
    if (krberr != 0) {
        DEBUG(1, ("krb5_cc_resolve failed.\n"));
        goto done;
    }

    memset(&mcred, 0, sizeof(mcred));
    memset(&cred, 0, sizeof(mcred));

    mcred.server = server_principal;
    mcred.client = client_principal;

    krberr = krb5_cc_retrieve_cred(ctx, ccache, 0, &mcred, &cred);
    if (krberr != 0) {
        DEBUG(1, ("krb5_cc_retrieve_cred failed.\n"));
        krberr = 0;
        goto done;
    }

    tgtt->authtime = cred.times.authtime;
    tgtt->starttime = cred.times.starttime;
    tgtt->endtime = cred.times.endtime;
    tgtt->renew_till = cred.times.renew_till;

    krb5_free_cred_contents(ctx, &cred);

    krberr = 0;

done:
    if (ccache != NULL) {
        krb5_cc_close(ctx, ccache);
    }

    return krberr;
}

static krb5_error_code check_fast_ccache(krb5_context ctx, const char *primary,
                                         const char *realm,
                                         const char *keytab_name,
                                         TALLOC_CTX *mem_ctx,
                                         char **fast_ccname)
{
    TALLOC_CTX *tmp_ctx = NULL;
    krb5_error_code kerr;
    char *ccname;
    char *server_name;
    sss_krb5_ticket_times tgtt;
    krb5_keytab keytab = NULL;
    krb5_principal client_princ = NULL;
    krb5_principal server_princ = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed.\n"));
        kerr = ENOMEM;
        goto done;
    }

    ccname = talloc_asprintf(tmp_ctx, "FILE:%s/fast_ccache_%s", DB_PATH, realm);
    if (ccname == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        kerr = ENOMEM;
        goto done;
    }

    if (keytab_name != NULL) {
        kerr = krb5_kt_resolve(ctx, keytab_name, &keytab);
    } else {
        kerr = krb5_kt_default(ctx, &keytab);
    }
    if (kerr) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Failed to read keytab file [%s]: %s\n",
               KEYTAB_CLEAN_NAME,
               sss_krb5_get_error_message(ctx, kerr)));
        goto done;
    }

    kerr = find_principal_in_keytab(ctx, keytab, primary, realm, &client_princ);
    if (kerr != 0) {
        DEBUG(1, ("find_principal_in_keytab failed.\n"));
        goto done;
    }

    server_name = talloc_asprintf(tmp_ctx, "krbtgt/%s@%s", realm, realm);
    if (server_name == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        kerr = ENOMEM;
        goto done;
    }

    kerr = krb5_parse_name(ctx, server_name, &server_princ);
    if (kerr != 0) {
        DEBUG(1, ("krb5_parse_name failed.\n"));
        goto done;
    }

    memset(&tgtt, 0, sizeof(tgtt));
    kerr = get_tgt_times(ctx, ccname, server_princ, client_princ, &tgtt);
    if (kerr == 0) {
        if (tgtt.endtime > time(NULL)) {
            DEBUG(5, ("FAST TGT is still valid.\n"));
            goto done;
        }
    }

    kerr = get_and_save_tgt_with_keytab(ctx, client_princ, keytab, ccname);
    if (kerr != 0) {
        DEBUG(1, ("get_and_save_tgt_with_keytab failed.\n"));
        goto done;
    }


    kerr = 0;

done:
    if (client_princ != NULL) {
        krb5_free_principal(ctx, client_princ);
    }
    if (server_princ != NULL) {
        krb5_free_principal(ctx, server_princ);
    }

    if (kerr == 0) {
        *fast_ccname = talloc_steal(mem_ctx, ccname);
    }
    talloc_free(tmp_ctx);

    if (keytab != NULL) {
        krb5_kt_close(ctx, keytab);
    }

    return kerr;
}

static int krb5_child_setup(struct krb5_req *kr, uint32_t offline)
{
    krb5_error_code kerr = 0;
    char *lifetime_str;
    char *use_fast_str;
    char *tmp_str;
    krb5_data *realm_data;
    krb5_principal fast_princ_struct;
    char *fast_principal = NULL;
    const char *fast_principal_realm = NULL;
    krb5_deltat lifetime;

    kr->krb5_ctx = talloc_zero(kr, struct krb5_child_ctx);
    if (kr->krb5_ctx == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        kerr = ENOMEM;
        goto failed;
    }

    kr->krb5_ctx->realm = getenv(SSSD_KRB5_REALM);
    if (kr->krb5_ctx->realm == NULL) {
        DEBUG(2, ("Cannot read [%s] from environment.\n", SSSD_KRB5_REALM));
    }

    switch(kr->pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            /* If we are offline, we need to create an empty ccache file */
            if (offline) {
                kr->child_req = create_empty_ccache;
            } else {
                kr->child_req = tgt_req_child;
            }
            break;
        case SSS_PAM_CHAUTHTOK:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            kr->child_req = changepw_child;
            break;
        case SSS_PAM_ACCT_MGMT:
            kr->child_req = kuserok_child;
            break;
        case SSS_CMD_RENEW:
            if (!offline) {
                kr->child_req = renew_tgt_child;
            } else {
                DEBUG(1, ("Cannot renew TGT while offline.\n"));
                kerr = KRB5_KDC_UNREACH;
                goto failed;
            }
            break;
        default:
            DEBUG(1, ("PAM command [%d] not supported.\n", kr->pd->cmd));
            kerr = EINVAL;
            goto failed;
    }

    kerr = krb5_init_context(&kr->ctx);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto failed;
    }

    kerr = krb5_parse_name(kr->ctx, kr->upn, &kr->princ);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto failed;
    }

    kerr = krb5_unparse_name(kr->ctx, kr->princ, &kr->name);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto failed;
    }

    kr->creds = calloc(1, sizeof(krb5_creds));
    if (kr->creds == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        kerr = ENOMEM;
        goto failed;
    }

    kerr = sss_krb5_get_init_creds_opt_alloc(kr->ctx, &kr->options);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto failed;
    }

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_CHANGE_PASSWORD_PROMPT
    /* A prompter is used to catch messages about when a password will
     * expired. The library shall not use the prompter to ask for a new password
     * but shall return KRB5KDC_ERR_KEY_EXP. */
    krb5_get_init_creds_opt_set_change_password_prompt(kr->options, 0);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto failed;
    }
#endif

    lifetime_str = getenv(SSSD_KRB5_RENEWABLE_LIFETIME);
    if (lifetime_str == NULL) {
        DEBUG(7, ("Cannot read [%s] from environment.\n",
                  SSSD_KRB5_RENEWABLE_LIFETIME));
    } else {
        kerr = krb5_string_to_deltat(lifetime_str, &lifetime);
        if (kerr != 0) {
            DEBUG(1, ("krb5_string_to_deltat failed for [%s].\n",
                      lifetime_str));
            KRB5_DEBUG(1, kerr);
            goto failed;
        }
        krb5_get_init_creds_opt_set_renew_life(kr->options, lifetime);
    }

    lifetime_str = getenv(SSSD_KRB5_LIFETIME);
    if (lifetime_str == NULL) {
        DEBUG(7, ("Cannot read [%s] from environment.\n",
                  SSSD_KRB5_LIFETIME));
    } else {
        kerr = krb5_string_to_deltat(lifetime_str, &lifetime);
        if (kerr != 0) {
            DEBUG(1, ("krb5_string_to_deltat failed for [%s].\n",
                      lifetime_str));
            KRB5_DEBUG(1, kerr);
            goto failed;
        }
        krb5_get_init_creds_opt_set_tkt_life(kr->options, lifetime);
    }

    if (!offline) {
        krb5_set_canonicalize(kr->options);

        use_fast_str = getenv(SSSD_KRB5_USE_FAST);
        if (use_fast_str == NULL || strcasecmp(use_fast_str, "never") == 0) {
            DEBUG(9, ("Not using FAST.\n"));
        } else if (strcasecmp(use_fast_str, "try") == 0 ||
                   strcasecmp(use_fast_str, "demand") == 0) {

            tmp_str = getenv(SSSD_KRB5_FAST_PRINCIPAL);
            if (!tmp_str) {
                fast_principal = NULL;
                fast_principal_realm = kr->krb5_ctx->realm;
            } else {
                kerr = krb5_parse_name(kr->ctx, tmp_str, &fast_princ_struct);
                if (kerr) {
                    DEBUG(1, ("krb5_parse_name failed.\n"));
                    goto failed;
                }
                kerr = sss_krb5_unparse_name_flags(kr->ctx, fast_princ_struct,
                                               KRB5_PRINCIPAL_UNPARSE_NO_REALM,
                                               &tmp_str);
                if (kerr) {
                    DEBUG(1, ("sss_krb5_unparse_name_flags failed.\n"));
                    goto failed;
                }
                fast_principal = talloc_strdup(kr, tmp_str);
                if (!fast_principal) {
                    DEBUG(1, ("talloc_strdup failed.\n"));
                    kerr = KRB5KRB_ERR_GENERIC;
                    goto failed;
                }
                free(tmp_str);
                realm_data = krb5_princ_realm(kr->ctx, fast_princ_struct);
                fast_principal_realm = talloc_asprintf(kr, "%.*s", realm_data->length, realm_data->data);
                if (!fast_principal_realm) {
                    DEBUG(1, ("talloc_asprintf failed.\n"));
                    goto failed;
                }
            }

            kerr = check_fast_ccache(kr->ctx, fast_principal, fast_principal_realm, kr->keytab,
                                     kr, &kr->fast_ccname);
            if (kerr != 0) {
                DEBUG(1, ("check_fast_ccache failed.\n"));
                KRB5_DEBUG(1, kerr);
                goto failed;
            }

            kerr = sss_krb5_get_init_creds_opt_set_fast_ccache_name(kr->ctx,
                                                                    kr->options,
                                                                    kr->fast_ccname);
            if (kerr != 0) {
                DEBUG(1, ("sss_krb5_get_init_creds_opt_set_fast_ccache_name "
                          "failed.\n"));
                KRB5_DEBUG(1, kerr);
                goto failed;
            }

            if (strcasecmp(use_fast_str, "demand") == 0) {
                kerr = sss_krb5_get_init_creds_opt_set_fast_flags(kr->ctx,
                                                        kr->options,
                                                        SSS_KRB5_FAST_REQUIRED);
                if (kerr != 0) {
                    DEBUG(1, ("sss_krb5_get_init_creds_opt_set_fast_flags "
                              "failed.\n"));
                    KRB5_DEBUG(1, kerr);
                    goto failed;
                }
            }
        } else {
            DEBUG(1, ("Unsupported value [%s] for krb5_use_fast.\n"));
            kerr = EINVAL;
            goto failed;
        }
    }

/* TODO: set options, e.g.
 *  krb5_get_init_creds_opt_set_forwardable
 *  krb5_get_init_creds_opt_set_proxiable
 *  krb5_get_init_creds_opt_set_etype_list
 *  krb5_get_init_creds_opt_set_address_list
 *  krb5_get_init_creds_opt_set_preauth_list
 *  krb5_get_init_creds_opt_set_salt
 *  krb5_get_init_creds_opt_set_change_password_prompt
 *  krb5_get_init_creds_opt_set_pa
 */

    return EOK;

failed:

    return kerr;
}

int main(int argc, const char *argv[])
{
    uint8_t *buf = NULL;
    int ret;
    ssize_t len = 0;
    struct pam_data *pd = NULL;
    struct krb5_req *kr = NULL;
    uint32_t offline;
    int opt;
    poptContext pc;
    int debug_fd = -1;

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

    debug_prg_name = talloc_asprintf(NULL, "[sssd[krb5_child[%d]]]", getpid());
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

    DEBUG(SSSDBG_TRACE_FUNC, ("krb5_child started.\n"));

    pd = talloc_zero(NULL, struct pam_data);
    if (pd == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero failed.\n"));
        talloc_free(discard_const(debug_prg_name));
        goto fail;
    }
    talloc_steal(pd, debug_prg_name);

    buf = talloc_size(pd, sizeof(uint8_t)*IN_BUF_SIZE);
    if (buf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("malloc failed.\n"));
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

    kr = talloc_zero(pd, struct krb5_req);
    if (kr == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        goto fail;
    }
    talloc_set_destructor((TALLOC_CTX *) kr, krb5_cleanup);
    kr->pd = pd;

    ret = unpack_buffer(buf, len, pd, kr, &offline);
    if (ret != EOK) {
        DEBUG(1, ("unpack_buffer failed.\n"));
        goto fail;
    }

    ret = krb5_child_setup(kr, offline);
    if (ret != EOK) {
        DEBUG(1, ("krb5_child_setup failed.\n"));
        goto fail;
    }

    ret = kr->child_req(STDOUT_FILENO, kr);
    if (ret != EOK) {
        DEBUG(1, ("Child request failed.\n"));
        goto fail;
    }

    close(STDOUT_FILENO);
    talloc_free(pd);

    return 0;

fail:
    close(STDOUT_FILENO);
    talloc_free(pd);
    exit(-1);
}
