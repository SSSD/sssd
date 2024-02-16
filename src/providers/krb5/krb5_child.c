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
#include <fcntl.h>
#include <ctype.h>
#include <popt.h>
#include <sys/prctl.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "util/sss_krb5.h"
#include "util/user_info_msg.h"
#include "util/child_common.h"
#include "util/find_uid.h"
#include "util/sss_chain_id.h"
#include "util/sss_ptr_hash.h"
#include "src/util/util_errors.h"
#include "providers/backend.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_utils.h"
#include "krb5_plugin/idp/idp.h"
#ifdef BUILD_PASSKEY
#include "responder/pam/pamsrv_passkey.h"
#include "krb5_plugin/passkey/passkey.h"
#endif /* BUILD_PASSKEY */
#include "sss_cli.h"

#define SSSD_KRB5_CHANGEPW_PRINCIPAL "kadmin/changepw"
#ifndef BUILD_PASSKEY
#define SSSD_PASSKEY_QUESTION "passkey"
#endif /* BUILD_PASSKEY */

typedef krb5_error_code
(*k5_init_creds_password_fn_t)(krb5_context context, krb5_creds *creds,
                               krb5_principal client, const char *password,
                               krb5_prompter_fct prompter, void *data,
                               krb5_deltat start_time,
                               const char *in_tkt_service,
                               krb5_get_init_creds_opt *k5_gic_options);

enum k5c_fast_opt {
    K5C_FAST_NEVER,
    K5C_FAST_TRY,
    K5C_FAST_DEMAND,
};

struct cli_opts {
    char *realm;
    char *lifetime;
    char *rtime;
    char *use_fast_str;
    char *fast_principal;
    uint32_t check_pac_flags;
    bool canonicalize;
    bool fast_use_anonymous_pkinit;
};

struct krb5_req {
    krb5_context ctx;
    krb5_principal princ;
    krb5_principal princ_orig;
    char* name;
    krb5_creds *creds;
    bool otp;
    bool password_prompting;
    bool pkinit_prompting;
    char *otp_vendor;
    char *otp_token_id;
    char *otp_challenge;
    krb5_get_init_creds_opt *options;
    k5_init_creds_password_fn_t krb5_get_init_creds_password;

    struct pam_data *pd;

    char *realm;
    char *ccname;
    char *keytab;
    bool validate;
    bool posix_domain;
    bool send_pac;
    bool use_enterprise_princ;
    char *fast_ccname;

    const char *upn;
    uid_t uid;
    gid_t gid;

    char *old_ccname;
    bool old_cc_valid;
    bool old_cc_active;
    enum k5c_fast_opt fast_val;

    uid_t fast_uid;
    gid_t fast_gid;
    struct sss_creds *pcsc_saved_creds;

    struct cli_opts *cli_opts;
};

static krb5_context krb5_error_ctx;

#define KRB5_CHILD_DEBUG_INT(level, errctx, krb5_error) do { \
    const char *__krb5_error_msg; \
    __krb5_error_msg = sss_krb5_get_error_message(errctx, krb5_error); \
    DEBUG(level, "%d: [%d][%s]\n", __LINE__, krb5_error, __krb5_error_msg); \
    if (level & (SSSDBG_CRIT_FAILURE | SSSDBG_FATAL_FAILURE)) { \
         sss_log(SSS_LOG_ERR, "%s", __krb5_error_msg); \
    } \
    sss_krb5_free_error_message(errctx, __krb5_error_msg); \
} while(0)

#define KRB5_CHILD_DEBUG(level, error) KRB5_CHILD_DEBUG_INT(level, krb5_error_ctx, error)

static errno_t k5c_attach_otp_info_msg(struct krb5_req *kr);
static errno_t k5c_attach_oauth2_info_msg(struct krb5_req *kr, struct sss_idp_oauth2 *data);
#ifdef BUILD_PASSKEY
static errno_t k5c_attach_passkey_msg(struct krb5_req *kr, struct sss_passkey_challenge *data);
#endif /* BUILD_PASSKEY */
static errno_t k5c_attach_keep_alive_msg(struct krb5_req *kr);
static errno_t k5c_recv_data(struct krb5_req *kr, int fd, uint32_t *offline);
static errno_t k5c_send_data(struct krb5_req *kr, int fd, errno_t error);

static errno_t k5c_become_user(uid_t uid, gid_t gid, bool is_posix)
{
    if (is_posix == false) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Will not drop privileges for a non-POSIX user\n");
        return EOK;
    }
    return become_user(uid, gid);
}

static krb5_error_code set_lifetime_options(struct cli_opts *cli_opts,
                                            krb5_get_init_creds_opt *options)
{
    krb5_error_code kerr;
    krb5_deltat lifetime;

    if (cli_opts->rtime == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "No specific renewable lifetime requested.\n");

        /* Unset option flag to make sure defaults from krb5.conf are used. */
        options->flags &= ~(KRB5_GET_INIT_CREDS_OPT_RENEW_LIFE);
    } else {
        kerr = krb5_string_to_deltat(cli_opts->rtime, &lifetime);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "krb5_string_to_deltat failed for [%s].\n", cli_opts->rtime);
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
            return kerr;
        }
        DEBUG(SSSDBG_CONF_SETTINGS, "Renewable lifetime is set to [%s]\n",
                                    cli_opts->rtime);
        krb5_get_init_creds_opt_set_renew_life(options, lifetime);
    }

    if (cli_opts->lifetime == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "No specific lifetime requested.\n");

        /* Unset option flag to make sure defaults from krb5.conf are used. */
        options->flags &= ~(KRB5_GET_INIT_CREDS_OPT_TKT_LIFE);
    } else {
        kerr = krb5_string_to_deltat(cli_opts->lifetime, &lifetime);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "krb5_string_to_deltat failed for [%s].\n",
                  cli_opts->lifetime);
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
            return kerr;
        }
        DEBUG(SSSDBG_CONF_SETTINGS, "Lifetime is set to [%s]\n",
                                    cli_opts->lifetime);
        krb5_get_init_creds_opt_set_tkt_life(options, lifetime);
    }

    return 0;
}

static void set_canonicalize_option(struct cli_opts *cli_opts,
                                    krb5_get_init_creds_opt *opts)
{
    int canonicalize = 0;

    canonicalize = cli_opts->canonicalize ? 1 : 0;
    DEBUG(SSSDBG_CONF_SETTINGS, "Canonicalization is set to [%s]\n",
          cli_opts->canonicalize ? "true" : "false");
    sss_krb5_get_init_creds_opt_set_canonicalize(opts, canonicalize);
}

static void set_changepw_options(krb5_get_init_creds_opt *options)
{
    sss_krb5_get_init_creds_opt_set_canonicalize(options, 0);
    krb5_get_init_creds_opt_set_forwardable(options, 0);
    krb5_get_init_creds_opt_set_proxiable(options, 0);
    krb5_get_init_creds_opt_set_renew_life(options, 0);
    krb5_get_init_creds_opt_set_tkt_life(options, 5*60);
}

static void revert_changepw_options(struct cli_opts *cli_opts,
                                    krb5_get_init_creds_opt *options)
{
    krb5_error_code kerr;

    set_canonicalize_option(cli_opts, options);

    /* Currently we do not set forwardable and proxiable explicitly, the flags
     * must be removed so that libkrb5 can take the defaults from krb5.conf */
    options->flags &= ~(KRB5_GET_INIT_CREDS_OPT_FORWARDABLE);
    options->flags &= ~(KRB5_GET_INIT_CREDS_OPT_PROXIABLE);

    kerr = set_lifetime_options(cli_opts, options);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "set_lifetime_options failed.\n");
    }
}


static errno_t sss_send_pac(krb5_authdata **pac_authdata)
{
    struct sss_cli_req_data sss_data;
    int ret;
    int errnop;

    sss_data.len = pac_authdata[0]->length;
    sss_data.data = pac_authdata[0]->contents;

    ret = sss_pac_make_request(SSS_PAC_ADD_PAC_USER, &sss_data,
                               NULL, NULL, &errnop);
    DEBUG(SSSDBG_TRACE_ALL,
          "NSS return code [%d], request return code [%d][%s].\n", ret,
          errnop, sss_strerror(errnop));
    if (errnop == ERR_CHECK_PAC_FAILED) {
        return ERR_CHECK_PAC_FAILED;
    }

    if (ret == NSS_STATUS_UNAVAIL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "failed to contact PAC responder\n");
        return EIO;
    } else if (ret != NSS_STATUS_SUCCESS || errnop != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_pac_make_request failed [%d][%d].\n",
                                  ret, errnop);
        return EIO;
    }
    DEBUG(SSSDBG_TRACE_FUNC,
          "PAC responder contacted. It might take a bit of time in case the "
          "cache is not up to date.\n");

    return EOK;
}

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
        DEBUG(SSSDBG_CRIT_FAILURE, "Time to expire out of range.\n");
        return;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "exp_time: [%ld]\n", exp_time);

    blob = talloc_array(kr->pd, uint32_t, 2);
    if (blob == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_array failed.\n");
        return;
    }

    blob[0] = SSS_PAM_USER_INFO_EXPIRE_WARN;
    blob[1] = (uint32_t) exp_time;

    ret = pam_add_response(kr->pd, SSS_PAM_USER_INFO, 2 * sizeof(uint32_t),
                           (uint8_t *) blob);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
    }

    return;
}

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_RESPONDER
/*
 * TODO: These features generally would requires a significant refactoring
 * of SSSD and MIT krb5 doesn't support them anyway. They are listed here
 * simply as a reminder of things that might become future feature potential.
 *
 *   1. tokeninfo selection
 *   2. challenge
 *   3. discreet token/PIN prompting
 *   4. interactive OTP format correction
 *   5. nextOTP
 *
 */
typedef int (*checker)(int c);

static inline checker pick_checker(int format)
{
    switch (format) {
    case KRB5_RESPONDER_OTP_FORMAT_DECIMAL:
        return isdigit;
    case KRB5_RESPONDER_OTP_FORMAT_HEXADECIMAL:
        return isxdigit;
    case KRB5_RESPONDER_OTP_FORMAT_ALPHANUMERIC:
        return isalnum;
    }

    return NULL;
}

static int token_pin_destructor(char *mem)
{
    return sss_erase_talloc_mem_securely(mem);
}

static krb5_error_code tokeninfo_matches_2fa(TALLOC_CTX *mem_ctx,
                                         const krb5_responder_otp_tokeninfo *ti,
                                         const char *fa1, size_t fa1_len,
                                         const char *fa2, size_t fa2_len,
                                         char **out_token, char **out_pin)
{
    char *token = NULL, *pin = NULL;
    checker check = NULL;
    int i;

    if (ti->flags & KRB5_RESPONDER_OTP_FLAGS_NEXTOTP) {
        return ENOTSUP;
    }

    if (ti->challenge != NULL) {
        return ENOTSUP;
    }

    /* This is a non-sensical value. */
    if (ti->length == 0) {
        return EPROTO;
    }

    if (ti->flags & KRB5_RESPONDER_OTP_FLAGS_COLLECT_TOKEN) {
        if (ti->length > 0 && ti->length != fa2_len) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Expected [%d] and given [%zu] token size "
                  "do not match.\n", ti->length, fa2_len);
            return EMSGSIZE;
        }

        if (ti->flags & KRB5_RESPONDER_OTP_FLAGS_COLLECT_PIN) {
            if (ti->flags & KRB5_RESPONDER_OTP_FLAGS_SEPARATE_PIN) {

                pin = talloc_strndup(mem_ctx, fa1, fa1_len);
                if (pin == NULL) {
                    talloc_free(token);
                    return ENOMEM;
                }
                talloc_set_destructor(pin, token_pin_destructor);

                token = talloc_strndup(mem_ctx, fa2, fa2_len);
                if (token == NULL) {
                    return ENOMEM;
                }
                talloc_set_destructor(token, token_pin_destructor);

                check = pick_checker(ti->format);
            }
        } else {
            token = talloc_asprintf(mem_ctx, "%s%s", fa1, fa2);
            if (token == NULL) {
                return ENOMEM;
            }
            talloc_set_destructor(token, token_pin_destructor);

            check = pick_checker(ti->format);
        }
    } else {
        /* Assuming PIN only required */
        pin = talloc_strndup(mem_ctx, fa1, fa1_len);
        if (pin == NULL) {
            return ENOMEM;
        }
        talloc_set_destructor(pin, token_pin_destructor);
    }

    /* If check is set, we need to verify the contents of the token. */
    for (i = 0; check != NULL && token[i] != '\0'; i++) {
        if (!check(token[i])) {
            talloc_free(token);
            talloc_free(pin);
            return EBADMSG;
        }
    }

    *out_token = token;
    *out_pin = pin;
    return 0;
}

static krb5_error_code tokeninfo_matches_pwd(TALLOC_CTX *mem_ctx,
                                         const krb5_responder_otp_tokeninfo *ti,
                                         const char *pwd, size_t len,
                                         char **out_token, char **out_pin)
{
    char *token = NULL, *pin = NULL;
    checker check = NULL;
    int i;


    if (ti->flags & KRB5_RESPONDER_OTP_FLAGS_NEXTOTP) {
        return ENOTSUP;
    }

    if (ti->challenge != NULL) {
        return ENOTSUP;
    }

    /* This is a non-sensical value. */
    if (ti->length == 0) {
        return EPROTO;
    }

    if (ti->flags & KRB5_RESPONDER_OTP_FLAGS_COLLECT_TOKEN) {
        /* ASSUMPTION: authtok has one of the following formats:
         *   1. TokenValue
         *   2. PIN+TokenValue
         */
        token = talloc_strndup(mem_ctx, pwd, len);
        if (token == NULL) {
            return ENOMEM;
        }
        talloc_set_destructor(token, token_pin_destructor);

        if (ti->flags & KRB5_RESPONDER_OTP_FLAGS_COLLECT_PIN) {
            /* If the server desires a separate PIN, we will split it.
             * ASSUMPTION: Format of authtok is PIN+TokenValue. */
            if (ti->flags & KRB5_RESPONDER_OTP_FLAGS_SEPARATE_PIN) {
                if (ti->length < 1) {
                    talloc_free(token);
                    return ENOTSUP;
                }

                if (ti->length >= len) {
                    talloc_free(token);
                    return EMSGSIZE;
                }

                /* Copy the PIN from the front of the value. */
                pin = talloc_strndup(NULL, pwd, len - ti->length);
                if (pin == NULL) {
                    talloc_free(token);
                    return ENOMEM;
                }
                talloc_set_destructor(pin, token_pin_destructor);

                /* Remove the PIN from the front of the token value. */
                memmove(token, token + len - ti->length, ti->length + 1);

                check = pick_checker(ti->format);
            } else {
                if (ti->length > 0 && ti->length > len) {
                    talloc_free(token);
                    return EMSGSIZE;
                }
            }
        } else {
            if (ti->length > 0 && ti->length != len) {
                talloc_free(token);
                return EMSGSIZE;
            }

            check = pick_checker(ti->format);
        }
    } else {
        pin = talloc_strndup(mem_ctx, pwd, len);
        if (pin == NULL) {
            return ENOMEM;
        }
        talloc_set_destructor(pin, token_pin_destructor);
    }

    /* If check is set, we need to verify the contents of the token. */
    for (i = 0; check != NULL && token[i] != '\0'; i++) {
        if (!check(token[i])) {
            talloc_free(token);
            talloc_free(pin);
            return EBADMSG;
        }
    }

    *out_token = token;
    *out_pin = pin;
    return 0;
}

static krb5_error_code tokeninfo_matches(TALLOC_CTX *mem_ctx,
                                         const krb5_responder_otp_tokeninfo *ti,
                                         struct sss_auth_token *auth_tok,
                                         char **out_token, char **out_pin)
{
    int ret;
    const char *pwd;
    size_t len;
    const char *fa2;
    size_t fa2_len;

    switch (sss_authtok_get_type(auth_tok)) {
    case SSS_AUTHTOK_TYPE_PASSWORD:
        ret = sss_authtok_get_password(auth_tok, &pwd, &len);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_get_password failed.\n");
            return ret;
        }

        return tokeninfo_matches_pwd(mem_ctx, ti, pwd, len, out_token, out_pin);
        break;
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
        ret = sss_authtok_get_2fa_single(auth_tok, &pwd, &len);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_get_password failed.\n");
            return ret;
        }

        return tokeninfo_matches_pwd(mem_ctx, ti, pwd, len, out_token, out_pin);
        break;
    case SSS_AUTHTOK_TYPE_2FA:
        ret = sss_authtok_get_2fa(auth_tok, &pwd, &len, &fa2, &fa2_len);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_get_2fa failed.\n");
            return ret;
        }

        return tokeninfo_matches_2fa(mem_ctx, ti, pwd, len, fa2, fa2_len,
                                     out_token, out_pin);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unsupported authtok type %d\n", sss_authtok_get_type(auth_tok));
    }

    return EINVAL;
}

static krb5_error_code answer_otp(krb5_context ctx,
                                  struct krb5_req *kr,
                                  krb5_responder_context rctx)
{
    krb5_responder_otp_challenge *chl;
    char *token = NULL, *pin = NULL;
    krb5_error_code ret;
    size_t i;

    ret = krb5_responder_otp_get_challenge(ctx, rctx, &chl);
    if (ret != EOK || chl == NULL) {
        /* Either an error, or nothing to do. */
        return ret;
    }

    if (chl->tokeninfo == NULL || chl->tokeninfo[0] == NULL) {
        /* No tokeninfos? Absurd! */
        ret = EINVAL;
        goto done;
    }

    kr->otp = true;

    if (kr->pd->cmd == SSS_PAM_PREAUTH) {
        for (i = 0; chl->tokeninfo[i] != NULL; i++) {
            DEBUG(SSSDBG_TRACE_ALL, "[%zu] Vendor [%s].\n",
                                    i, chl->tokeninfo[i]->vendor);
            DEBUG(SSSDBG_TRACE_ALL, "[%zu] Token-ID [%s].\n",
                                    i, chl->tokeninfo[i]->token_id);
            DEBUG(SSSDBG_TRACE_ALL, "[%zu] Challenge [%s].\n",
                                    i, chl->tokeninfo[i]->challenge);
            DEBUG(SSSDBG_TRACE_ALL, "[%zu] Flags [%d].\n",
                                    i, chl->tokeninfo[i]->flags);
        }

        if (chl->tokeninfo[0]->vendor != NULL) {
            kr->otp_vendor = talloc_strdup(kr, chl->tokeninfo[0]->vendor);
        }
        if (chl->tokeninfo[0]->token_id != NULL) {
            kr->otp_token_id = talloc_strdup(kr, chl->tokeninfo[0]->token_id);
        }
        if (chl->tokeninfo[0]->challenge != NULL) {
            kr->otp_challenge = talloc_strdup(kr, chl->tokeninfo[0]->challenge);
        }
        /* Allocation errors are ignored on purpose */

        DEBUG(SSSDBG_TRACE_INTERNAL, "Exit answer_otp during pre-auth.\n");
        return EAGAIN;
    }

    /* Find the first supported tokeninfo which matches our authtoken. */
    for (i = 0; chl->tokeninfo[i] != NULL; i++) {
        ret = tokeninfo_matches(kr, chl->tokeninfo[i], kr->pd->authtok,
                                &token, &pin);
        if (ret == EOK) {
            break;
        }

        switch (ret) {
        case EBADMSG:
        case EMSGSIZE:
        case ENOTSUP:
        case EPROTO:
            break;
        default:
            goto done;
        }
    }
    if (chl->tokeninfo[i] == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "No tokeninfos found which match our credentials.\n");
        ret = EOK;
        goto done;
    }

    if (chl->tokeninfo[i]->flags & KRB5_RESPONDER_OTP_FLAGS_COLLECT_TOKEN) {
        /* Don't let SSSD cache the OTP authtoken since it is single-use. */
        ret = pam_add_response(kr->pd, SSS_OTP, 0, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            goto done;
        }
    }

    /* Respond with the appropriate answer. */
    ret = krb5_responder_otp_set_answer(ctx, rctx, i, token, pin);
done:
    talloc_free(token);
    talloc_free(pin);
    krb5_responder_otp_challenge_free(ctx, rctx, chl);
    return ret;
}

static bool pkinit_identity_matches(const char *identity,
                                    const char *token_name,
                                    const char *module_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *str;
    bool res = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        return false;
    }

    str = talloc_asprintf(tmp_ctx, "module_name=%s", module_name);
    if (str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        goto done;
    }

    if (strstr(identity, str) == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Identity [%s] does not contain [%s].\n",
                                identity, str);
        goto done;
    }
    DEBUG(SSSDBG_TRACE_ALL, "Found [%s] in identity [%s].\n", str, identity);

    str = talloc_asprintf(tmp_ctx, "token=%s", token_name);
    if (str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        goto done;
    }

    if (strstr(identity, str) == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Identity [%s] does not contain [%s].\n",
                                identity, str);
        goto done;
    }
    DEBUG(SSSDBG_TRACE_ALL, "Found [%s] in identity [%s].\n", str, identity);

    res = true;

done:
    talloc_free(tmp_ctx);

    return res;
}

static krb5_error_code answer_pkinit(krb5_context ctx,
                                     struct krb5_req *kr,
                                     krb5_responder_context rctx)
{
    krb5_error_code kerr;
    const char *pin = NULL;
    const char *token_name = NULL;
    const char *module_name = NULL;
    krb5_responder_pkinit_challenge *chl = NULL;
    size_t c;

    kerr = krb5_responder_pkinit_get_challenge(ctx, rctx, &chl);
    if (kerr != EOK || chl == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "krb5_responder_pkinit_get_challenge failed.\n");
        return kerr;
    }
    if (chl->identities == NULL || chl->identities[0] == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No identities for pkinit!\n");
        kerr = EINVAL;
        goto done;
    }

    for (c = 0; chl->identities[c] != NULL; c++) {
        DEBUG(SSSDBG_TRACE_ALL, "[%zu] Identity [%s] flags [%"PRId32"].\n",
                                c, chl->identities[c]->identity,
                                chl->identities[c]->token_flags);
    }

    DEBUG(SSSDBG_TRACE_ALL, "Setting pkinit_prompting.\n");
    kr->pkinit_prompting = true;

    if (kr->pd->cmd == SSS_PAM_AUTHENTICATE
            && (sss_authtok_get_type(kr->pd->authtok)
                    == SSS_AUTHTOK_TYPE_SC_PIN
                || sss_authtok_get_type(kr->pd->authtok)
                    == SSS_AUTHTOK_TYPE_SC_KEYPAD)) {
        kerr = sss_authtok_get_sc(kr->pd->authtok, &pin, NULL,
                                 &token_name, NULL,
                                 &module_name, NULL,
                                 NULL, NULL, NULL, NULL);
        if (kerr != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sss_authtok_get_sc failed.\n");
            goto done;
        }

        for (c = 0; chl->identities[c] != NULL; c++) {
            if (chl->identities[c]->identity != NULL
                    && pkinit_identity_matches(chl->identities[c]->identity,
                                               token_name, module_name)) {
                break;
            }
        }

        if (chl->identities[c] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "No matching identity for [%s][%s] found in pkinit challenge.\n",
                  token_name, module_name);
            kerr = EINVAL;
            goto done;
        }

        kerr = krb5_responder_pkinit_set_answer(ctx, rctx,
                                                chl->identities[c]->identity,
                                                pin);
        if (kerr != 0) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "krb5_responder_set_answer failed.\n");
        }

        goto done;
    }

    kerr = EOK;

done:
    krb5_responder_pkinit_challenge_free(ctx, rctx, chl);

    return kerr;
}

static errno_t krb5_req_update(struct krb5_req *dest, struct krb5_req *src)
{
    /* Check request validity. This should never happen, but it is better to
     * be little paranoid. */
    if (strcmp(dest->ccname, src->ccname) != 0) {
        return EINVAL;
    }

    if (strcmp(dest->upn, src->upn) != 0) {
        return EINVAL;
    }

    if (dest->uid != src->uid || dest->gid != src->gid) {
        return EINVAL;
    }

    /* Update PAM data. */
    talloc_free(dest->pd);
    dest->pd = talloc_steal(dest, src->pd);

    return EOK;
}

static krb5_error_code idp_oauth2_preauth(struct krb5_req *kr,
                                          struct sss_idp_oauth2 *oauth2)
{
    struct krb5_req *tmpkr = NULL;
    uint32_t offline;
    errno_t ret;

    if (oauth2->verification_uri == NULL || oauth2->user_code == NULL) {
        ret = EINVAL;
        goto done;
    }

    /* Challenge was presented. We need to continue the authentication
     * with this exact child process in order to maintain internal Kerberos
     * state so we are able to respond to this particular challenge. */

    ret = k5c_attach_oauth2_info_msg(kr, oauth2);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "k5c_attach_oauth2_info_msg failed.\n");
        return ret;
    }

    ret = k5c_attach_keep_alive_msg(kr);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "k5c_attach_keep_alive_msg failed.\n");
        return ret;
    }

    tmpkr = talloc_zero(NULL, struct krb5_req);
    if (tmpkr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    /* Send reply and wait for next step. */
    ret = k5c_send_data(kr, STDOUT_FILENO, ret);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to send reply\n");
    }

    ret = k5c_recv_data(tmpkr, STDIN_FILENO, &offline);
    if (ret != EOK) {
        goto done;
    }

    ret = krb5_req_update(kr, tmpkr);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to update krb request [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    talloc_free(tmpkr);
    return ret;
}

static krb5_error_code answer_idp_oauth2(krb5_context kctx,
                                         struct krb5_req *kr,
                                         krb5_responder_context rctx)
{
    enum sss_authtok_type type;
    struct sss_idp_oauth2 *data;
    const char *challenge;
    const char *token;
    size_t token_len;
    krb5_error_code kerr;

    challenge = krb5_responder_get_challenge(kctx, rctx,
                                             SSSD_IDP_OAUTH2_QUESTION);
    if (challenge == NULL) {
        return ENOENT;
    }

    data = sss_idp_oauth2_decode_challenge(challenge);
    if (data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to parse OAuth2 challenge\n");
        return EINVAL;
    }

    if (kr->pd->cmd == SSS_PAM_PREAUTH) {
        kerr = idp_oauth2_preauth(kr, data);
        if (kerr != EOK) {
            goto done;
        }
    }

    if (kr->pd->cmd != SSS_PAM_AUTHENTICATE) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected command [%d]\n", kr->pd->cmd);
        kerr = EINVAL;
        goto done;
    }

    type = sss_authtok_get_type(kr->pd->authtok);
    if (type != SSS_AUTHTOK_TYPE_OAUTH2) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected authentication token type [%s]\n",
              sss_authtok_type_to_str(type));
        kerr = EINVAL;
        goto done;
    }

    kerr = sss_authtok_get_oauth2(kr->pd->authtok, &token, &token_len);
    if (kerr != EOK) {
        goto done;
    }

    if (strlen(data->user_code) != token_len && strcmp(data->user_code, token) != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "User code do not match!\n");
        kerr = EINVAL;
        goto done;
    }

    /* Don't let SSSD cache the authtoken since it is single-use. */
    kerr = pam_add_response(kr->pd, SSS_OTP, 0, NULL);
    if (kerr != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        goto done;
    }

    /* The answer is arbitrary but we need to provide some since krb5 lib
     * expects it. So we choose the pin. */
    kerr = krb5_responder_set_answer(kctx, rctx, SSSD_IDP_OAUTH2_QUESTION,
                                     data->user_code);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to set IdP answer [%d]\n", kerr);
        goto done;
    }

    kerr = EOK;

done:
    sss_idp_oauth2_free(data);

    return kerr;
}

#ifdef BUILD_PASSKEY
static errno_t k5c_attach_passkey_msg(struct krb5_req *kr,
                                      struct sss_passkey_challenge *data)
{
    uint8_t *msg;
    const char *user_verification;
    int i;
    size_t msg_len = 0;
    size_t domain_len = 0;
    size_t crypto_len = 0;
    size_t num_creds = 0;
    size_t cred_len = 0;
    size_t verification_len = 0;
    size_t idx = 0;
    errno_t ret;

    if (data->domain == NULL || data->credential_id_list == NULL
            || data->cryptographic_challenge == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Empty passkey domain, credential id list, or cryptographic "
              "challenge\n");
        return EINVAL;
    }

    user_verification = data->user_verification == 0 ? "false" : "true";
    verification_len = strlen(user_verification) + 1;
    msg_len += verification_len;

    crypto_len = strlen(data->cryptographic_challenge) + 1;
    msg_len += crypto_len;

    domain_len = strlen(data->domain) + 1;
    msg_len += domain_len;

    /* credentials list size */
    msg_len += sizeof(uint32_t);

    for (i = 0; data->credential_id_list[i] != NULL; i++) {
        msg_len += (strlen(data->credential_id_list[i]) + 1);
    }
    num_creds = i;

    msg = talloc_zero_size(kr, msg_len);
    if (msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    /* To avoid sending extraneous data back and forth to pam_sss,
     * (and reduce boilerplate memcpy code) only the user
     * verification and cryptographic challenge are retrieved in pam_sss.
     *
     * The remaining passkey data (domain, creds list, num_creds)
     * is sent to the PAM responder and stored in a hash table. The
     * challenge is used as a unique key of the hash table. The pam_sss
     * reply includes the challenge which is used to lookup the passkey
     * data in the PAM responder, ensuring it matches the originating
     * request */
    memcpy(msg + idx, user_verification, verification_len);
    idx += verification_len;

    memcpy(msg + idx, data->cryptographic_challenge, crypto_len);
    idx += crypto_len;

    memcpy(msg + idx, data->domain, domain_len);
    idx += domain_len;

    SAFEALIGN_COPY_UINT32(msg + idx, &num_creds, &idx);

    for (i = 0; data->credential_id_list[i] != NULL; i++) {
        cred_len = strlen(data->credential_id_list[i]) + 1;
        memcpy(msg + idx, data->credential_id_list[i], cred_len);
        idx += cred_len;
    }

    ret = pam_add_response(kr->pd, SSS_PAM_PASSKEY_KRB_INFO, msg_len, msg);
    talloc_zfree(msg);

    return ret;
}

static krb5_error_code passkey_preauth(struct krb5_req *kr,
                                       struct sss_passkey_challenge *passkey)
{
    struct krb5_req *tmpkr = NULL;
    uint32_t offline;
    errno_t ret;

    if (passkey->domain == NULL || passkey->credential_id_list == NULL
            || passkey->cryptographic_challenge == NULL) {
        ret = EINVAL;
        goto done;
    }

    ret = k5c_attach_passkey_msg(kr, passkey);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "k5c_attach_passkey_info_msg failed.\n");
        return ret;
    }

    /* Challenge was presented. We need to continue the authentication
     * with this exact child process in order to maintain internal Kerberos
     * state so we are able to respond to this particular challenge. */
    ret = k5c_attach_keep_alive_msg(kr);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "k5c_attach_keep_alive_msg failed.\n");
        return ret;
    }

    tmpkr = talloc_zero(NULL, struct krb5_req);
    if (tmpkr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    /* Send reply and wait for next step. */
    ret = k5c_send_data(kr, STDOUT_FILENO, ret);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to send reply\n");
    }

    ret = k5c_recv_data(tmpkr, STDIN_FILENO, &offline);
    if (ret != EOK) {
        goto done;
    }

    ret = krb5_req_update(kr, tmpkr);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to update krb request [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    talloc_free(tmpkr);
    return ret;
}
#endif /* BUILD_PASSKEY */

static krb5_error_code answer_passkey(krb5_context kctx,
                                      struct krb5_req *kr,
                                      krb5_responder_context rctx)
{
#ifndef BUILD_PASSKEY
    DEBUG(SSSDBG_TRACE_FUNC, "Passkey auth not possible, SSSD built without passkey support!\n");
    return EINVAL;
#else
    enum sss_authtok_type type;
    struct sss_passkey_message *msg;
    struct sss_passkey_message *reply_msg = NULL;
    const char *challenge;
    const char *reply;
    char *reply_str = NULL;
    enum sss_passkey_phase phase;
    const char *state;
    size_t reply_len;
    krb5_error_code kerr;

    challenge = krb5_responder_get_challenge(kctx, rctx,
                                             SSSD_PASSKEY_QUESTION);
    if (challenge == NULL) {
        return ENOENT;
    }

    msg = sss_passkey_message_decode(challenge);
    if (msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to decode passkey message\n");
        return EINVAL;
    }

    if (kr->pd->cmd == SSS_PAM_PREAUTH) {
        kerr = passkey_preauth(kr, msg->data.challenge);
        if (kerr != EOK) {
            goto done;
        }
    }

    if (kr->pd->cmd != SSS_PAM_AUTHENTICATE) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected command [%d]\n", kr->pd->cmd);
        kerr = EINVAL;
        goto done;
    }

    type = sss_authtok_get_type(kr->pd->authtok);
    if (type != SSS_AUTHTOK_TYPE_PASSKEY_REPLY) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected authentication token type [%s]\n",
              sss_authtok_type_to_str(type));
        kerr = EINVAL;
        goto done;
    }

    kerr = sss_authtok_get_passkey_reply(kr->pd->authtok, &reply, &reply_len);
    if (kerr != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected command [%d]\n", kr->pd->cmd);
        goto done;
    }

    phase = SSS_PASSKEY_PHASE_REPLY;
    state = SSSD_PASSKEY_REPLY_STATE;
    reply_msg = sss_passkey_message_from_reply_json(phase, state, reply);
    if (reply_msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to prefix passkey message\n");
        kerr = EINVAL;
        goto done;
    }

    reply_str = sss_passkey_message_encode(reply_msg);
    if (reply_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to encode passkey message\n");
        kerr = EINVAL;
        goto done;
    }

    /* Don't let SSSD cache the authtoken since it is single-use. */
    kerr = pam_add_response(kr->pd, SSS_OTP, 0, NULL);
    if (kerr != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        goto done;
    }

    kerr = krb5_responder_set_answer(kctx, rctx, SSSD_PASSKEY_QUESTION,
                                     reply_str);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to set passkey answer [%d]\n", kerr);
        goto done;
    }

    kerr = EOK;

done:
    if (reply_str != NULL) {
        free(reply_str);
    }
    if (reply_msg != NULL) {
        sss_passkey_message_free(reply_msg);
    }

    return kerr;
#endif /* BUILD_PASSKEY */
}

static krb5_error_code sss_krb5_responder(krb5_context ctx,
                                          void *data,
                                          krb5_responder_context rctx)
{
    struct krb5_req *kr = talloc_get_type(data, struct krb5_req);
    const char * const *question_list;
    size_t c;
    const char *pwd;
    int ret;
    krb5_error_code kerr;

    if (kr == NULL) {
        return EINVAL;
    }

    question_list = krb5_responder_list_questions(ctx, rctx);

    if (question_list != NULL) {
        for (c = 0; question_list[c] != NULL; c++) {
            DEBUG(SSSDBG_TRACE_ALL, "Got question [%s].\n", question_list[c]);

            if (strcmp(question_list[c],
                       KRB5_RESPONDER_QUESTION_PASSWORD) == 0) {
                kr->password_prompting = true;

                if ((kr->pd->cmd == SSS_PAM_AUTHENTICATE
                            || kr->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM
                            || kr->pd->cmd == SSS_PAM_CHAUTHTOK)
                        && sss_authtok_get_type(kr->pd->authtok)
                                                 == SSS_AUTHTOK_TYPE_PASSWORD) {
                    ret = sss_authtok_get_password(kr->pd->authtok, &pwd, NULL);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              "sss_authtok_get_password failed.\n");
                        return ret;
                    }

                    kerr = krb5_responder_set_answer(ctx, rctx,
                                               KRB5_RESPONDER_QUESTION_PASSWORD,
                                               pwd);
                    if (kerr != 0) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              "krb5_responder_set_answer failed.\n");
                    }

                    return kerr;
                }
            } else if (strcmp(question_list[c],
                              KRB5_RESPONDER_QUESTION_PKINIT) == 0
                        && (sss_authtok_get_type(kr->pd->authtok)
                                               == SSS_AUTHTOK_TYPE_SC_PIN
                            || sss_authtok_get_type(kr->pd->authtok)
                                               == SSS_AUTHTOK_TYPE_SC_KEYPAD)) {
                return answer_pkinit(ctx, kr, rctx);
            } else if (strcmp(question_list[c], SSSD_IDP_OAUTH2_QUESTION) == 0) {
                return answer_idp_oauth2(ctx, kr, rctx);
            } else if (strcmp(question_list[c], SSSD_PASSKEY_QUESTION) == 0) {
                return answer_passkey(ctx, kr, rctx);
            }
        }
    }

    return answer_otp(ctx, kr, rctx);
}
#endif /* HAVE_KRB5_GET_INIT_CREDS_OPT_SET_RESPONDER */

static char *password_or_responder(const char *password)
{
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_RESPONDER
    /* If the new responder interface is available, we will handle even simple
     * passwords in the responder. */
    return NULL;
#else
    return discard_const(password);
#endif
}

static krb5_error_code sss_krb5_prompter(krb5_context context, void *data,
                                         const char *name, const char *banner,
                                         int num_prompts, krb5_prompt prompts[])
{
    int ret;
    size_t c;
    struct krb5_req *kr = talloc_get_type(data, struct krb5_req);

    if (kr == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_ALL,
          "sss_krb5_prompter name [%s] banner [%s] num_prompts [%d] EINVAL.\n",
          name, banner, num_prompts);

    if (num_prompts != 0) {
        for (c = 0; c < num_prompts; c++) {
            DEBUG(SSSDBG_TRACE_ALL, "Prompt [%zu][%s].\n", c,
                                    prompts[c].prompt);
        }

        DEBUG(SSSDBG_FUNC_DATA, "Prompter interface isn't used for password prompts by SSSD.\n");
        return KRB5_LIBOS_CANTREADPWD;
    }

    if (banner == NULL || *banner == '\0') {
        DEBUG(SSSDBG_FUNC_DATA,
              "Prompter called with empty banner, nothing to do.\n");
        return EOK;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Prompter called with [%s].\n", banner);

    ret = pam_add_response(kr->pd, SSS_PAM_TEXT_MSG, strlen(banner)+1,
                           (const uint8_t *) banner);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
    }

    return EOK;
}


static krb5_error_code create_empty_cred(krb5_context ctx, krb5_principal princ,
                                         krb5_creds **_cred)
{
    krb5_error_code kerr;
    krb5_creds *cred = NULL;
    krb5_data *krb5_realm;

    cred = calloc(1, sizeof(krb5_creds));
    if (cred == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "calloc failed.\n");
        return ENOMEM;
    }

    kerr = krb5_copy_principal(ctx, princ, &cred->client);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_copy_principal failed.\n");
        goto done;
    }

    krb5_realm = krb5_princ_realm(ctx, princ);

    kerr = krb5_build_principal_ext(ctx, &cred->server,
                                    krb5_realm->length, krb5_realm->data,
                                    KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
                                    krb5_realm->length, krb5_realm->data, 0);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_build_principal_ext failed.\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Created empty krb5_creds.\n");

done:
    if (kerr != 0) {
        krb5_free_cred_contents(ctx, cred);
        free(cred);
    } else {
        *_cred = cred;
    }

    return kerr;
}


static errno_t handle_randomized(char *in)
{
    size_t ccname_len;
    char *ccname = NULL;
    int ret;

    /* We only treat the FILE type case in a special way due to the history
     * of storing FILE type ccache in /tmp and associated security issues */
    if (in[0] == '/') {
        ccname = in;
    } else if (strncmp(in, "FILE:", 5) == 0) {
        ccname = in + 5;
    } else {
        return EOK;
    }

    ccname_len = strlen(ccname);
    if (ccname_len >= 6 && strcmp(ccname + (ccname_len - 6), "XXXXXX") == 0) {
        /* NOTE: this call is only used to create a unique name, as later
        * krb5_cc_initialize() will unlink and recreate the file.
        * This is ok because this part of the code is called with
        * privileges already dropped when handling user ccache, or the ccache
        * is stored in a private directory. So we do not have huge issues if
        * something races, we mostly care only about not accidentally use
        * an existing name and thus failing in the process of saving the
        * cache. Malicious races can only be avoided by libkrb5 itself. */
        ret = sss_unique_filename(NULL, ccname);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                    "mkstemp(\"%s\") failed [%d]: %s!\n",
                    ccname, ret, strerror(ret));
            return ret;
        }
    }

    return EOK;
}

/* NOTE: callers rely on 'name' being *changed* if it needs to be randomized,
 * as they will then send the name back to the new name via the return call
 * k5c_attach_ccname_msg(). Callers will send in a copy of the name if they
 * do not care for changes. */
static krb5_error_code create_ccache(char *ccname, krb5_creds *creds)
{
    krb5_context kctx = NULL;
    krb5_ccache kcc = NULL;
    const char *type;
    krb5_error_code kerr;
#ifdef HAVE_KRB5_CC_COLLECTION
    krb5_ccache cckcc;
    bool switch_to_cc = false;
#endif

    /* Set a restrictive umask, just in case we end up creating any file or a
     * directory. */
    if (strncmp(ccname, "DIR:", 4) == 0) {
        umask(SSS_DFL_X_UMASK);
    } else {
        umask(SSS_DFL_UMASK);
    }

    /* we create a new context here as the main process one may have been
     * opened as root and contain possibly references (even open handles?)
     * to resources we do not have or do not want to have access to */
    kerr = krb5_init_context(&kctx);
    if (kerr) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return ERR_INTERNAL;
    }

    kerr = handle_randomized(ccname);
    if (kerr) {
        DEBUG(SSSDBG_CRIT_FAILURE, "handle_randomized failed: %d\n", kerr);
        goto done;
    }

    kerr = krb5_cc_resolve(kctx, ccname, &kcc);
    if (kerr) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        goto done;
    }

    type = krb5_cc_get_type(kctx, kcc);
    DEBUG(SSSDBG_TRACE_ALL, "Initializing ccache of type [%s]\n", type);

#ifdef HAVE_KRB5_CC_COLLECTION
    if (krb5_cc_support_switch(kctx, type)) {
        DEBUG(SSSDBG_TRACE_ALL, "CC supports switch\n");
        kerr = krb5_cc_set_default_name(kctx, ccname);
        if (kerr) {
            DEBUG(SSSDBG_TRACE_ALL, "Cannot set default name!\n");
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
            goto done;
        }

        kerr = krb5_cc_cache_match(kctx, creds->client, &cckcc);
        if (kerr == KRB5_CC_NOTFOUND) {
            DEBUG(SSSDBG_TRACE_ALL, "Match not found\n");
            kerr = krb5_cc_new_unique(kctx, type, NULL, &cckcc);
            switch_to_cc = true;
        }
        if (kerr) {
            DEBUG(SSSDBG_TRACE_ALL, "krb5_cc_cache_match failed\n");
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
            goto done;
        }
        krb5_cc_close(kctx, kcc);
        kcc = cckcc;
    }
#endif

    kerr = krb5_cc_initialize(kctx, kcc, creds->client);
    if (kerr) {
        DEBUG(SSSDBG_TRACE_ALL, "krb5_cc_initialize failed\n");
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        goto done;
    }

    kerr = krb5_cc_store_cred(kctx, kcc, creds);
    if (kerr) {
        DEBUG(SSSDBG_TRACE_ALL, "krb5_cc_store_cred failed\n");
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        goto done;
    }

#ifdef HAVE_KRB5_CC_COLLECTION
    if (switch_to_cc) {
        DEBUG(SSSDBG_TRACE_ALL, "switch_to_cc\n");
        kerr = krb5_cc_switch(kctx, kcc);
        if (kerr) {
            DEBUG(SSSDBG_TRACE_ALL, "krb5_cc_switch\n");
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
            goto done;
        }
    }
#endif

    DEBUG(SSSDBG_TRACE_ALL, "returning: %d\n", kerr);
done:
    if (kcc) {
        /* FIXME: should we krb5_cc_destroy in case of error? */
        krb5_cc_close(kctx, kcc);
    }

    krb5_free_context(kctx);

    return kerr;
}

static errno_t pack_response_packet(TALLOC_CTX *mem_ctx, errno_t error,
                                    struct response_data *resp_list,
                                    uint8_t **_buf, size_t *_len)
{
    uint8_t *buf;
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

    for (pdr = resp_list; pdr != NULL; pdr = pdr->next) {
        size += 2*sizeof(int32_t) + pdr->len;
    }

    buf = talloc_array(mem_ctx, uint8_t, size);
    if (!buf) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_array failed\n");
        return ENOMEM;
    }

    SAFEALIGN_SET_INT32(&buf[p], error, &p);

    for (pdr = resp_list; pdr != NULL; pdr = pdr->next) {
        SAFEALIGN_SET_INT32(&buf[p], pdr->type, &p);
        SAFEALIGN_SET_INT32(&buf[p], pdr->len, &p);
        safealign_memcpy(&buf[p], pdr->data, pdr->len, &p);
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "response packet size: [%zu]\n", p);

    *_buf = buf;
    *_len = p;
    return EOK;
}

static errno_t k5c_attach_otp_info_msg(struct krb5_req *kr)
{
    uint8_t *msg = NULL;
    size_t msg_len;
    int ret;
    size_t vendor_len = 0;
    size_t token_id_len = 0;
    size_t challenge_len = 0;
    size_t idx = 0;

    msg_len = 3;
    if (kr->otp_vendor != NULL) {
        vendor_len = strlen(kr->otp_vendor);
        msg_len += vendor_len;
    }

    if (kr->otp_token_id != NULL) {
        token_id_len = strlen(kr->otp_token_id);
        msg_len += token_id_len;
    }

    if (kr->otp_challenge != NULL) {
        challenge_len = strlen(kr->otp_challenge);
        msg_len += challenge_len;
    }

    msg = talloc_zero_size(kr, msg_len);
    if (msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    if (kr->otp_vendor != NULL) {
        memcpy(msg, kr->otp_vendor, vendor_len);
    }
    idx += vendor_len +1;

    if (kr->otp_token_id != NULL) {
        memcpy(msg + idx, kr->otp_token_id, token_id_len);
    }
    idx += token_id_len +1;

    if (kr->otp_challenge != NULL) {
        memcpy(msg + idx, kr->otp_challenge, challenge_len);
    }

    ret = pam_add_response(kr->pd, SSS_PAM_OTP_INFO, msg_len, msg);
    talloc_zfree(msg);

    return ret;
}

static errno_t k5c_attach_oauth2_info_msg(struct krb5_req *kr,
                                          struct sss_idp_oauth2 *data)
{
    uint8_t *msg;
    const char *curi;
    size_t msg_len;
    size_t uri_len = 0;
    size_t curi_len = 0;
    size_t user_code_len = 0;
    size_t idx = 0;
    errno_t ret;

    if (data->verification_uri == NULL || data->user_code == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Empty oauth2 verification_uri or user_code\n");
        return EINVAL;
    }

    msg_len = 0;

    uri_len = strlen(data->verification_uri) + 1;
    msg_len += uri_len;

    if (data->verification_uri_complete != NULL) {
        curi = data->verification_uri_complete;
        curi_len = strlen(curi) + 1;
    } else {
        curi = "";
        curi_len = 1;
    }
    msg_len += curi_len;

    user_code_len = strlen(data->user_code) + 1;
    msg_len += user_code_len;

    msg = talloc_zero_size(NULL, msg_len);
    if (msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    memcpy(msg, data->verification_uri, uri_len);
    idx += uri_len;

    memcpy(msg + idx, curi, curi_len);
    idx += curi_len;

    memcpy(msg + idx, data->user_code, user_code_len);

    ret = pam_add_response(kr->pd, SSS_PAM_OAUTH2_INFO, msg_len, msg);
    talloc_zfree(msg);

    return ret;
}


static errno_t k5c_attach_keep_alive_msg(struct krb5_req *kr)
{
    uint8_t *msg;
    pid_t pid;
    int ret;

    pid = getpid();

    msg = talloc_memdup(kr, &pid, sizeof(pid_t));
    if (msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    /* Indicate that the krb5 child must be kept alive to continue
     * authentication with correct internal state of Kerberos API.
     *
     * Further communication must be done against the same child process */
    ret = pam_add_response(kr->pd, SSS_CHILD_KEEP_ALIVE, sizeof(pid_t), msg);
    talloc_zfree(msg);

    return ret;
}

static errno_t k5c_attach_ccname_msg(struct krb5_req *kr)
{
    char *msg = NULL;
    int ret;

    if (kr->ccname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error obtaining ccname.\n");
        return ERR_INTERNAL;
    }

    msg = talloc_asprintf(kr, "%s=%s",CCACHE_ENV_NAME, kr->ccname);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        return ENOMEM;
    }

    ret = pam_add_response(kr->pd, SSS_PAM_ENV_ITEM,
                           strlen(msg) + 1, (uint8_t *)msg);
    talloc_zfree(msg);

    return ret;
}

static errno_t k5c_send_data(struct krb5_req *kr, int fd, errno_t error)
{
    ssize_t written;
    uint8_t *buf;
    size_t len;
    int ret;

    DEBUG(SSSDBG_FUNC_DATA, "Received error code %d\n", error);

    ret = pack_response_packet(kr, error, kr->pd->resp_list, &buf, &len);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pack_response_packet failed.\n");
        return ret;
    }

    errno = 0;
    written = sss_atomic_write_safe_s(fd, buf, len);
    if (written == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "write failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    if (written != len) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Write error, wrote [%zu] bytes, expected [%zu]\n",
               written, len);
        return EOK;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Response sent.\n");

    return EOK;
}

static errno_t get_pkinit_identity(TALLOC_CTX *mem_ctx,
                                   struct sss_auth_token *authtok,
                                   char **_identity)
{
    int ret;
    char *identity;
    const char *token_name;
    const char *module_name;
    const char *key_id;
    const char *label;

    ret = sss_authtok_get_sc(authtok, NULL, NULL,
                             &token_name, NULL,
                             &module_name, NULL,
                             &key_id, NULL, &label, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_get_sc failed.\n");
        return ret;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Got [%s][%s].\n", token_name, module_name);

    if (module_name == NULL || *module_name == '\0') {
        module_name = "p11-kit-proxy.so";
    }

    identity = talloc_asprintf(mem_ctx, "PKCS11:module_name=%s", module_name);
    if (identity == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        return ENOMEM;
    }

    if (token_name != NULL && *token_name != '\0') {
        identity = talloc_asprintf_append(identity, ":token=%s",
                                                    token_name);
        if (identity == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "talloc_asprintf_append failed.\n");
            return ENOMEM;
        }
    }

    if (key_id != NULL && *key_id != '\0') {
        identity = talloc_asprintf_append(identity, ":certid=%s", key_id);
        if (identity == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "talloc_asprintf_append failed.\n");
            return ENOMEM;
        }
    }

    if (label != NULL && *label != '\0') {
        identity = talloc_asprintf_append(identity, ":certlabel=%s", label);
        if (identity == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "talloc_asprintf_append failed.\n");
            return ENOMEM;
        }
    }

    *_identity = identity;

    DEBUG(SSSDBG_TRACE_ALL, "Using pkinit identity [%s].\n", identity);

    return EOK;
}

static errno_t add_ticket_times_and_upn_to_response(struct krb5_req *kr)
{
    int ret;
    int64_t t[4];
    krb5_error_code kerr;
    char *upn = NULL;
    unsigned int upn_len = 0;

    t[0] = (int64_t) kr->creds->times.authtime;
    t[1] = (int64_t) kr->creds->times.starttime;
    t[2] = (int64_t) kr->creds->times.endtime;
    t[3] = (int64_t) kr->creds->times.renew_till;

    ret = pam_add_response(kr->pd, SSS_KRB5_INFO_TGT_LIFETIME,
                           4*sizeof(int64_t), (uint8_t *) t);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        goto done;
    }

    kerr = krb5_unparse_name_ext(kr->ctx, kr->creds->client, &upn, &upn_len);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_unparse_name_ext failed.\n");
        goto done;
    }

    ret = pam_add_response(kr->pd, SSS_KRB5_INFO_UPN, upn_len,
                           (uint8_t *) upn);
    krb5_free_unparsed_name(kr->ctx, upn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        goto done;
    }

done:
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
    krb5_principal validation_princ = NULL;
    bool realm_entry_found = false;
    krb5_ccache validation_ccache = NULL;
    krb5_authdata **pac_authdata = NULL;

    memset(&keytab, 0, sizeof(keytab));
    kerr = krb5_kt_resolve(kr->ctx, kr->keytab, &keytab);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error resolving keytab [%s], " \
                                    "not verifying TGT.\n", kr->keytab);
        return kerr;
    }

    memset(&cursor, 0, sizeof(cursor));
    kerr = krb5_kt_start_seq_get(kr->ctx, keytab, &cursor);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error reading keytab [%s], " \
                                    "not verifying TGT.\n", kr->keytab);
        krb5_kt_close(kr->ctx, keytab);
        return kerr;
    }

    /* We look for the first entry from our realm or take the last one */
    memset(&entry, 0, sizeof(entry));
    while ((kt_err = krb5_kt_next_entry(kr->ctx, keytab, &entry, &cursor)) == 0) {
        if (validation_princ != NULL) {
            krb5_free_principal(kr->ctx, validation_princ);
            validation_princ = NULL;
        }
        kerr = krb5_copy_principal(kr->ctx, entry.principal,
                                   &validation_princ);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "krb5_copy_principal failed.\n");
            krb5_kt_end_seq_get(kr->ctx, keytab, &cursor);
            goto done;
        }

        kerr = sss_krb5_free_keytab_entry_contents(kr->ctx, &entry);
        if (kerr != 0) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to free keytab entry.\n");
        }
        memset(&entry, 0, sizeof(entry));

        if (krb5_realm_compare(kr->ctx, validation_princ, kr->creds->client)) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Found keytab entry with the realm of the credential.\n");
            realm_entry_found = true;
            break;
        }
    }

    if (!realm_entry_found) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
                "Keytab entry with the realm of the credential not found "
                 "in keytab. Using the last entry.\n");
    }

    /* Close the keytab here. Even though we're using cursors, the file
     * handle is stored in the krb5_keytab structure, and it gets
     * overwritten when the verify_init_creds() call below creates its own
     * cursor, creating a leak. */
    kerr = krb5_kt_end_seq_get(kr->ctx, keytab, &cursor);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_kt_end_seq_get failed, " \
                                    "not verifying TGT.\n");
        goto done;
    }

    /* check if we got any errors from krb5_kt_next_entry */
    if (kt_err != 0 && kt_err != KRB5_KT_END) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error reading keytab [%s], " \
                                    "not verifying TGT.\n", kr->keytab);
        goto done;
    }

    /* Get the principal to which the key belongs, for logging purposes. */
    principal = NULL;
    kerr = krb5_unparse_name(kr->ctx, validation_princ, &principal);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "internal error parsing principal name, "
                                    "not verifying TGT.\n");
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        goto done;
    }


    krb5_verify_init_creds_opt_init(&opt);
    krb5_verify_init_creds_opt_set_ap_req_nofail(&opt, TRUE);
    kerr = krb5_verify_init_creds(kr->ctx, kr->creds, validation_princ, keytab,
                                  &validation_ccache, &opt);

    if (kerr == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "TGT verified using key for [%s].\n",
                                  principal);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE ,"TGT failed verification using key " \
                                    "for [%s].\n", principal);
        goto done;
    }

    /* Try to find and send the PAC to the PAC responder.
     * Failures are not critical. */
    if (kr->send_pac || kr->cli_opts->check_pac_flags != 0) {
        kerr = sss_extract_pac(kr->ctx, validation_ccache, validation_princ,
                               kr->creds->client, keytab,
                               kr->cli_opts->check_pac_flags, &pac_authdata);
        if (kerr != 0) {
            if (kerr == ERR_CHECK_PAC_FAILED) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "PAC check failed for principal [%s].\n", kr->name);
                goto done;
            }
            DEBUG(SSSDBG_OP_FAILURE, "sss_extract_and_send_pac failed, group " \
                                      "membership for user with principal [%s] " \
                                      "might not be correct.\n", kr->name);
            kerr = 0;
            goto done;
        }
    }

    if (kr->send_pac) {
        if(unsetenv("_SSS_LOOPS") != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to unset _SSS_LOOPS, "
                      "sss_pac_make_request will most certainly fail.\n");
        }

        kerr = sss_send_pac(pac_authdata);

        if(setenv("_SSS_LOOPS", "NO", 0) != 0) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set _SSS_LOOPS.\n");
        }

        if (kerr != 0) {
            if (kerr == ERR_CHECK_PAC_FAILED) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "PAC for principal [%s] is not valid.\n", kr->name);
                goto done;
            }
            if (kr->cli_opts->check_pac_flags != 0) {
                DEBUG(SSSDBG_IMPORTANT_INFO,
                      "pac_check is set but PAC responder is not running, "
                      "failed to properly validate PAC, ignored, "
                      "authentication for [%s] can proceed.\n", kr->name);
            }
            DEBUG(SSSDBG_OP_FAILURE, "sss_send_pac failed, group " \
                                      "membership for user with principal [%s] " \
                                      "might not be correct.\n", kr->name);
            kerr = 0;
        }
    }

done:
    krb5_free_authdata(kr->ctx, pac_authdata);
    if (validation_ccache != NULL) {
        krb5_cc_destroy(kr->ctx, validation_ccache);
    }

    if (krb5_kt_close(kr->ctx, keytab) != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "krb5_kt_close failed\n");
    }
    if (validation_princ != NULL) {
        krb5_free_principal(kr->ctx, validation_princ);
    }
    if (principal != NULL) {
        sss_krb5_free_unparsed_name(kr->ctx, principal);
    }

    return kerr;

}

static krb5_error_code get_and_save_tgt_with_keytab(krb5_context ctx,
                                                    struct cli_opts *cli_opts,
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
    set_canonicalize_option(cli_opts, &options);

    kerr = krb5_get_init_creds_keytab(ctx, &creds, princ, keytab, 0, NULL,
                                      &options);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    /* Use the updated principal in the creds in case canonicalized */
    kerr = create_ccache(ccname, &creds);
    if (kerr != 0) {
        goto done;
    }
    kerr = 0;

done:
    krb5_free_cred_contents(ctx, &creds);

    return kerr;

}

/* [MS-KILE]: Kerberos Protocol Extensions
 * https://msdn.microsoft.com/en-us/library/cc233855.aspx
 * http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/%5BMS-KILE%5D.pdf
 * 2.2.1 KERB-EXT-ERROR
 */
bool have_ms_kile_ext_error(unsigned char *data, unsigned int length,
                            uint32_t *_ntstatus)
{
    /* [MS-KILE] 2.2.2 KERB-ERROR-DATA
     * Kerberos V5 messages are defined using Abstract Syntax Notation One
     * (ASN.1)
     * KERB-ERROR-DATA ::= SEQUENCE {
     *      data-type              [1] INTEGER,
     *      data-value             [2] OCTET STRING OPTIONAL
     * }
     * We are interested in data-type 3 KERB_ERR_TYPE_EXTENDED
     */
    uint8_t kile_asn1_begining[] = {
        0x30, 0x15, /* 0x30 is SEQUENCE, 0x15 length */
        0xA1, 0x03, /* 0xA1 is 1st element of sequence, 0x03 length */
        0x02, 0x01, 0x03, /* 0x02 is INTEGER, 0x01 length, 0x03 value */
        0xA2, 0x0E, /* 0xA2 is 2nd element of sequence, 0x0E length */
        0x04, 0x0C, /* 0x04 is OCTET STRING, 0x0C length (12 bytes) */
    };
    const size_t offset = sizeof(kile_asn1_begining);
    uint32_t value;

    if (length != 23 || data == NULL) {
        return false;
    }

    if (memcmp(data, kile_asn1_begining, offset) != 0) {
        return false;
    }

    /* [MS-KILE] 2.2.1 KERB-EXT-ERROR
     * typedef struct KERB_EXT_ERROR {
     *     unsigned long status;
     *     unsigned long reserved;
     *     unsigned long flags;
     * } KERB_EXT_ERROR;
     * Status: An NTSTATUS value. See [MS-ERREF] section 2.3.
     */
    value = data[offset + 3] << 24
            | data[offset + 2] << 16
            | data[offset + 1] << 8
            | data[offset + 0];

    *_ntstatus = value;
    return true;
}

/* Following NTSTATUS values are from:
 * [MS-ERREF]: Windows Error Codes -> Section 2.3.1
 * https://msdn.microsoft.com/en-us/library/cc231196.aspx
 * http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/%5BMS-ERREF%5D.pdf
 */
#define NT_STATUS_ACCOUNT_EXPIRED 0xC0000193
#define NT_STATUS_ACCOUNT_DISABLED 0xC0000072

void check_ms_kile_ext_krb5err(krb5_context context,
                               krb5_init_creds_context init_cred_ctx,
                               krb5_error_code *_kerr)
{
    krb5_error_code err;
    krb5_error *error = NULL;
    uint32_t ntstatus;

    err = krb5_init_creds_get_error(context, init_cred_ctx, &error);
    if (err != 0 || error == NULL) {
        KRB5_CHILD_DEBUG(SSSDBG_TRACE_FUNC, err);
        return;
    }

    if (have_ms_kile_ext_error((unsigned char *)error->e_data.data, error->e_data.length,
                               &ntstatus)) {
        switch (ntstatus) {
        case NT_STATUS_ACCOUNT_EXPIRED:
            *_kerr = KRB5KDC_ERR_NAME_EXP;
            break;
        case NT_STATUS_ACCOUNT_DISABLED:
            *_kerr = KRB5KDC_ERR_CLIENT_REVOKED;
            break;
        }
    }
}

krb5_error_code
sss_krb5_get_init_creds_password(krb5_context context, krb5_creds *creds,
                                 krb5_principal client, const char *password,
                                 krb5_prompter_fct prompter, void *data,
                                 krb5_deltat start_time,
                                 const char *in_tkt_service,
                                 krb5_get_init_creds_opt *k5_gic_options)
{
    krb5_error_code kerr;
    krb5_init_creds_context init_cred_ctx = NULL;
    int log_level = SSSDBG_MINOR_FAILURE;
    struct krb5_req *kr = talloc_get_type(data, struct krb5_req);

    if (kr->pd->cmd != SSS_PAM_PREAUTH) {
        log_level = SSSDBG_OP_FAILURE;
    }

    kerr = krb5_init_creds_init(context, client, prompter, data,
                                start_time, k5_gic_options,
                                &init_cred_ctx);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(log_level, kerr);
        goto done;
    }

    if (password != NULL) {
        kerr = krb5_init_creds_set_password(context, init_cred_ctx, password);
        if (kerr != 0) {
            KRB5_CHILD_DEBUG(log_level, kerr);
            goto done;
        }
    }

    if (in_tkt_service != NULL) {
        kerr = krb5_init_creds_set_service(context, init_cred_ctx,
                                           in_tkt_service);
        if (kerr != 0) {
            KRB5_CHILD_DEBUG(log_level, kerr);
            goto done;
        }
    }

    kerr = krb5_init_creds_get(context, init_cred_ctx);
    if (kerr == KRB5KDC_ERR_CLIENT_REVOKED) {
        check_ms_kile_ext_krb5err(context, init_cred_ctx, &kerr);
    }

    if (kerr != 0) {
        KRB5_CHILD_DEBUG(log_level, kerr);
        goto done;
    }

    kerr = krb5_init_creds_get_creds(context, init_cred_ctx, creds);

done:
    krb5_init_creds_free(context, init_cred_ctx);
    return kerr;
}

static krb5_error_code get_and_save_tgt(struct krb5_req *kr,
                                        const char *password)
{
    const char *realm_name;
    int realm_length;
    krb5_error_code kerr;
    char *cc_name;
    int ret;
    char *identity = NULL;

    kerr = sss_krb5_get_init_creds_opt_set_expire_callback(kr->ctx, kr->options,
                                                  sss_krb5_expire_callback_func,
                                                  kr);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set expire callback, continue without.\n");
    }

    sss_krb5_princ_realm(kr->ctx, kr->princ, &realm_name, &realm_length);
    if (realm_length == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_krb5_princ_realm failed.\n");
        return KRB5KRB_ERR_GENERIC;
    }

    if (sss_authtok_get_type(kr->pd->authtok) == SSS_AUTHTOK_TYPE_SC_PIN
            || sss_authtok_get_type(kr->pd->authtok)
                                                == SSS_AUTHTOK_TYPE_SC_KEYPAD) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Found Smartcard credentials, trying pkinit.\n");

        ret = get_pkinit_identity(kr, kr->pd->authtok, &identity);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_pkinit_identity failed.\n");
            return ret;
        }

        kerr = krb5_get_init_creds_opt_set_pa(kr->ctx, kr->options,
                                              "X509_user_identity", identity);
        talloc_free(identity);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "krb5_get_init_creds_opt_set_pa failed.\n");
            return kerr;
        }

        /* TODO: Maybe X509_anchors should be added here as well */
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Attempting kinit for realm [%s]\n",realm_name);
    kerr = kr->krb5_get_init_creds_password(kr->ctx, kr->creds, kr->princ,
                                            password_or_responder(password),
                                            sss_krb5_prompter, kr, 0, NULL,
                                            kr->options);
    if (kr->pd->cmd == SSS_PAM_PREAUTH && kerr != KRB5KDC_ERR_KEY_EXP) {
        /* Any errors except KRB5KDC_ERR_KEY_EXP are ignored during pre-auth,
         * only data is collected to be send back to the client.
         * KRB5KDC_ERR_KEY_EXP must be handled separately to figure out the
         * possible authentication methods to update the password. */
        DEBUG(SSSDBG_TRACE_FUNC,
              "krb5_get_init_creds_password returned [%d] during pre-auth.\n",
              kerr);
        return 0;
    } else {
        if (kerr != 0) {
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);

            /* Special case for IPA password migration */
            if (kr->pd->cmd == SSS_PAM_AUTHENTICATE
                    && kerr == KRB5_PREAUTH_FAILED
                    && kr->pkinit_prompting == false
                    && kr->password_prompting == false
                    && kr->otp == false
                    && sss_authtok_get_type(kr->pd->authtok)
                            == SSS_AUTHTOK_TYPE_PASSWORD) {
                return ERR_CREDS_INVALID;
            }

            /* If during authentication either the MIT Kerberos pkinit
             * pre-auth module is missing or no Smartcard is inserted and only
             * pkinit is available KRB5_PREAUTH_FAILED is returned.
             * ERR_NO_AUTH_METHOD_AVAILABLE is used to indicate to the
             * frontend that local authentication might be tried.
             * Same is true if Smartcard credentials are given but only other
             * authentication methods are available. */
            if (kr->pd->cmd == SSS_PAM_AUTHENTICATE
                    && kerr == KRB5_PREAUTH_FAILED
                    && kr->pkinit_prompting == false
                    && (( kr->password_prompting == false
                              && kr->otp == false)
                            || ((kr->otp == true
                                    || kr->password_prompting == true)
                              && IS_SC_AUTHTOK(kr->pd->authtok))) ) {
                return ERR_NO_AUTH_METHOD_AVAILABLE;
            }
            return kerr;
        }
    }

    if (kr->validate) {
        kerr = validate_tgt(kr);
        if (kerr != 0) {
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
            return kerr;
        }

    } else {
        DEBUG(SSSDBG_CONF_SETTINGS, "TGT validation is disabled.\n");
    }

    /* In a non-POSIX environment, we only care about the return code from
     * krb5_child, so let's not even attempt to create the ccache
     */
    if (kr->posix_domain == false) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Finished authentication in a non-POSIX domain\n");
        goto done;
    }

    kerr = restore_creds(kr->pcsc_saved_creds);
    if (kerr != 0)  {
        DEBUG(SSSDBG_OP_FAILURE, "restore_creds failed.\n");
    }
    /* Make sure ccache is created and written as the user */
    if (geteuid() != kr->uid || getegid() != kr->gid) {
        kerr = k5c_become_user(kr->uid, kr->gid, kr->posix_domain);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "become_user failed.\n");
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Running as [%"SPRIuid"][%"SPRIgid"].\n", geteuid(), getegid());

    /* If kr->ccname is cache collection (DIR:/...), we want to work
     * directly with file ccache (DIR::/...), but cache collection
     * should be returned back to back end.
     */
    cc_name = sss_get_ccache_name_for_principal(kr->pd, kr->ctx,
                                                kr->creds->client,
                                                kr->ccname);
    if (cc_name == NULL) {
        cc_name = kr->ccname;
    }

    /* Use the updated principal in the creds in case canonicalized */
    kerr = create_ccache(cc_name, kr->creds);
    if (kerr != 0) {
        goto done;
    }

    /* Successful authentication! Check if ccache contains the
     * right principal...
     */
    kerr = sss_krb5_check_ccache_princ(kr->ctx, kr->ccname, kr->creds->client);
    if (kerr) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "No ccache for %s in %s?\n", kr->upn, kr->ccname);
        goto done;
    }

    kerr = safe_remove_old_ccache_file(kr->old_ccname, kr->ccname,
                                       kr->uid, kr->gid);
    if (kerr != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to remove old ccache file [%s], "
              "please remove it manually.\n", kr->old_ccname);
    }

    kerr = add_ticket_times_and_upn_to_response(kr);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "add_ticket_times_and_upn_to_response failed.\n");
    }

    kerr = 0;

done:
    krb5_free_cred_contents(kr->ctx, kr->creds);

    return kerr;

}

static errno_t map_krb5_error(krb5_error_code kerr)
{
    /* just pass SSSD's internal error codes */
    if (kerr > 0 && IS_SSSD_ERROR(kerr)) {
        DEBUG(SSSDBG_OP_FAILURE, "[%d][%s].\n", kerr, sss_strerror(kerr));
        return kerr;
    }

    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_OP_FAILURE, kerr);
    }

    switch (kerr) {
    case 0:
        return ERR_OK;

    case KRB5_LIBOS_CANTREADPWD:
        return ERR_NO_CREDS;

    case KRB5_KDCREP_SKEW:
    case KRB5KRB_AP_ERR_SKEW:
    case KRB5KRB_AP_ERR_TKT_EXPIRED:
    case KRB5KRB_AP_ERR_TKT_NYV:
    case KRB5_KDC_UNREACH:
    case KRB5_REALM_CANT_RESOLVE:
    case KRB5_REALM_UNKNOWN:
        return ERR_NETWORK_IO;

    case KRB5KDC_ERR_CLIENT_REVOKED:
        return ERR_ACCOUNT_LOCKED;

    case KRB5KDC_ERR_NAME_EXP:
        return ERR_ACCOUNT_EXPIRED;

    case KRB5KDC_ERR_KEY_EXP:
        return ERR_CREDS_EXPIRED;

    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
        return ERR_AUTH_FAILED;

    /* ERR_CREDS_INVALID is used to indicate to the IPA provider that trying
     * password migration would make sense. All Kerberos error codes which can
     * be seen while migrating LDAP users to IPA should be added here. */
    case KRB5_PROG_ETYPE_NOSUPP:
    case KRB5_PREAUTH_FAILED:
    case KRB5KDC_ERR_PREAUTH_FAILED:
        return ERR_CREDS_INVALID;

    /* Please do not remove KRB5KRB_ERR_GENERIC here, it is a _generic_ error
     * code and we cannot make any assumptions about the reason for the error.
     * As a consequence we cannot return a different error code than a generic
     * one which unfortunately might result in a unspecific system error
     * message to the user.
     *
     * If there are cases where libkrb5 calls return KRB5KRB_ERR_GENERIC where
     * SSSD should behave differently this has to be detected by different
     * means, e.g. by evaluation error messages, and then the error code
     * should be changed to a more suitable KRB5* error code or immediately to
     * an SSSD ERR_* error code to avoid the default handling here. */
    case KRB5KRB_ERR_GENERIC:
    default:
        return ERR_INTERNAL;
    }
}

static errno_t changepw_child(struct krb5_req *kr, bool prelim)
{
    int ret;
    krb5_error_code kerr = 0;
    const char *password = NULL;
    const char *newpassword = NULL;
    int result_code = -1;
    krb5_data result_code_string;
    krb5_data result_string;
    char *user_error_message = NULL;
    size_t user_resp_len;
    uint8_t *user_resp;
    krb5_prompter_fct prompter = NULL;
    const char *realm_name;
    int realm_length;
    size_t msg_len;
    uint8_t *msg;
    uint32_t user_info_type;

    DEBUG(SSSDBG_TRACE_LIBS, "Password change operation\n");

    if (sss_authtok_get_type(kr->pd->authtok) == SSS_AUTHTOK_TYPE_PASSWORD) {
        ret = sss_authtok_get_password(kr->pd->authtok, &password, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to fetch current password [%d] %s.\n",
                      ret, strerror(ret));
            return ERR_NO_CREDS;
        }
    }

    if (!prelim) {
        /* We do not need a password expiration warning here. */
        prompter = sss_krb5_prompter;
    }

    set_changepw_options(kr->options);
    sss_krb5_princ_realm(kr->ctx, kr->princ, &realm_name, &realm_length);
    if (realm_length == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_krb5_princ_realm failed.\n");
        return ERR_INTERNAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Attempting kinit for realm [%s]\n",realm_name);
    kerr = kr->krb5_get_init_creds_password(kr->ctx, kr->creds, kr->princ,
                                            password_or_responder(password),
                                            prompter, kr, 0,
                                            SSSD_KRB5_CHANGEPW_PRINCIPAL,
                                            kr->options);
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "chpass is%s using OTP\n", kr->otp ? "" : " not");
    if (kerr != 0) {
        ret = pack_user_info_chpass_error(kr->pd, "Old password not accepted.",
                                          &msg_len, &msg);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "pack_user_info_chpass_error failed [%d]\n", ret);
        } else {
            ret = pam_add_response(kr->pd, SSS_PAM_USER_INFO, msg_len,
                                   msg);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            }
        }
        return kerr;
    }

    sss_authtok_set_empty(kr->pd->authtok);

    if (prelim) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Initial authentication for change password operation "
               "successful.\n");
        krb5_free_cred_contents(kr->ctx, kr->creds);
        return EOK;
    }

    ret = sss_authtok_get_password(kr->pd->newauthtok, &newpassword, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to fetch new password [%d] %s.\n",
                  ret, strerror(ret));
        return ERR_NO_CREDS;
    }

    memset(&result_code_string, 0, sizeof(krb5_data));
    memset(&result_string, 0, sizeof(krb5_data));
    kerr = krb5_change_password(kr->ctx, kr->creds,
                                discard_const(newpassword), &result_code,
                                &result_code_string, &result_string);

    if (kerr == KRB5_KDC_UNREACH) {
        return ERR_NETWORK_IO;
    }

    if (kerr != 0 || result_code != 0) {
        if (kerr != 0) {
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        }

        if (result_code_string.length > 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "krb5_change_password failed [%d][%.*s].\n", result_code,
                      result_code_string.length, result_code_string.data);
            user_error_message = talloc_strndup(kr->pd, result_code_string.data,
                                                result_code_string.length);
            if (user_error_message == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
            }
        }

        if (result_string.length > 0 && result_string.data[0] != '\0') {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "krb5_change_password failed [%d][%.*s].\n", result_code,
                      result_string.length, result_string.data);
            talloc_free(user_error_message);
            user_error_message = talloc_strndup(kr->pd, result_string.data,
                                                result_string.length);
            if (user_error_message == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
            }
        } else if (result_code == KRB5_KPASSWD_SOFTERROR) {
            user_error_message = talloc_strdup(kr->pd, "Please make sure the "
                                 "password meets the complexity constraints.");
            if (user_error_message == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
            }
        }

        if (user_error_message != NULL) {
            ret = pack_user_info_chpass_error(kr->pd, user_error_message,
                                              &user_resp_len, &user_resp);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "pack_user_info_chpass_error failed [%d]\n", ret);
            } else {
                ret = pam_add_response(kr->pd, SSS_PAM_USER_INFO, user_resp_len,
                                       user_resp);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
                }
            }
        }

        return ERR_CHPASS_FAILED;
    }

    krb5_free_cred_contents(kr->ctx, kr->creds);

    if (kr->otp == true) {
        user_info_type = SSS_PAM_USER_INFO_OTP_CHPASS;
        ret = pam_add_response(kr->pd, SSS_PAM_USER_INFO, sizeof(uint32_t),
                               (const uint8_t *) &user_info_type);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            /* Not fatal */
        }

        sss_authtok_set_empty(kr->pd->newauthtok);
        return map_krb5_error(kerr);
    }

    /* We changed some of the GIC options for the password change, now we have
     * to change them back to get a fresh TGT. */
    revert_changepw_options(kr->cli_opts, kr->options);

    ret = sss_authtok_set_password(kr->pd->authtok, newpassword, 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set password for fresh TGT.\n");
        return ret;
    }

    kerr = get_and_save_tgt(kr, newpassword);

    sss_authtok_set_empty(kr->pd->authtok);
    sss_authtok_set_empty(kr->pd->newauthtok);

    if (kerr == 0) {
        kerr = k5c_attach_ccname_msg(kr);
    }
    return map_krb5_error(kerr);
}

static errno_t pam_add_prompting(struct krb5_req *kr)
{
    int ret;

    /* add OTP tokeninfo message if available */
    if (kr->otp) {
        ret = k5c_attach_otp_info_msg(kr);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "k5c_attach_otp_info_msg failed.\n");
            return ret;
        }
    }

    if (kr->password_prompting) {
        ret = pam_add_response(kr->pd, SSS_PASSWORD_PROMPTING, 0, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            return ret;
        }
    }

    if (kr->pkinit_prompting) {
        ret = pam_add_response(kr->pd, SSS_CERT_AUTH_PROMPTING, 0,
                               NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            return ret;
        }
    }

    return EOK;
}

static errno_t tgt_req_child(struct krb5_req *kr)
{
    const char *password = NULL;
    krb5_error_code kerr;
    int ret;

    DEBUG(SSSDBG_TRACE_LIBS, "Attempting to get a TGT\n");

    /* No password is needed for pre-auth or if we have 2FA or SC */
    if (kr->pd->cmd != SSS_PAM_PREAUTH
            && sss_authtok_get_type(kr->pd->authtok) != SSS_AUTHTOK_TYPE_2FA
            && sss_authtok_get_type(kr->pd->authtok) != SSS_AUTHTOK_TYPE_2FA_SINGLE
            && sss_authtok_get_type(kr->pd->authtok) != SSS_AUTHTOK_TYPE_SC_PIN
            && sss_authtok_get_type(kr->pd->authtok)
                                                != SSS_AUTHTOK_TYPE_SC_KEYPAD) {
        ret = sss_authtok_get_password(kr->pd->authtok, &password, NULL);
        switch (ret) {
        case EOK:
            break;

        case EACCES:
            DEBUG(SSSDBG_OP_FAILURE, "Invalid authtok type\n");
            return ERR_INVALID_CRED_TYPE;
            break;

        default:
            DEBUG(SSSDBG_OP_FAILURE, "No credentials available\n");
            return ERR_NO_CREDS;
            break;
        }
    }

    kerr = get_and_save_tgt(kr, password);

    if (kerr != KRB5KDC_ERR_KEY_EXP) {
        if (kr->pd->cmd == SSS_PAM_PREAUTH) {
            ret = pam_add_prompting(kr);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_prompting failed.\n");
                goto done;
            }
        } else {
            if (kerr == 0) {
                kerr = k5c_attach_ccname_msg(kr);
            }
        }
        ret = map_krb5_error(kerr);
        goto done;
    }

    /* If the password is expired, the KDC will always return
       KRB5KDC_ERR_KEY_EXP regardless if the supplied password is correct or
       not. In general the password can still be used to get a changepw ticket.
       So we validate the password by trying to get a changepw ticket. */
    DEBUG(SSSDBG_TRACE_LIBS, "Password was expired\n");
    kerr = sss_krb5_get_init_creds_opt_set_expire_callback(kr->ctx,
                                                           kr->options,
                                                           NULL, NULL);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unset expire callback, continue ...\n");
    }

    set_changepw_options(kr->options);
    kerr = kr->krb5_get_init_creds_password(kr->ctx, kr->creds, kr->princ_orig,
                                            password_or_responder(password),
                                            sss_krb5_prompter, kr, 0,
                                            SSSD_KRB5_CHANGEPW_PRINCIPAL,
                                            kr->options);

    krb5_free_cred_contents(kr->ctx, kr->creds);

    if (kr->pd->cmd == SSS_PAM_PREAUTH) {
        /* Any errors are ignored during pre-auth, only data is collected to
         * be send back to the client. Even if the password is expired we
         * should now know which authentication methods are available to
         * update the password. */
        DEBUG(SSSDBG_TRACE_FUNC,
              "krb5_get_init_creds_password returned [%d] during pre-auth, "
              "ignored.\n", kerr);
        ret = pam_add_prompting(kr);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_prompting failed.\n");
            goto done;
        }
        goto done;
    }

    if (kerr == 0) {
        ret = ERR_CREDS_EXPIRED;

        /* If the password is expired, we can safely remove the ccache from the
         * cache and disk if it is not actively used anymore. This will allow
         * to create a new random ccache if sshd with privilege separation is
         * used. */
        if (kr->old_cc_active == false && kr->old_ccname) {
            ret = safe_remove_old_ccache_file(kr->old_ccname, NULL,
                    kr->uid, kr->gid);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                        "Failed to remove old ccache file [%s], "
                        "please remove it manually.\n", kr->old_ccname);
            }
            ret = ERR_CREDS_EXPIRED_CCACHE;
        }
    } else {
        ret = map_krb5_error(kerr);
    }

done:
    sss_authtok_set_empty(kr->pd->authtok);
    return ret;
}

static errno_t kuserok_child(struct krb5_req *kr)
{
    krb5_boolean access_allowed;
    krb5_error_code kerr;

    DEBUG(SSSDBG_TRACE_LIBS, "Verifying if principal can log in as user\n");

    /* krb5_kuserok tries to verify that kr->pd->user is a locally known
     * account, so we have to unset _SSS_LOOPS to make getpwnam() work. */
    if (unsetenv("_SSS_LOOPS") != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to unset _SSS_LOOPS, "
                  "krb5_kuserok will most certainly fail.\n");
    }

    kerr = krb5_set_default_realm(kr->ctx, kr->realm);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_set_default_realm failed, "
                  "krb5_kuserok may fail.\n");
    }

    access_allowed = krb5_kuserok(kr->ctx, kr->princ, kr->pd->user);
    DEBUG(SSSDBG_TRACE_LIBS,
          "Access was %s\n", access_allowed ? "allowed" : "denied");

    if (access_allowed) {
        return EOK;
    }

    return ERR_AUTH_DENIED;
}

static errno_t renew_tgt_child(struct krb5_req *kr)
{
    const char *ccname;
    krb5_ccache ccache = NULL;
    krb5_error_code kerr;
    int ret;

    DEBUG(SSSDBG_TRACE_LIBS, "Renewing a ticket\n");

    ret = sss_authtok_get_ccfile(kr->pd->authtok, &ccname, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unsupported authtok type for TGT renewal [%d].\n",
               sss_authtok_get_type(kr->pd->authtok));
        return ERR_INVALID_CRED_TYPE;
    }

    kerr = krb5_cc_resolve(kr->ctx, ccname, &ccache);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        goto done;
    }

    kerr = krb5_get_renewed_creds(kr->ctx, kr->creds, kr->princ, ccache, NULL);
    if (kerr != 0) {
        goto done;
    }

    if (kr->validate) {
        kerr = validate_tgt(kr);
        if (kerr != 0) {
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
            goto done;
        }

    } else {
        DEBUG(SSSDBG_CONF_SETTINGS, "TGT validation is disabled.\n");
    }

    kerr = krb5_cc_initialize(kr->ctx, ccache, kr->princ);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        goto done;
    }

    kerr = krb5_cc_store_cred(kr->ctx, ccache, kr->creds);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        goto done;
    }

    kerr = add_ticket_times_and_upn_to_response(kr);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "add_ticket_times_and_upn_to_response failed.\n");
    }

    kerr = k5c_attach_ccname_msg(kr);

done:
    krb5_free_cred_contents(kr->ctx, kr->creds);

    if (ccache != NULL) {
        krb5_cc_close(kr->ctx, ccache);
    }

    if (kerr == KRB5KRB_AP_ERR_TKT_EXPIRED) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Attempted to renew an expired TGT, changing the error code "
              "to expired creds internally\n");
        /* map_krb5_error() won't touch the SSSD-internal code */
        kerr = ERR_CREDS_EXPIRED;
    }

    return map_krb5_error(kerr);
}

static errno_t create_empty_ccache(struct krb5_req *kr)
{
    krb5_creds *creds = NULL;
    krb5_error_code kerr;

    if (kr->old_cc_valid == false) {
        DEBUG(SSSDBG_TRACE_LIBS, "Creating empty ccache\n");
        kerr = create_empty_cred(kr->ctx, kr->princ, &creds);
        if (kerr == 0) {
            kerr = create_ccache(kr->ccname, creds);
        }
    } else {
        DEBUG(SSSDBG_TRACE_LIBS, "Existing ccache still valid, reusing\n");
        kerr = 0;
    }

    if (kerr == 0) {
        kerr = k5c_attach_ccname_msg(kr);
    }

    krb5_free_creds(kr->ctx, creds);

    return map_krb5_error(kerr);
}

static errno_t unpack_authtok(struct sss_auth_token *tok,
                              uint8_t *buf, size_t size, size_t *p)
{
    uint32_t auth_token_type;
    uint32_t auth_token_length;
    errno_t ret = EOK;

    SAFEALIGN_COPY_UINT32_CHECK(&auth_token_type, buf + *p, size, p);
    SAFEALIGN_COPY_UINT32_CHECK(&auth_token_length, buf + *p, size, p);
    if (auth_token_length > (size - *p)) {
        return EINVAL;
    }
    switch (auth_token_type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        sss_authtok_set_empty(tok);
        break;
    case SSS_AUTHTOK_TYPE_PASSWORD:
        ret = sss_authtok_set_password(tok, (char *)(buf + *p), 0);
        break;
    case SSS_AUTHTOK_TYPE_CCFILE:
        ret = sss_authtok_set_ccfile(tok, (char *)(buf + *p), 0);
        break;
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
        ret = sss_authtok_set_2fa_single(tok, (char *)(buf + *p), 0);
        break;
    case SSS_AUTHTOK_TYPE_2FA:
    case SSS_AUTHTOK_TYPE_SC_PIN:
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
    case SSS_AUTHTOK_TYPE_OAUTH2:
    case SSS_AUTHTOK_TYPE_PASSKEY:
    case SSS_AUTHTOK_TYPE_PASSKEY_KRB:
    case SSS_AUTHTOK_TYPE_PASSKEY_REPLY:
        ret = sss_authtok_set(tok, auth_token_type, (buf + *p),
                              auth_token_length);
        break;
    default:
        return EINVAL;
    }

    if (ret == EOK) {
        *p += auth_token_length;
    }
    return ret;
}

static const char *krb5_child_command_to_str(int cmd)
{
    switch (cmd) {
    case SSS_PAM_AUTHENTICATE:
        return "auth";
    case SSS_PAM_CHAUTHTOK:
        return "password change";
    case SSS_PAM_CHAUTHTOK_PRELIM:
        return "password change checks";
    case SSS_PAM_ACCT_MGMT:
        return "account management";
    case SSS_CMD_RENEW:
        return "ticket renewal";
    case SSS_PAM_PREAUTH:
        return "pre-auth";
    }

    DEBUG(SSSDBG_MINOR_FAILURE, "Unexpected command %d\n", cmd);
    return "-unexpected-";
}

static errno_t unpack_buffer(uint8_t *buf, size_t size,
                             struct krb5_req *kr, uint32_t *offline)
{
    size_t p = 0;
    uint32_t len;
    uint32_t validate;
    uint32_t posix_domain;
    uint32_t send_pac;
    uint32_t use_enterprise_princ;
    struct pam_data *pd;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_LIBS, "total buffer size: [%zu]\n", size);

    if (!offline || !kr) return EINVAL;

    pd = create_pam_data(kr);
    if (pd == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "create_pam_data failed.\n");
        return ENOMEM;
    }
    kr->pd = pd;

    SAFEALIGN_COPY_UINT32_CHECK(&pd->cmd, buf + p, size, &p);
    SAFEALIGN_COPY_UINT32_CHECK(&kr->uid, buf + p, size, &p);
    SAFEALIGN_COPY_UINT32_CHECK(&kr->gid, buf + p, size, &p);
    SAFEALIGN_COPY_UINT32_CHECK(&validate, buf + p, size, &p);
    kr->validate = (validate == 0) ? false : true;
    SAFEALIGN_COPY_UINT32_CHECK(&posix_domain, buf + p, size, &p);
    kr->posix_domain = (posix_domain == 0) ? false : true;
    SAFEALIGN_COPY_UINT32_CHECK(offline, buf + p, size, &p);
    SAFEALIGN_COPY_UINT32_CHECK(&send_pac, buf + p, size, &p);
    kr->send_pac = (send_pac == 0) ? false : true;
    SAFEALIGN_COPY_UINT32_CHECK(&use_enterprise_princ, buf + p, size, &p);
    kr->use_enterprise_princ = (use_enterprise_princ == 0) ? false : true;
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
    if (len > size - p) return EINVAL;
    kr->upn = talloc_strndup(kr, (char *)(buf + p), len);
    if (kr->upn == NULL) return ENOMEM;
    p += len;

    DEBUG(SSSDBG_CONF_SETTINGS,
          "cmd [%d (%s)] uid [%llu] gid [%llu] validate [%s] "
           "enterprise principal [%s] offline [%s] UPN [%s]\n",
           pd->cmd, krb5_child_command_to_str(pd->cmd),
           (unsigned long long) kr->uid, (unsigned long long) kr->gid,
           kr->validate ? "true" : "false",
           kr->use_enterprise_princ ? "true" : "false",
           *offline ? "true" : "false", kr->upn ? kr->upn : "none");

    if (pd->cmd == SSS_PAM_AUTHENTICATE ||
        pd->cmd == SSS_PAM_PREAUTH ||
        pd->cmd == SSS_CMD_RENEW ||
        pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM || pd->cmd == SSS_PAM_CHAUTHTOK) {
        SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
        if (len > size - p) return EINVAL;
        kr->ccname = talloc_strndup(kr, (char *)(buf + p), len);
        if (kr->ccname == NULL) return ENOMEM;
        p += len;

        SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
        if (len > size - p) return EINVAL;

        if (len > 0) {
            kr->old_ccname = talloc_strndup(kr, (char *)(buf + p), len);
            if (kr->old_ccname == NULL) return ENOMEM;
            p += len;
        } else {
            DEBUG(SSSDBG_TRACE_INTERNAL, "No old ccache\n");
        }

        SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
        if (len > size - p) return EINVAL;

        if (len > 0) {
            kr->keytab = talloc_strndup(kr, (char *)(buf + p), len);
            p += len;
        } else {
            kr->keytab = NULL;
        }

        ret = unpack_authtok(pd->authtok, buf, size, &p);
        if (ret) {
            return ret;
        }

        DEBUG(SSSDBG_CONF_SETTINGS,
              "ccname: [%s] old_ccname: [%s] keytab: [%s]\n",
              kr->ccname,
              kr->old_ccname ? kr->old_ccname : "not set",
              kr->keytab ? kr->keytab : "not set");
    } else {
        kr->ccname = NULL;
        kr->old_ccname = NULL;
        kr->keytab = NULL;
        sss_authtok_set_empty(pd->authtok);
    }

    if (pd->cmd == SSS_PAM_CHAUTHTOK) {
        ret = unpack_authtok(pd->newauthtok, buf, size, &p);
        if (ret) {
            return ret;
        }
    } else {
        sss_authtok_set_empty(pd->newauthtok);
    }

    if (pd->cmd == SSS_PAM_ACCT_MGMT) {
        SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
        if (len > size - p) return EINVAL;
        pd->user = talloc_strndup(pd, (char *)(buf + p), len);
        if (pd->user == NULL) return ENOMEM;
        p += len;
        DEBUG(SSSDBG_CONF_SETTINGS, "user: [%s]\n", pd->user);
    } else {
        pd->user = NULL;
    }

    return EOK;
}

static int krb5_cleanup(struct krb5_req *kr)
{
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
    if (kr->princ_orig != NULL)
        krb5_free_principal(kr->ctx, kr->princ_orig);
    if (kr->ctx != NULL)
        krb5_free_context(kr->ctx);

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
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_cc_resolve failed.\n");
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, krberr);
        goto done;
    }

    memset(&mcred, 0, sizeof(mcred));
    memset(&cred, 0, sizeof(mcred));

    mcred.server = server_principal;
    mcred.client = client_principal;

    krberr = krb5_cc_retrieve_cred(ctx, ccache, 0, &mcred, &cred);
    if (krberr == KRB5_FCC_NOFILE) {
        DEBUG(SSSDBG_TRACE_LIBS, "FAST ccache must be recreated\n");
    } else if (krberr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_cc_retrieve_cred failed\n");
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, krberr);
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

static krb5_error_code get_fast_ccache_with_anonymous_pkinit(krb5_context ctx,
                                                    uid_t fast_uid,
                                                    gid_t fast_gid,
                                                    bool posix_domain,
                                                    struct cli_opts *cli_opts,
                                                    krb5_keytab keytab,
                                                    krb5_principal client_princ,
                                                    char *ccname,
                                                    const char *realm)
{
    krb5_error_code kerr;
    krb5_get_init_creds_opt *options;
    struct sss_creds *saved_creds = NULL;
    krb5_preauthtype pkinit = KRB5_PADATA_PK_AS_REQ;
    krb5_creds creds = { 0 };

    kerr = sss_krb5_get_init_creds_opt_alloc(ctx, &options);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    krb5_get_init_creds_opt_set_tkt_life(options, 10 * 60);
    krb5_get_init_creds_opt_set_renew_life(options, 0);
    krb5_get_init_creds_opt_set_forwardable(options, 0);
    krb5_get_init_creds_opt_set_proxiable(options, 0);
    krb5_get_init_creds_opt_set_canonicalize(options, 1);
    krb5_get_init_creds_opt_set_preauth_list(options, &pkinit, 1);

    kerr = krb5_build_principal(ctx, &creds.server, strlen(realm), realm,
                                KRB5_TGS_NAME, realm, NULL);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create principal.\n");
        goto done;
    }

    creds.client = client_princ;

    kerr = krb5_get_init_creds_password(ctx, &creds, client_princ, NULL,
                                        sss_krb5_prompter, NULL, 0, NULL,
                                        options);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to get FAST credential with anonymous PKINIT.\n");
        goto done;
    }

    kerr = switch_creds(NULL, fast_uid, fast_gid, 0, NULL, &saved_creds);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to switch credentials to store FAST ccache with "
              "expected permissions.\n");
        goto done;
    }

    kerr = create_ccache(ccname, &creds);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to store FAST ccache.\n");
        goto done;
    }

    kerr = restore_creds(saved_creds);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to restore credentials, krb5_child might run with wrong "
              "permissions, aborting.\n");
        goto done;
    }

done:
    sss_krb5_get_init_creds_opt_free(ctx, options);
    talloc_free(saved_creds);

    return kerr;
}

static krb5_error_code get_fast_ccache_with_keytab(krb5_context ctx,
                                                   uid_t fast_uid,
                                                   gid_t fast_gid,
                                                   bool posix_domain,
                                                   struct cli_opts *cli_opts,
                                                   krb5_keytab keytab,
                                                   krb5_principal client_princ,
                                                   char *ccname)
{
    krb5_error_code kerr;
    pid_t fchild_pid;
    int status;

    fchild_pid = fork();
    switch (fchild_pid) {
        case -1:
            DEBUG(SSSDBG_CRIT_FAILURE, "fork failed\n");
            return EIO;
        case 0:
            /* Child */
            debug_prg_name = talloc_asprintf(NULL, "krb5_child[%d]", getpid());
            if (debug_prg_name == NULL) {
                debug_prg_name = "krb5_child";
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
                /* Try to carry on */
            }

            kerr = k5c_become_user(fast_uid, fast_gid, posix_domain);
            if (kerr != 0) {
                DEBUG(SSSDBG_CRIT_FAILURE, "become_user failed: %d\n", kerr);
                exit(1);
            }
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Running as [%"SPRIuid"][%"SPRIgid"].\n", geteuid(), getegid());

            kerr = get_and_save_tgt_with_keytab(ctx, cli_opts, client_princ,
                                                keytab, ccname);
            if (kerr != 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "get_and_save_tgt_with_keytab failed: %d\n", kerr);
                exit(2);
            }
            exit(0);
        default:
            /* Parent */
            do {
                errno = 0;
                kerr = waitpid(fchild_pid, &status, 0);
            } while (kerr == -1 && errno == EINTR);

            if (kerr > 0) {
                if (WIFEXITED(status)) {
                    kerr = WEXITSTATUS(status);
                    /* Don't blindly fail if the child fails, but check
                     * the ccache again */
                    if (kerr != 0) {
                        DEBUG(SSSDBG_MINOR_FAILURE,
                              "Creating FAST ccache failed, krb5_child will "
                              "likely fail!\n");
                    }
                } else {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "krb5_child subprocess %d terminated unexpectedly\n",
                          fchild_pid);
                }
            } else {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to wait for child %d\n", fchild_pid);
                /* Let the code re-check the TGT times and fail if we
                 * can't find the updated principal */
            }
    }

    return 0;
}

static krb5_error_code check_fast_ccache(TALLOC_CTX *mem_ctx,
                                         krb5_context ctx,
                                         uid_t fast_uid,
                                         gid_t fast_gid,
                                         bool posix_domain,
                                         struct cli_opts *cli_opts,
                                         const char *primary,
                                         const char *realm,
                                         const char *keytab_name,
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
    krb5_principal client_search_princ = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ccname = talloc_asprintf(tmp_ctx, "FILE:%s/fast_ccache_%s", DB_PATH, realm);
    if (ccname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        kerr = ENOMEM;
        goto done;
    }

    if (cli_opts->fast_use_anonymous_pkinit) {
        kerr = krb5_build_principal(ctx, &client_princ, strlen(realm), realm,
                                    KRB5_WELLKNOWN_NAMESTR,
                                    KRB5_ANONYMOUS_PRINCSTR, NULL);
        if (kerr != 0) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to create anonymous PKINIT principal.\n");
            goto done;
        }

        /* Anonymous pkinit is using the canonical principal
         * WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS so we need an additional
         * client_search_princ to find it in the ccache to determine the
         * lifetime. */
        kerr = krb5_build_principal(ctx, &client_search_princ,
                                    strlen(KRB5_ANONYMOUS_REALMSTR),
                                    KRB5_ANONYMOUS_REALMSTR,
                                    KRB5_WELLKNOWN_NAMESTR,
                                    KRB5_ANONYMOUS_PRINCSTR, NULL);
        if (kerr != 0) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to create anonymous PKINIT principal.\n");
            goto done;
        }
    } else {
        if (keytab_name != NULL) {
            kerr = krb5_kt_resolve(ctx, keytab_name, &keytab);
        } else {
            kerr = krb5_kt_default(ctx, &keytab);
        }
        if (kerr) {
            const char *__err_msg = sss_krb5_get_error_message(ctx, kerr);
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to read keytab file [%s]: %s\n",
                   sss_printable_keytab_name(ctx, keytab_name),
                   __err_msg);
            sss_krb5_free_error_message(ctx, __err_msg);
            goto done;
        }

        kerr = find_principal_in_keytab(ctx, keytab, primary, realm, &client_princ);
        if (kerr != 0) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "find_principal_in_keytab failed for principal %s@%s.\n",
                   primary, realm);
            goto done;
        }
    }

    server_name = talloc_asprintf(tmp_ctx, "krbtgt/%s@%s", realm, realm);
    if (server_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        kerr = ENOMEM;
        goto done;
    }

    kerr = krb5_parse_name(ctx, server_name, &server_princ);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_parse_name failed.\n");
        goto done;
    }

    memset(&tgtt, 0, sizeof(tgtt));
    kerr = get_tgt_times(ctx, ccname, server_princ,
                         client_search_princ != NULL ? client_search_princ
                                                     : client_princ,
                         &tgtt);
    if (kerr == 0) {
        if (tgtt.endtime > time(NULL)) {
            DEBUG(SSSDBG_FUNC_DATA, "FAST TGT is still valid.\n");
            goto done;
        }
    }

    /* Need to recreate the FAST ccache */
    if (cli_opts->fast_use_anonymous_pkinit) {
        kerr = get_fast_ccache_with_anonymous_pkinit(ctx, fast_uid, fast_gid,
                                                     posix_domain, cli_opts,
                                                     keytab, client_princ,
                                                     ccname, realm);
        if (kerr != 0) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Creating FAST ccache with anonymous "
                                        "PKINIT failed, krb5_child will "
                                        "likely fail!\n");
        }
    } else {
        kerr = get_fast_ccache_with_keytab(ctx, fast_uid, fast_gid, posix_domain,
                                           cli_opts, keytab, client_princ, ccname);
        if (kerr != 0) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Creating FAST ccache with keytab failed, "
                                        "krb5_child will likely fail!\n");
        }
    }

    /* Check the ccache times again. Should be updated ... */
    memset(&tgtt, 0, sizeof(tgtt));
    kerr = get_tgt_times(ctx, ccname, server_princ,
                         client_search_princ != NULL ? client_search_princ
                                                     : client_princ,
                         &tgtt);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "get_tgt_times() failed\n");
        goto done;
    }

    if (tgtt.endtime < time(NULL)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "FAST TGT was renewed but is already expired, please check that "
              "time is synchronized with server.\n");
        kerr = ERR_CREDS_EXPIRED;
        goto done;
    }
    DEBUG(SSSDBG_FUNC_DATA, "FAST TGT was successfully recreated!\n");

done:
    if (client_princ != NULL) {
        krb5_free_principal(ctx, client_princ);
    }
    if (client_search_princ != NULL) {
        krb5_free_principal(ctx, client_search_princ);
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

static errno_t k5c_recv_data(struct krb5_req *kr, int fd, uint32_t *offline)
{
    uint8_t buf[IN_BUF_SIZE];
    ssize_t len;
    errno_t ret;

    errno = 0;
    len = sss_atomic_read_safe_s(fd, buf, IN_BUF_SIZE, NULL);
    if (len == -1) {
        ret = errno;
        ret = (ret == 0) ? EINVAL: ret;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "read failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    ret = unpack_buffer(buf, len, kr, offline);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "unpack_buffer failed.\n");
    }

    return ret;
}

static int k5c_setup_fast(struct krb5_req *kr, bool demand)
{
    krb5_principal fast_princ_struct;
    krb5_data *realm_data;
    char *fast_principal_realm;
    char *fast_principal;
    krb5_error_code kerr;
    char *tmp_str = NULL;
    char *new_ccname;

    if (kr->cli_opts->fast_principal) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Fast principal is set to [%s]\n",
                                    kr->cli_opts->fast_principal);
        kerr = krb5_parse_name(kr->ctx, kr->cli_opts->fast_principal,
                               &fast_princ_struct);
        if (kerr) {
            DEBUG(SSSDBG_CRIT_FAILURE, "krb5_parse_name failed.\n");
            return kerr;
        }
        kerr = sss_krb5_unparse_name_flags(kr->ctx, fast_princ_struct,
                                       KRB5_PRINCIPAL_UNPARSE_NO_REALM,
                                       &tmp_str);
        if (kerr) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_krb5_unparse_name_flags failed.\n");
            return kerr;
        }
        fast_principal = talloc_strdup(kr, tmp_str);
        if (!fast_principal) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
            return KRB5KRB_ERR_GENERIC;
        }
        free(tmp_str);
        realm_data = krb5_princ_realm(kr->ctx, fast_princ_struct);
        fast_principal_realm = talloc_asprintf(kr, "%.*s", realm_data->length,
                                                           realm_data->data);
        if (!fast_principal_realm) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
            return ENOMEM;
        }
    } else {
        fast_principal_realm = kr->realm;
        fast_principal = NULL;
    }

    kerr = check_fast_ccache(kr, kr->ctx, kr->fast_uid, kr->fast_gid,
                             kr->posix_domain, kr->cli_opts,
                             fast_principal, fast_principal_realm,
                             kr->keytab, &kr->fast_ccname);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "check_fast_ccache failed.\n");
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    kerr = copy_ccache_into_memory(kr, kr->ctx, kr->fast_ccname, &new_ccname);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "copy_ccache_into_memory failed.\n");
        return kerr;
    }

    talloc_free(kr->fast_ccname);
    kr->fast_ccname = new_ccname;

    kerr = sss_krb5_get_init_creds_opt_set_fast_ccache_name(kr->ctx,
                                                            kr->options,
                                                            kr->fast_ccname);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_krb5_get_init_creds_opt_set_fast_ccache_name "
                  "failed.\n");
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    if (demand) {
        kerr = sss_krb5_get_init_creds_opt_set_fast_flags(kr->ctx,
                                                kr->options,
                                                SSS_KRB5_FAST_REQUIRED);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sss_krb5_get_init_creds_opt_set_fast_flags "
                      "failed.\n");
            KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
            return kerr;
        }
    }

    return EOK;
}

static errno_t check_use_fast(const char *use_fast_str,
                              enum k5c_fast_opt *_fast_val)
{
    enum k5c_fast_opt fast_val;

    if (use_fast_str == NULL || strcasecmp(use_fast_str, "never") == 0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Not using FAST.\n");
        fast_val = K5C_FAST_NEVER;
    } else if (strcasecmp(use_fast_str, "try") == 0) {
        fast_val = K5C_FAST_TRY;
    } else if (strcasecmp(use_fast_str, "demand") == 0) {
        fast_val = K5C_FAST_DEMAND;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
                "Unsupported value [%s] for krb5_use_fast.\n",
                use_fast_str);
        return EINVAL;
    }

    *_fast_val = fast_val;
    return EOK;
}

static errno_t old_ccache_valid(struct krb5_req *kr, bool *_valid)
{
    errno_t ret;
    bool valid;

    valid = false;

    ret = sss_krb5_cc_verify_ccache(kr->old_ccname,
                                    kr->uid, kr->gid,
                                    kr->realm, kr->upn);
    switch (ret) {
        case ERR_NOT_FOUND:
        case ENOENT:
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Saved ccache %s doesn't exist, ignoring\n", kr->old_ccname);
            break;
        case EINVAL:
            /* cache found but no TGT or expired */
        case EOK:
            valid = true;
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot check if saved ccache %s is valid\n",
                   kr->old_ccname);
            return ret;
    }

    *_valid = valid;
    return EOK;
}

static int k5c_check_old_ccache(struct krb5_req *kr)
{
    errno_t ret;

    if (kr->old_ccname) {
        ret = old_ccache_valid(kr, &kr->old_cc_valid);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "old_ccache_valid failed.\n");
            return ret;
        }

        ret = check_if_uid_is_active(kr->uid, &kr->old_cc_active);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "check_if_uid_is_active failed.\n");
            return ret;
        }

        DEBUG(SSSDBG_TRACE_ALL,
                "Ccache_file is [%s] and is %s active and TGT is %s valid.\n",
                kr->old_ccname ? kr->old_ccname : "not set",
                kr->old_cc_active ? "" : "not",
                kr->old_cc_valid ? "" : "not");
    }

    return EOK;
}

static int k5c_precreate_ccache(struct krb5_req *kr, uint32_t offline)
{
    errno_t ret;

    /* The ccache file should be (re)created if one of the following conditions
     * is true:
     * - it doesn't exist (kr->old_ccname == NULL)
     * - the backend is online and the current ccache file is not used, i.e
     * the related user is currently not logged in and it is not a renewal
     * request
     * (offline && !kr->old_cc_active && kr->pd->cmd != SSS_CMD_RENEW)
     * - the backend is offline and the current cache file not used and
     * it does not contain a valid TGT
     * (offline && !kr->old_cc_active && !kr->valid_tgt)
     */
    if (kr->old_ccname == NULL ||
            (offline && !kr->old_cc_active && !kr->old_cc_valid) ||
            (!offline && !kr->old_cc_active && kr->pd->cmd != SSS_CMD_RENEW)) {
        DEBUG(SSSDBG_TRACE_ALL, "Recreating ccache\n");

        ret = sss_krb5_precreate_ccache(kr->ccname, kr->uid, kr->gid);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "ccache creation failed.\n");
            return ret;
        }
    } else {
        /* We can reuse the old ccache */
        kr->ccname = kr->old_ccname;
    }

    return EOK;
}

static int k5c_ccache_setup(struct krb5_req *kr, uint32_t offline)
{
    errno_t ret;

    if (kr->pd->cmd == SSS_PAM_ACCT_MGMT) {
        return EOK;
    }

    ret = k5c_check_old_ccache(kr);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot check old ccache [%s]: [%d][%s]. " \
                                   "Assuming old cache is invalid " \
                                   "and not used.\n",
                                   kr->old_ccname, ret, sss_strerror(ret));
    }

    /* Pre-creating the ccache must be done as root, otherwise we can't mkdir
     * some of the DIR: cache components. One example is /run/user/$UID because
     * logind doesn't create the directory until the session phase, whereas
     * we need the directory during the auth phase already
     */
    ret = k5c_precreate_ccache(kr, offline);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot precreate ccache\n");
        return ret;
    }

    return EOK;
}

static int k5c_setup(struct krb5_req *kr, uint32_t offline)
{
    krb5_error_code kerr;
    int parse_flags;

    /* Set the global error context */
    krb5_error_ctx = kr->ctx;

    if (debug_level & SSSDBG_TRACE_ALL) {
        kerr = sss_child_set_krb5_tracing(kr->ctx);
        if (kerr != 0) {
            KRB5_CHILD_DEBUG(SSSDBG_MINOR_FAILURE, kerr);
            return EIO;
        }
    }

    /* Enterprise principals require that a default realm is available. To
     * make SSSD more robust in the case that the default realm option is
     * missing in krb5.conf or to allow SSSD to work with multiple unconnected
     * realms (e.g. AD domains without trust between them) the default realm
     * will be set explicitly. */
    if (kr->use_enterprise_princ) {
        kerr = krb5_set_default_realm(kr->ctx, kr->realm);
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "krb5_set_default_realm failed.\n");
        }
    }

    parse_flags = kr->use_enterprise_princ ? KRB5_PRINCIPAL_PARSE_ENTERPRISE : 0;
    kerr = sss_krb5_parse_name_flags(kr->ctx, kr->upn, parse_flags, &kr->princ);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    kerr = krb5_parse_name(kr->ctx, kr->upn, &kr->princ_orig);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    kerr = krb5_unparse_name(kr->ctx, kr->princ, &kr->name);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    kr->creds = calloc(1, sizeof(krb5_creds));
    if (kr->creds == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "calloc failed.\n");
        return ENOMEM;
    }

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_RESPONDER
    kerr = krb5_get_init_creds_opt_set_responder(kr->ctx, kr->options,
                                                 sss_krb5_responder, kr);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }
#endif

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_CHANGE_PASSWORD_PROMPT
    /* A prompter is used to catch messages about when a password will
     * expire. The library shall not use the prompter to ask for a new password
     * but shall return KRB5KDC_ERR_KEY_EXP. */
    krb5_get_init_creds_opt_set_change_password_prompt(kr->options, 0);
#endif

    kerr = set_lifetime_options(kr->cli_opts, kr->options);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "set_lifetime_options failed.\n");
        return kerr;
    }

    if (!offline) {
        set_canonicalize_option(kr->cli_opts, kr->options);
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

    return kerr;
}

static krb5_error_code check_keytab_name(struct krb5_req *kr)
{
    krb5_error_code kerr;
    char krb5_conf_keytab[MAX_KEYTAB_NAME_LEN];
    char *path_start = NULL;

    if (kr->keytab == NULL && (
        kr->pd->cmd == SSS_PAM_AUTHENTICATE ||
        kr->pd->cmd == SSS_PAM_PREAUTH ||
        kr->pd->cmd == SSS_CMD_RENEW ||
        kr->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM ||
        kr->pd->cmd == SSS_PAM_CHAUTHTOK)) {

        DEBUG(SSSDBG_TRACE_FUNC,
              "Missing krb5_keytab option for domain, looking for default one\n");

        kerr = krb5_kt_default_name(kr->ctx, krb5_conf_keytab, sizeof(krb5_conf_keytab));
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unable to get default keytab location from krb.conf\n");
            return kerr;
        }

        DEBUG(SSSDBG_TRACE_FUNC,
              "krb5_kt_default_name() returned: %s\n",
              krb5_conf_keytab);

        /* krb5_kt_default_name() can return file path with "FILE:" prefix,
           it need to be removed */
        if (0 == strncmp(krb5_conf_keytab, "FILE:", strlen("FILE:"))) {
            path_start = krb5_conf_keytab + strlen("FILE:");
        } else {
            path_start = krb5_conf_keytab;
        }

        kr->keytab = talloc_strndup(kr->pd, path_start, strlen(path_start));

        DEBUG(SSSDBG_TRACE_FUNC, "krb5_child will default to: %s\n", path_start);
    }

    return 0;
}

static krb5_error_code privileged_krb5_setup(struct krb5_req *kr,
                                             uint32_t offline)
{
    krb5_error_code kerr;
    int ret;
    char *mem_keytab;

    kr->realm = kr->cli_opts->realm;
    if (kr->realm == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Realm not available.\n");
    }

    kerr = krb5_init_context(&kr->ctx);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    kerr = check_keytab_name(kr);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    kerr = sss_krb5_get_init_creds_opt_alloc(kr->ctx, &kr->options);
    if (kerr != 0) {
        KRB5_CHILD_DEBUG(SSSDBG_CRIT_FAILURE, kerr);
        return kerr;
    }

    ret = check_use_fast(kr->cli_opts->use_fast_str, &kr->fast_val);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "check_use_fast failed.\n");
        return ret;
    }

    /* For ccache types FILE: and DIR: we might need to create some directory
     * components as root. Cache files are not needed during preauth. */
    if (kr->pd->cmd != SSS_PAM_PREAUTH) {
        ret = k5c_ccache_setup(kr, offline);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "k5c_ccache_setup failed.\n");
            return ret;
        }
    }

    if (!(offline ||
            (kr->fast_val == K5C_FAST_NEVER && kr->validate == false))) {
        /* A Keytab is not used if fast with anonymous pkinit is used (and validate is false)*/
        if (!(kr->cli_opts->fast_use_anonymous_pkinit == true && kr->validate == false)) {
            kerr = copy_keytab_into_memory(kr, kr->ctx, kr->keytab, &mem_keytab,
                                           NULL);
            if (kerr != 0) {
                DEBUG(SSSDBG_OP_FAILURE, "copy_keytab_into_memory failed.\n");
                return kerr;
            }

            talloc_free(kr->keytab);
            kr->keytab = mem_keytab;
        }

        if (kr->fast_val != K5C_FAST_NEVER) {
            kerr = k5c_setup_fast(kr, kr->fast_val == K5C_FAST_DEMAND);
            if (kerr != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Cannot set up FAST\n");
                return kerr;
            }
        }
    }

    if (kr->send_pac) {
        /* This is to establish connection with 'sssd_pac' while process
         * still runs under privileged user.
         */
        ret = sss_pac_check_and_open();
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Cannot open the PAC responder socket\n");
            /* Not fatal */
        }
    }

    return 0;
}

static void try_open_krb5_conf(void)
{
    int fd;
    int ret;

    fd = open("/etc/krb5.conf", O_RDONLY);
    if (fd != -1) {
        close(fd);
    } else {
        ret = errno;
        if (ret == EACCES || ret == EPERM) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "User with uid:%"SPRIuid" gid:%"SPRIgid" cannot read "
                  "/etc/krb5.conf. It might cause problems\n",
                  geteuid(), getegid());
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot open /etc/krb5.conf [%d]: %s\n",
                  ret, strerror(ret));
        }
    }
}

int main(int argc, const char *argv[])
{
    struct krb5_req *kr = NULL;
    uint32_t offline;
    int opt;
    poptContext pc;
    int dumpable = 1;
    int debug_fd = -1;
    const char *opt_logger = NULL;
    errno_t ret;
    krb5_error_code kerr;
    uid_t fast_uid = 0;
    gid_t fast_gid = 0;
    long chain_id = 0;
    struct cli_opts cli_opts = { 0 };
    int sss_creds_password = 0;
    long dummy_long = 0;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"dumpable", 0, POPT_ARG_INT, &dumpable, 0,
         _("Allow core dumps"), NULL },
        {"debug-fd", 0, POPT_ARG_INT, &debug_fd, 0,
         _("An open file descriptor for the debug logs"), NULL},
        SSSD_LOGGER_OPTS
        {CHILD_OPT_FAST_CCACHE_UID, 0, POPT_ARG_INT, &fast_uid, 0,
          _("The user to create FAST ccache as"), NULL},
        {CHILD_OPT_FAST_CCACHE_GID, 0, POPT_ARG_INT, &fast_gid, 0,
          _("The group to create FAST ccache as"), NULL},
        {CHILD_OPT_FAST_USE_ANONYMOUS_PKINIT, 0, POPT_ARG_NONE, NULL, 'A',
          _("Use anonymous PKINIT to request FAST armor ticket"), NULL},
        {CHILD_OPT_REALM, 0, POPT_ARG_STRING, &cli_opts.realm, 0,
         _("Kerberos realm to use"), NULL},
        {CHILD_OPT_LIFETIME, 0, POPT_ARG_STRING, &cli_opts.lifetime, 0,
         _("Requested lifetime of the ticket"), NULL},
        {CHILD_OPT_RENEWABLE_LIFETIME, 0, POPT_ARG_STRING, &cli_opts.rtime, 0,
         _("Requested renewable lifetime of the ticket"), NULL},
        {CHILD_OPT_USE_FAST, 0, POPT_ARG_STRING, &cli_opts.use_fast_str, 0,
         _("FAST options ('never', 'try', 'demand')"), NULL},
        {CHILD_OPT_FAST_PRINCIPAL, 0, POPT_ARG_STRING,
         &cli_opts.fast_principal, 0,
         _("Specifies the server principal to use for FAST"), NULL},
        {CHILD_OPT_CANONICALIZE, 0, POPT_ARG_NONE, NULL, 'C',
         _("Requests canonicalization of the principal name"), NULL},
        {CHILD_OPT_SSS_CREDS_PASSWORD, 0, POPT_ARG_NONE, &sss_creds_password,
         0, _("Use custom version of krb5_get_init_creds_password"), NULL},
        {CHILD_OPT_CHAIN_ID, 0, POPT_ARG_LONG, &chain_id,
         0, _("Tevent chain ID used for logging purposes"), NULL},
        {CHILD_OPT_CHECK_PAC, 0, POPT_ARG_LONG, &dummy_long, 0,
         _("Check PAC flags"), NULL},
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    cli_opts.canonicalize = false;
    cli_opts.fast_use_anonymous_pkinit = false;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        case 'A':
            cli_opts.fast_use_anonymous_pkinit = true;
            break;
        case 'C':
            cli_opts.canonicalize = true;
            break;
        default:
        fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            _exit(-1);
        }
    }

    cli_opts.check_pac_flags = 0;
    if (dummy_long >= 0 && dummy_long <= UINT32_MAX) {
        cli_opts.check_pac_flags = (uint32_t) dummy_long;
    } else {
        fprintf(stderr, "\nInvalid value [%ld] of check-pac option\n\n",
                        dummy_long);
        poptPrintUsage(pc, stderr, 0);
        _exit(-1);
    }

    poptFreeContext(pc);

    prctl(PR_SET_DUMPABLE, (dumpable == 0) ? 0 : 1);

    debug_prg_name = talloc_asprintf(NULL, "krb5_child[%d]", getpid());
    if (!debug_prg_name) {
        debug_prg_name = "krb5_child";
        ERROR("talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (debug_fd != -1) {
        opt_logger = sss_logger_str[FILES_LOGGER];
        ret = set_debug_file_from_fd(debug_fd);
        if (ret != EOK) {
            opt_logger = sss_logger_str[STDERR_LOGGER];
            ERROR("set_debug_file_from_fd failed.\n");
        }
    }

    sss_chain_id_set_format(DEBUG_CHAIN_ID_FMT_RID);
    sss_chain_id_set((uint64_t)chain_id);

    DEBUG_INIT(debug_level, opt_logger);

    DEBUG(SSSDBG_TRACE_FUNC, "krb5_child started.\n");

    kr = talloc_zero(NULL, struct krb5_req);
    if (kr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }
    talloc_steal(kr, debug_prg_name);

    kr->fast_uid = fast_uid;
    kr->fast_gid = fast_gid;
    kr->cli_opts = &cli_opts;
    if (sss_creds_password != 0) {
        kr->krb5_get_init_creds_password = sss_krb5_get_init_creds_password;
    } else {
        kr->krb5_get_init_creds_password = krb5_get_init_creds_password;
    }

    ret = k5c_recv_data(kr, STDIN_FILENO, &offline);
    if (ret != EOK) {
        goto done;
    }

    if (cli_opts.check_pac_flags != 0 && !kr->validate) {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "PAC check is requested but krb5_validate is set to false. "
              "PAC checks will be skipped.\n");
    }

    kerr = privileged_krb5_setup(kr, offline);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "privileged_krb5_setup failed.\n");
        ret = EFAULT;
        goto done;
    }

    /* For PKINIT we might need access to the pcscd socket which by default
     * is only allowed for authenticated users. Since PKINIT is part of
     * the authentication and the user is not authenticated yet, we have
     * to use different privileges and can only drop it only after the TGT is
     * received. The fast_uid and fast_gid are the IDs the backend is running
     * with. This can be either root or the 'sssd' user. Root is allowed by
     * default and the 'sssd' user is allowed with the help of the
     * sssd-pcsc.rules policy-kit rule. So those IDs are a suitable choice. We
     * can only call switch_creds() because after the TGT is returned we have
     * to switch to the IDs of the user to store the TGT.
     * If we are offline we have to switch to the user's credentials directly
     * to make sure the empty ccache is created with the expected
     * ownership. */
    if (IS_SC_AUTHTOK(kr->pd->authtok) && !offline) {
        kerr = switch_creds(kr, kr->fast_uid, kr->fast_gid, 0, NULL,
                            &kr->pcsc_saved_creds);
    } else {
        kerr = k5c_become_user(kr->uid, kr->gid, kr->posix_domain);
    }
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "become_user failed.\n");
        ret = EFAULT;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Running as [%"SPRIuid"][%"SPRIgid"].\n", geteuid(), getegid());

    try_open_krb5_conf();

    ret = k5c_setup(kr, offline);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "k5c_setup failed.\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Will perform %s\n", krb5_child_command_to_str(kr->pd->cmd));
    switch(kr->pd->cmd) {
    case SSS_PAM_AUTHENTICATE:
        /* If we are offline, we need to create an empty ccache file */
        if (offline) {
            DEBUG(SSSDBG_TRACE_FUNC, "Will perform offline auth\n");
            ret = create_empty_ccache(kr);
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "Will perform online auth\n");
            ret = tgt_req_child(kr);
        }
        break;
    case SSS_PAM_CHAUTHTOK:
        ret = changepw_child(kr, false);
        break;
    case SSS_PAM_CHAUTHTOK_PRELIM:
        ret = changepw_child(kr, true);
        break;
    case SSS_PAM_ACCT_MGMT:
        ret = kuserok_child(kr);
        break;
    case SSS_CMD_RENEW:
        if (offline) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot renew TGT while offline\n");
            ret = KRB5_KDC_UNREACH;
            goto done;
        }
        ret = renew_tgt_child(kr);
        break;
    case SSS_PAM_PREAUTH:
        ret = tgt_req_child(kr);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "PAM command [%d] not supported.\n", kr->pd->cmd);
        ret = EINVAL;
        goto done;
    }

    ret = k5c_send_data(kr, STDOUT_FILENO, ret);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to send reply\n");
    }

done:
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "krb5_child completed successfully\n");
        ret = 0;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_child failed!\n");
        ret = -1;
    }
    krb5_cleanup(kr);
    talloc_free(kr);
    exit(ret);
}
