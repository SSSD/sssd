/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat
    Copyright (C) 2010, rhafer@suse.de, Novell Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "config.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <syslog.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <locale.h>
#include <stdbool.h>
#include <ctype.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#ifdef HAVE_GDM_PAM_EXTENSIONS
#include <gdm/gdm-pam-extensions.h>
#endif

#include "sss_pam_compat.h"
#include "sss_pam_macros.h"

#include "sss_cli.h"
#include "pam_message.h"
#include "util/atomic_io.h"
#include "util/authtok-utils.h"
#include "util/dlinklist.h"

#include <libintl.h>
#define _(STRING) dgettext (PACKAGE, STRING)
#define _n(SINGULAR, PLURAL, VALUE) dngettext(PACKAGE, SINGULAR, PLURAL, VALUE)

#define PWEXP_FLAG "pam_sss:password_expired_flag"
#define FD_DESTRUCTOR "pam_sss:fd_destructor"
#define PAM_SSS_AUTHOK_TYPE "pam_sss:authtok_type"
#define PAM_SSS_AUTHOK_SIZE "pam_sss:authtok_size"
#define PAM_SSS_AUTHOK_DATA "pam_sss:authtok_data"

#define PW_RESET_MSG_FILENAME_TEMPLATE SSSD_CONF_DIR"/customize/%s/pam_sss_pw_reset_message.%s"
#define PW_RESET_MSG_MAX_SIZE 4096

#define OPT_RETRY_KEY "retry="
#define OPT_DOMAINS_KEY "domains="

#define EXP_ACC_MSG _("Permission denied. ")
#define SRV_MSG     _("Server message: ")
#define PASSKEY_LOCAL_AUTH_MSG      _("Kerberos TGT will not be granted upon login, user experience will be affected.")
#define PASSKEY_DEFAULT_PIN_MSG     _("Enter PIN:")

#define DEBUG_MGS_LEN 1024
#define MAX_AUTHTOK_SIZE (1024*1024)
#define CHECK_AND_RETURN_PI_STRING(s) ((s != NULL && *s != '\0')? s : "(not available)")
#define SERVICE_IS_GDM_SMARTCARD(pitem) (strcmp((pitem)->pam_service, \
                                                "gdm-smartcard") == 0)

static void logger(pam_handle_t *pamh, int level, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);

#ifdef DEBUG
    va_list apd;
    char debug_msg[DEBUG_MGS_LEN];
    int ret;
    va_copy(apd, ap);

    ret = vsnprintf(debug_msg, DEBUG_MGS_LEN, fmt, apd);
    if (ret >= DEBUG_MGS_LEN) {
        D(("the following message is truncated: %s", debug_msg));
    } else if (ret < 0) {
        D(("vsnprintf failed to format debug message!"));
    } else {
        D((debug_msg));
    }

    va_end(apd);
#endif

    pam_vsyslog(pamh, LOG_AUTHPRIV|level, fmt, ap);

    va_end(ap);
}

static void free_exp_data(pam_handle_t *pamh, void *ptr, int err)
{
    free(ptr);
}

static void close_fd(pam_handle_t *pamh, void *ptr, int err)
{
#ifdef PAM_DATA_REPLACE
    if (err & PAM_DATA_REPLACE) {
        /* Nothing to do */
        return;
    }
#endif /* PAM_DATA_REPLACE */

    D(("Closing the fd"));

    sss_pam_lock();
    sss_cli_close_socket();
    sss_pam_unlock();
}

struct cert_auth_info {
    char *cert_user;
    char *cert;
    char *token_name;
    char *module_name;
    char *key_id;
    char *label;
    char *prompt_str;
    char *pam_cert_user;
    char *choice_list_id;
    struct cert_auth_info *prev;
    struct cert_auth_info *next;
};

static void free_cai(struct cert_auth_info *cai)
{
    if (cai != NULL) {
        free(cai->cert_user);
        free(cai->cert);
        free(cai->token_name);
        free(cai->module_name);
        free(cai->key_id);
        free(cai->label);
        free(cai->prompt_str);
        free(cai->choice_list_id);
        free(cai);
    }
}

static void free_cert_list(struct cert_auth_info *list)
{
    struct cert_auth_info *cai;
    struct cert_auth_info *cai_next;

    if (list != NULL) {
        DLIST_FOR_EACH_SAFE(cai, cai_next, list) {
            DLIST_REMOVE(list, cai);
            free_cai(cai);
        }
    }
}

static void overwrite_and_free_authtoks(struct pam_items *pi)
{
    if (pi->pam_authtok != NULL) {
        _pam_overwrite_n((void *)pi->pam_authtok, pi->pam_authtok_size);
        free((void *)pi->pam_authtok);
        pi->pam_authtok = NULL;
    }

    if (pi->pam_newauthtok != NULL) {
        _pam_overwrite_n((void *)pi->pam_newauthtok,  pi->pam_newauthtok_size);
        free((void *)pi->pam_newauthtok);
        pi->pam_newauthtok = NULL;
    }

    if (pi->first_factor != NULL) {
        _pam_overwrite_n((void *)pi->first_factor, strlen(pi->first_factor));
        free((void *)pi->first_factor);
        pi->first_factor = NULL;
    }

    pi->pamstack_authtok = NULL;
    pi->pamstack_oldauthtok = NULL;
}

static void overwrite_and_free_pam_items(struct pam_items *pi)
{
    overwrite_and_free_authtoks(pi);

    free(pi->domain_name);
    pi->domain_name = NULL;

    free(pi->otp_vendor);
    pi->otp_vendor = NULL;

    free(pi->otp_token_id);
    pi->otp_token_id = NULL;

    free(pi->otp_challenge);
    pi->otp_challenge = NULL;

    free(pi->passkey_key);
    pi->passkey_key = NULL;

    free(pi->passkey_prompt_pin);
    pi->passkey_prompt_pin = NULL;

    free_cert_list(pi->cert_list);
    pi->cert_list = NULL;
    pi->selected_cert = NULL;

    pc_list_free(pi->pc);
    pi->pc = NULL;
}

static int null_strcmp(const char *s1, const char *s2) {
    if (s1 == NULL && s2 == NULL) return 0;
    if (s1 == NULL && s2 != NULL) return -1;
    if (s1 != NULL && s2 == NULL) return 1;
    return strcmp(s1, s2);
}

enum {
    SSS_PAM_CONV_DONE = 0,
    SSS_PAM_CONV_STD,
    SSS_PAM_CONV_REENTER,
};

static int do_pam_conversation(pam_handle_t *pamh, const int msg_style,
                               const char *msg,
                               const char *reenter_msg,
                               char **_answer)
{
    int ret;
    int state = SSS_PAM_CONV_STD;
    const struct pam_conv *conv;
    const struct pam_message *mesg[1];
    struct pam_message *pam_msg;
    struct pam_response *resp=NULL;
    char *answer = NULL;

    if ((msg_style == PAM_TEXT_INFO || msg_style == PAM_ERROR_MSG) &&
        msg == NULL) return PAM_SYSTEM_ERR;

    if ((msg_style == PAM_PROMPT_ECHO_OFF ||
         msg_style == PAM_PROMPT_ECHO_ON) &&
        (msg == NULL || _answer == NULL)) return PAM_SYSTEM_ERR;

    if (msg_style == PAM_TEXT_INFO || msg_style == PAM_ERROR_MSG) {
        logger(pamh, LOG_INFO, "User %s message: %s",
                               msg_style == PAM_TEXT_INFO ? "info" : "error",
                               msg);
    }

    ret=pam_get_item(pamh, PAM_CONV, (const void **) &conv);
    if (ret != PAM_SUCCESS) return ret;
    if (conv == NULL || conv->conv == NULL) {
        logger(pamh, LOG_ERR, "No conversation function");
        return PAM_SYSTEM_ERR;
    }

    do {
        pam_msg = malloc(sizeof(struct pam_message));
        if (pam_msg == NULL) {
            D(("Malloc failed."));
            ret = PAM_SYSTEM_ERR;
            goto failed;
        }

        pam_msg->msg_style = msg_style;
        if (state == SSS_PAM_CONV_REENTER) {
            pam_msg->msg = reenter_msg;
        } else {
            pam_msg->msg = msg;
        }

        mesg[0] = (const struct pam_message *) pam_msg;

        ret=conv->conv(1, mesg, &resp,
                       conv->appdata_ptr);
        free(pam_msg);
        if (ret != PAM_SUCCESS) {
            D(("Conversation failure: %s.",  pam_strerror(pamh,ret)));
            goto failed;
        }

        if (msg_style == PAM_PROMPT_ECHO_OFF ||
            msg_style == PAM_PROMPT_ECHO_ON) {
            if (resp == NULL) {
                D(("response expected, but resp==NULL"));
                ret = PAM_SYSTEM_ERR;
                goto failed;
            }

            if (state == SSS_PAM_CONV_REENTER) {
                if (null_strcmp(answer, resp[0].resp) != 0) {
                    logger(pamh, LOG_NOTICE, "Passwords do not match.");
                    _pam_overwrite((void *)resp[0].resp);
                    free(resp[0].resp);
                    if (answer != NULL) {
                        _pam_overwrite((void *) answer);
                        free(answer);
                        answer = NULL;
                    }
                    ret = do_pam_conversation(pamh, PAM_ERROR_MSG,
                                              _("Passwords do not match"),
                                              NULL, NULL);
                    if (ret != PAM_SUCCESS) {
                        D(("do_pam_conversation failed."));
                        ret = PAM_SYSTEM_ERR;
                        goto failed;
                    }
                    ret = PAM_CRED_ERR;
                    goto failed;
                }
                _pam_overwrite((void *)resp[0].resp);
                free(resp[0].resp);
            } else {
                if (resp[0].resp == NULL) {
                    D(("Empty password"));
                    answer = NULL;
                } else {
                    answer = strndup(resp[0].resp, MAX_AUTHTOK_SIZE);
                    _pam_overwrite((void *)resp[0].resp);
                    free(resp[0].resp);
                    if(answer == NULL) {
                        D(("strndup failed"));
                        ret = PAM_BUF_ERR;
                        goto failed;
                    }
                }
            }
            free(resp);
            resp = NULL;
        }

        if (reenter_msg != NULL && state == SSS_PAM_CONV_STD) {
            state = SSS_PAM_CONV_REENTER;
        } else {
            state = SSS_PAM_CONV_DONE;
        }
    } while (state != SSS_PAM_CONV_DONE);

    if (_answer) *_answer = answer;
    return PAM_SUCCESS;

failed:
    free(answer);
    return ret;

}

static errno_t display_pw_reset_message(pam_handle_t *pamh,
                                        const char *domain_name,
                                        const char *suffix)
{
    int ret;
    struct stat stat_buf;
    char *msg_buf = NULL;
    int fd = -1;
    size_t size;
    size_t total_len;
    char *filename = NULL;

    if (strchr(suffix, '/') != NULL || strchr(domain_name, '/') != NULL) {
        D(("Suffix [%s] or domain name [%s] contain illegal character.", suffix,
           domain_name));
        return EINVAL;
    }

    size = sizeof(PW_RESET_MSG_FILENAME_TEMPLATE) + strlen(domain_name) +
           strlen(suffix);
    filename = malloc(size);
    if (filename == NULL) {
        D(("malloc failed."));
        ret = ENOMEM;
        goto done;
    }
    ret = snprintf(filename, size, PW_RESET_MSG_FILENAME_TEMPLATE, domain_name,
                   suffix);
    if (ret < 0 || ret >= size) {
        D(("snprintf failed."));
        ret = EFAULT;
        goto done;
    }

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        ret = errno;
        D(("open failed [%d][%s].\n", ret, strerror(ret)));
        goto done;
    }

    ret = fstat(fd, &stat_buf);
    if (ret == -1) {
        ret = errno;
        D(("fstat failed [%d][%s].", ret, strerror(ret)));
        goto done;
    }

    if (!S_ISREG(stat_buf.st_mode)) {
        logger(pamh, LOG_ERR,
               "Password reset message file is not a regular file.");
        ret = EINVAL;
        goto done;
    }

    if (stat_buf.st_uid != 0 || stat_buf.st_gid != 0 ||
        (stat_buf.st_mode & ~S_IFMT) != 0644) {
        logger(pamh, LOG_ERR,"Permission error, "
               "file [%s] must be owned by root with permissions 0644.",
               filename);
        ret = EPERM;
        goto done;
    }

    if (stat_buf.st_size > PW_RESET_MSG_MAX_SIZE) {
        logger(pamh, LOG_ERR, "Password reset message file is too large.");
        ret = EFBIG;
        goto done;
    }

    msg_buf = malloc(stat_buf.st_size + 1);
    if (msg_buf == NULL) {
        D(("malloc failed."));
        ret = ENOMEM;
        goto done;
    }

    errno = 0;
    total_len = sss_atomic_read_s(fd, msg_buf, stat_buf.st_size);
    if (total_len == -1) {
        ret = errno;
        D(("read failed [%d][%s].", ret, strerror(ret)));
        goto done;
    }

    ret = close(fd);
    fd = -1;
    if (ret == -1) {
        ret = errno;
        D(("close failed [%d][%s].", ret, strerror(ret)));
    }

    if (total_len != stat_buf.st_size) {
        D(("read fewer bytes [%d] than expected [%d].", total_len,
           stat_buf.st_size));
        ret = EIO;
        goto done;
    }

    msg_buf[stat_buf.st_size] = '\0';

    ret = do_pam_conversation(pamh, PAM_TEXT_INFO, msg_buf, NULL, NULL);
    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));
    }

done:
    if (fd != -1) {
        close(fd);
    }
    free(msg_buf);
    free(filename);

    return ret;
}

static errno_t select_pw_reset_message(pam_handle_t *pamh, struct pam_items *pi)
{
    int ret;
    char *locale;
    const char *domain_name;

    domain_name = pi->domain_name;
    if (domain_name == NULL || *domain_name == '\0') {
        D(("Domain name is unknown."));
        return EINVAL;
    }

    locale = setlocale(LC_MESSAGES, NULL);

    ret = -1;
    if (locale != NULL) {
        ret = display_pw_reset_message(pamh, domain_name, locale);
    }

    if (ret != 0) {
        ret = display_pw_reset_message(pamh, domain_name, "txt");
    }

    if (ret != 0) {
        ret = do_pam_conversation(pamh, PAM_TEXT_INFO,
                      _("Password reset by root is not supported."),
                      NULL, NULL);
        if (ret != PAM_SUCCESS) {
            D(("do_pam_conversation failed."));
        }
    }

    return ret;
}

static int user_info_offline_auth(pam_handle_t *pamh, size_t buflen,
                                  uint8_t *buf)
{
    int ret;
    int64_t expire_date;
    struct tm tm;
    char expire_str[128];
    char user_msg[256];

    expire_str[0] = '\0';

    if (buflen != sizeof(uint32_t) + sizeof(int64_t)) {
        D(("User info response data has the wrong size"));
        return PAM_BUF_ERR;
    }

    memcpy(&expire_date, buf + sizeof(uint32_t), sizeof(int64_t));

    if (expire_date > 0) {
        if (localtime_r((time_t *) &expire_date, &tm) != NULL) {
            ret = strftime(expire_str, sizeof(expire_str), "%c", &tm);
            if (ret == 0) {
                D(("strftime failed."));
                expire_str[0] = '\0';
            }
        } else {
            D(("localtime_r failed"));
        }
    }

    ret = snprintf(user_msg, sizeof(user_msg), "%s%s%s.",
               _("Authenticated with cached credentials"),
              expire_str[0] ? _(", your cached password will expire at: ") : "",
              expire_str[0] ? expire_str : "");
    if (ret < 0 || ret >= sizeof(user_msg)) {
        D(("snprintf failed."));
        return PAM_SYSTEM_ERR;
    }

    ret = do_pam_conversation(pamh, PAM_TEXT_INFO, user_msg, NULL, NULL);
    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));
        return PAM_SYSTEM_ERR;
    }

    return PAM_SUCCESS;
}

static int user_info_grace_login(pam_handle_t *pamh,
                                 size_t buflen,
                                 uint8_t *buf)
{
    int ret;
    uint32_t grace;
    char user_msg[256];

    if (buflen != 2* sizeof(uint32_t)) {
        D(("User info response data has the wrong size"));
        return PAM_BUF_ERR;
    }
    memcpy(&grace, buf + sizeof(uint32_t), sizeof(uint32_t));
    ret = snprintf(user_msg, sizeof(user_msg),
                   _("Your password has expired. "
                     "You have %1$d grace login(s) remaining."),
                   grace);
    if (ret < 0 || ret >= sizeof(user_msg)) {
        D(("snprintf failed."));
        return PAM_SYSTEM_ERR;
    }
    ret = do_pam_conversation(pamh, PAM_TEXT_INFO, user_msg, NULL, NULL);

    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));
        return PAM_SYSTEM_ERR;
    }

    return PAM_SUCCESS;
}

#define MINSEC 60
#define HOURSEC (60*MINSEC)
#define DAYSEC (24*HOURSEC)
static int user_info_expire_warn(pam_handle_t *pamh,
                                 size_t buflen,
                                 uint8_t *buf)
{
    int ret;
    uint32_t expire;
    char user_msg[256];
    const char* unit;

    if (buflen != 2* sizeof(uint32_t)) {
        D(("User info response data has the wrong size"));
        return PAM_BUF_ERR;
    }
    memcpy(&expire, buf + sizeof(uint32_t), sizeof(uint32_t));
    /* expire == 0 indicates the password expired */
    if (expire != 0) {
        if (expire >= DAYSEC) {
            expire /= DAYSEC;
            unit = _n("day", "days", expire);
        } else if (expire >= HOURSEC) {
            expire /= HOURSEC;
            unit = _n("hour", "hours", expire);
        } else if (expire >= MINSEC) {
            expire /= MINSEC;
            unit = _n("minute", "minutes", expire);
        } else {
            unit = _n("second", "seconds", expire);
        }

        ret = snprintf(user_msg, sizeof(user_msg),
                       _("Your password will expire in %1$d %2$s."), expire, unit);
    } else {
        ret = snprintf(user_msg, sizeof(user_msg),
                       _("Your password has expired."));
    }

    if (ret < 0 || ret >= sizeof(user_msg)) {
        D(("snprintf failed."));
        return PAM_SYSTEM_ERR;
    }
    ret = do_pam_conversation(pamh, PAM_TEXT_INFO, user_msg, NULL, NULL);

    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));
        return PAM_SYSTEM_ERR;
    }

    return PAM_SUCCESS;
}

static int user_info_offline_auth_delayed(pam_handle_t *pamh, size_t buflen,
                                  uint8_t *buf)
{
    int ret;
    int64_t delayed_until;
    struct tm tm;
    char delay_str[128];
    char user_msg[256];

    delay_str[0] = '\0';

    if (buflen != sizeof(uint32_t) + sizeof(int64_t)) {
        D(("User info response data has the wrong size"));
        return PAM_BUF_ERR;
    }

    memcpy(&delayed_until, buf + sizeof(uint32_t), sizeof(int64_t));

    if (delayed_until <= 0) {
        D(("User info response data has an invalid value"));
        return PAM_BUF_ERR;
    }

    if (localtime_r((time_t *) &delayed_until, &tm) != NULL) {
        ret = strftime(delay_str, sizeof(delay_str), "%c", &tm);
        if (ret == 0) {
            D(("strftime failed."));
            delay_str[0] = '\0';
        }
    } else {
        D(("localtime_r failed"));
    }

    ret = snprintf(user_msg, sizeof(user_msg), "%s%s.",
                   _("Authentication is denied until: "),
                   delay_str);
    if (ret < 0 || ret >= sizeof(user_msg)) {
        D(("snprintf failed."));
        return PAM_SYSTEM_ERR;
    }

    ret = do_pam_conversation(pamh, PAM_TEXT_INFO, user_msg, NULL, NULL);
    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));
        return PAM_SYSTEM_ERR;
    }

    return PAM_SUCCESS;
}

static int user_info_offline_chpass(pam_handle_t *pamh)
{
    int ret;

    ret = do_pam_conversation(pamh, PAM_TEXT_INFO,
                              _("System is offline, password change not possible"),
                              NULL, NULL);
    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));
        return PAM_SYSTEM_ERR;
    }

    return PAM_SUCCESS;
}

static int user_info_otp_chpass(pam_handle_t *pamh)
{
    int ret;

    ret = do_pam_conversation(pamh, PAM_TEXT_INFO,
                              _("After changing the OTP password, you need to "
                                "log out and back in order to acquire a ticket"),
                              NULL, NULL);
    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));
        return PAM_SYSTEM_ERR;
    }

    return PAM_SUCCESS;
}

static int user_info_pin_locked(pam_handle_t *pamh)
{
    int ret;

    ret = do_pam_conversation(pamh, PAM_TEXT_INFO, _("PIN locked"),
                              NULL, NULL);
    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));
        return PAM_SYSTEM_ERR;
    }

    return PAM_SUCCESS;
}

static int user_info_no_krb_tgt(pam_handle_t *pamh)
{
    int ret;

    ret = do_pam_conversation(pamh, PAM_TEXT_INFO,
                              _("No Kerberos TGT granted as "
                                "the server does not support this method. "
                                "Your single-sign on(SSO) experience will "
                                "be affected."),
                              NULL, NULL);
    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));
        return PAM_SYSTEM_ERR;
    }

    return PAM_SUCCESS;
}

static int user_info_account_expired(pam_handle_t *pamh, size_t buflen,
                                     uint8_t *buf)
{
    int ret;
    uint32_t msg_len;
    char *user_msg;
    size_t bufsize = 0;

    /* resp_type and length of message are expected to be in buf */
    if (buflen < 2* sizeof(uint32_t)) {
        D(("User info response data is too short"));
        return PAM_BUF_ERR;
    }

    /* msg_len = legth of message */
    memcpy(&msg_len, buf + sizeof(uint32_t), sizeof(uint32_t));

    if (buflen != 2* sizeof(uint32_t) + msg_len) {
        D(("User info response data has the wrong size"));
        return PAM_BUF_ERR;
    }

    bufsize = strlen(EXP_ACC_MSG) + 1;

    if (msg_len > 0) {
        bufsize += strlen(SRV_MSG) + msg_len;
    }

    user_msg = (char *)malloc(sizeof(char) * bufsize);
    if (!user_msg) {
       D(("Out of memory."));
       return PAM_SYSTEM_ERR;
    }

    ret = snprintf(user_msg, bufsize, "%s%s%.*s",
                   EXP_ACC_MSG,
                   msg_len > 0 ? SRV_MSG : "",
                   (int)msg_len,
                   msg_len > 0 ? (char *)(buf + 2 * sizeof(uint32_t)) : "" );
    if (ret < 0 || ret > bufsize) {
        D(("snprintf failed."));

        free(user_msg);
        return PAM_SYSTEM_ERR;
    }

    ret = do_pam_conversation(pamh, PAM_TEXT_INFO, user_msg, NULL, NULL);
    free(user_msg);
    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));

        return PAM_SYSTEM_ERR;
    }

    return PAM_SUCCESS;
}

static int user_info_chpass_error(pam_handle_t *pamh, size_t buflen,
                                  uint8_t *buf)
{
    int ret;
    uint32_t msg_len;
    char *user_msg;
    size_t bufsize = 0;

    if (buflen < 2* sizeof(uint32_t)) {
        D(("User info response data is too short"));
        return PAM_BUF_ERR;
    }

    memcpy(&msg_len, buf + sizeof(uint32_t), sizeof(uint32_t));

    if (buflen != 2* sizeof(uint32_t) + msg_len) {
        D(("User info response data has the wrong size"));
        return PAM_BUF_ERR;
    }

    bufsize = strlen(_("Password change failed. ")) + 1;

    if (msg_len > 0) {
        bufsize += strlen(_("Server message: ")) + msg_len;
    }

    user_msg = (char *)malloc(sizeof(char) * bufsize);
    if (!user_msg) {
       D(("Out of memory."));
       return PAM_SYSTEM_ERR;
    }

    ret = snprintf(user_msg, bufsize, "%s%s%.*s",
                   _("Password change failed. "),
                   msg_len > 0 ? _("Server message: ") : "",
                   (int)msg_len,
                   msg_len > 0 ? (char *)(buf + 2 * sizeof(uint32_t)) : "" );
    if (ret < 0 || ret > bufsize) {
        D(("snprintf failed."));

        free(user_msg);
        return PAM_SYSTEM_ERR;
    }

    ret = do_pam_conversation(pamh, PAM_TEXT_INFO, user_msg, NULL, NULL);
    free(user_msg);
    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));

        return PAM_SYSTEM_ERR;
    }

    return PAM_SUCCESS;
}

static int eval_user_info_response(pam_handle_t *pamh, size_t buflen,
                                   uint8_t *buf)
{
    int ret;
    uint32_t type;

    if (buflen < sizeof(uint32_t)) {
        D(("User info response data is too short"));
        return PAM_BUF_ERR;
    }

    memcpy(&type, buf, sizeof(uint32_t));

    switch(type) {
        case SSS_PAM_USER_INFO_OFFLINE_AUTH:
            ret = user_info_offline_auth(pamh, buflen, buf);
            break;
        case SSS_PAM_USER_INFO_GRACE_LOGIN:
            ret = user_info_grace_login(pamh, buflen, buf);
            break;
        case SSS_PAM_USER_INFO_EXPIRE_WARN:
            ret = user_info_expire_warn(pamh, buflen, buf);
            break;
        case SSS_PAM_USER_INFO_OFFLINE_AUTH_DELAYED:
            ret = user_info_offline_auth_delayed(pamh, buflen, buf);
            break;
        case SSS_PAM_USER_INFO_OFFLINE_CHPASS:
            ret = user_info_offline_chpass(pamh);
            break;
        case SSS_PAM_USER_INFO_OTP_CHPASS:
            ret = user_info_otp_chpass(pamh);
            break;
        case SSS_PAM_USER_INFO_CHPASS_ERROR:
            ret = user_info_chpass_error(pamh, buflen, buf);
            break;
        case SSS_PAM_USER_INFO_PIN_LOCKED:
            ret = user_info_pin_locked(pamh);
            break;
        case SSS_PAM_USER_INFO_ACCOUNT_EXPIRED:
            ret = user_info_account_expired(pamh, buflen, buf);
            break;
        case SSS_PAM_USER_INFO_NO_KRB_TGT:
            ret = user_info_no_krb_tgt(pamh);
            break;
        default:
            D(("Unknown user info type [%d]", type));
            ret = PAM_SYSTEM_ERR;
    }

    return ret;
}

static int parse_cert_info(struct pam_items *pi, uint8_t *buf, size_t len,
                           size_t *p, const char **cert_user,
                           const char **pam_cert_user)
{
    struct cert_auth_info *cai = NULL;
    size_t offset;
    int ret;

    if (buf[*p + (len - 1)] != '\0') {
        D(("cert info does not end with \\0."));
        return EINVAL;
    }

    cai = calloc(1, sizeof(struct cert_auth_info));
    if (cai == NULL) {
        return ENOMEM;
    }

    cai->cert_user = strdup((char *) &buf[*p]);
    if (cai->cert_user == NULL) {
        D(("strdup failed"));
        ret = ENOMEM;
        goto done;
    }
    if (cert_user != NULL) {
        *cert_user = cai->cert_user;
    }

    offset = strlen(cai->cert_user) + 1;
    if (offset >= len) {
        D(("Cert message size mismatch"));
        ret = EINVAL;
        goto done;
    }

    cai->token_name = strdup((char *) &buf[*p + offset]);
    if (cai->token_name == NULL) {
        D(("strdup failed"));
        ret = ENOMEM;
        goto done;
    }

    offset += strlen(cai->token_name) + 1;
    if (offset >= len) {
        D(("Cert message size mismatch"));
        ret = EINVAL;
        goto done;
    }

    cai->module_name = strdup((char *) &buf[*p + offset]);
    if (cai->module_name == NULL) {
        D(("strdup failed"));
        ret = ENOMEM;
        goto done;
    }

    offset += strlen(cai->module_name) + 1;
    if (offset >= len) {
        D(("Cert message size mismatch"));
        ret = EINVAL;
        goto done;
    }

    cai->key_id = strdup((char *) &buf[*p + offset]);
    if (cai->key_id == NULL) {
        D(("strdup failed"));
        ret = ENOMEM;
        goto done;
    }

    offset += strlen(cai->key_id) + 1;
    if (offset >= len) {
        D(("Cert message size mismatch"));
        ret = EINVAL;
        goto done;
    }

    cai->label = strdup((char *) &buf[*p + offset]);
    if (cai->label == NULL) {
        D(("strdup failed"));
        ret = ENOMEM;
        goto done;
    }

    offset += strlen(cai->label) + 1;
    if (offset >= len) {
        D(("Cert message size mismatch"));
        ret = EINVAL;
        goto done;
    }

    cai->prompt_str = strdup((char *) &buf[*p + offset]);
    if (cai->prompt_str == NULL) {
        D(("strdup failed"));
        ret = ENOMEM;
        goto done;
    }

    offset += strlen(cai->prompt_str) + 1;
    if (offset >= len) {
        D(("Cert message size mismatch"));
        ret = EINVAL;
        goto done;
    }

    cai->pam_cert_user = strdup((char *) &buf[*p + offset]);
    if (cai->pam_cert_user == NULL) {
        D(("strdup failed"));
        ret = ENOMEM;
        goto done;
    }
    if (pam_cert_user != NULL) {
        *pam_cert_user = cai->pam_cert_user;
    }

    D(("cert user: [%s] token name: [%s] module: [%s] key id: [%s] "
       "prompt: [%s] pam cert user: [%s]",
       cai->cert_user, cai->token_name, cai->module_name,
       cai->key_id, cai->prompt_str, cai->pam_cert_user));

    DLIST_ADD(pi->cert_list, cai);
    ret = 0;

done:
    if (ret != 0) {
        free_cai(cai);
    }

    return ret;
}

static int eval_response(pam_handle_t *pamh, size_t buflen, uint8_t *buf,
                         struct pam_items *pi)
{
    int ret;
    size_t p=0;
    char *env_item;
    int32_t c;
    int32_t type;
    int32_t len;
    int32_t pam_status;
    size_t offset;
    const char *cert_user;
    const char *pam_cert_user;

    if (buflen < (2*sizeof(int32_t))) {
        D(("response buffer is too small"));
        return PAM_BUF_ERR;
    }

    memcpy(&pam_status, buf+p, sizeof(int32_t));
    p += sizeof(int32_t);


    memcpy(&c, buf+p, sizeof(int32_t));
    p += sizeof(int32_t);

    while(c>0) {
        if (buflen < (p+2*sizeof(int32_t))) {
            D(("response buffer is too small"));
            return PAM_BUF_ERR;
        }

        memcpy(&type, buf+p, sizeof(int32_t));
        p += sizeof(int32_t);

        memcpy(&len, buf+p, sizeof(int32_t));
        p += sizeof(int32_t);

        if (buflen < (p + len)) {
            D(("response buffer is too small"));
            return PAM_BUF_ERR;
        }

        switch(type) {
            case SSS_PAM_SYSTEM_INFO:
                if (buf[p + (len -1)] != '\0') {
                    D(("system info does not end with \\0."));
                    break;
                }
                logger(pamh, LOG_INFO, "system info: [%s]", &buf[p]);
                break;
            case SSS_PAM_DOMAIN_NAME:
                if (buf[p + (len -1)] != '\0') {
                    D(("domain name does not end with \\0."));
                    break;
                }
                D(("domain name: [%s]", &buf[p]));
                free(pi->domain_name);
                pi->domain_name = strdup((char *) &buf[p]);
                if (pi->domain_name == NULL) {
                    D(("strdup failed"));
                }
                break;
            case SSS_ENV_ITEM:
            case SSS_PAM_ENV_ITEM:
            case SSS_ALL_ENV_ITEM:
                if (buf[p + (len -1)] != '\0') {
                    D(("env item does not end with \\0."));
                    break;
                }

                D(("env item: [%s]", &buf[p]));
                if (type == SSS_PAM_ENV_ITEM || type == SSS_ALL_ENV_ITEM) {
                    ret = pam_putenv(pamh, (char *)&buf[p]);
                    if (ret != PAM_SUCCESS) {
                        D(("pam_putenv failed."));
                        break;
                    }
                }

                if (type == SSS_ENV_ITEM || type == SSS_ALL_ENV_ITEM) {
                    env_item = strdup((char *)&buf[p]);
                    if (env_item == NULL) {
                        D(("strdup failed"));
                        break;
                    }
                    ret = putenv(env_item);
                    if (ret == -1) {
                        D(("putenv failed."));
                        break;
                    }
                }
                break;
            case SSS_PAM_USER_INFO:
                ret = eval_user_info_response(pamh, len, &buf[p]);
                if (ret != PAM_SUCCESS) {
                    D(("eval_user_info_response failed"));
                }
                break;
            case SSS_PAM_TEXT_MSG:
                if (buf[p + (len -1)] != '\0') {
                    D(("system info does not end with \\0."));
                    break;
                }

                ret = do_pam_conversation(pamh, PAM_TEXT_INFO, (char *) &buf[p],
                                          NULL, NULL);
                if (ret != PAM_SUCCESS) {
                    D(("do_pam_conversation failed."));
                }
                break;
            case SSS_OTP:
                D(("OTP was used, removing authtokens."));
                overwrite_and_free_authtoks(pi);
                ret = pam_set_item(pamh, PAM_AUTHTOK, NULL);
                if (ret != PAM_SUCCESS) {
                    D(("Failed to remove PAM_AUTHTOK after using otp [%s]",
                       pam_strerror(pamh,ret)));
                }
                break;
            case SSS_PAM_OTP_INFO:
                if (buf[p + (len - 1)] != '\0') {
                    D(("otp info does not end with \\0."));
                    break;
                }

                free(pi->otp_vendor);
                pi->otp_vendor = strdup((char *) &buf[p]);
                if (pi->otp_vendor == NULL) {
                    D(("strdup failed"));
                    break;
                }

                offset = strlen(pi->otp_vendor) + 1;
                if (offset >= len) {
                    D(("OTP message size mismatch"));
                    free(pi->otp_vendor);
                    pi->otp_vendor = NULL;
                    break;
                }
                free(pi->otp_token_id);
                pi->otp_token_id = strdup((char *) &buf[p + offset]);
                if (pi->otp_token_id == NULL) {
                    D(("strdup failed"));
                    break;
                }

                offset += strlen(pi->otp_token_id) + 1;
                if (offset >= len) {
                    D(("OTP message size mismatch"));
                    free(pi->otp_token_id);
                    pi->otp_token_id = NULL;
                    break;
                }
                free(pi->otp_challenge);
                pi->otp_challenge = strdup((char *) &buf[p + offset]);
                if (pi->otp_challenge == NULL) {
                    D(("strdup failed"));
                    break;
                }

                break;
            case SSS_PAM_CERT_INFO:
            case SSS_PAM_CERT_INFO_WITH_HINT:
                if (buf[p + (len - 1)] != '\0') {
                    D(("cert info does not end with \\0."));
                    break;
                }

                if (type == SSS_PAM_CERT_INFO_WITH_HINT) {
                    pi->user_name_hint = true;
                } else {
                    pi->user_name_hint = false;
                }

                ret = parse_cert_info(pi, buf, len, &p, &cert_user,
                                      &pam_cert_user);
                if (ret != 0) {
                    D(("Failed to parse cert info"));
                    break;
                }

                if ((pi->pam_user == NULL || *(pi->pam_user) == '\0')
                        && *cert_user != '\0' && *pam_cert_user != '\0') {
                    ret = pam_set_item(pamh, PAM_USER, pam_cert_user);
                    if (ret != PAM_SUCCESS) {
                        D(("Failed to set PAM_USER during "
                           "Smartcard authentication [%s]",
                           pam_strerror(pamh, ret)));
                        break;
                    }

                    pi->pam_user = cert_user;
                    pi->pam_user_size = strlen(pi->pam_user) + 1;
                }
                break;
            case SSS_PASSWORD_PROMPTING:
                D(("Password prompting available."));
                pi->password_prompting = true;
                break;
            case SSS_PAM_PROMPT_CONFIG:
                if (pi->pc == NULL) {
                    ret = pc_list_from_response(len, &buf[p], &pi->pc);
                    if (ret != EOK) {
                        D(("Failed to parse prompting data, using defaults"));
                        pc_list_free(pi->pc);
                        pi->pc = NULL;
                    }
                }
                break;
            case SSS_CHILD_KEEP_ALIVE:
                memcpy(&pi->child_pid, &buf[p], len);
                break;
            case SSS_PAM_OAUTH2_INFO:
                if (buf[p + (len - 1)] != '\0') {
                    D(("oauth2 info does not end with \\0."));
                    break;
                }

                free(pi->oauth2_url);
                pi->oauth2_url = strdup((char *) &buf[p]);
                if (pi->oauth2_url == NULL) {
                    D(("strdup failed"));
                    break;
                }

                offset = strlen(pi->oauth2_url) + 1;
                if (offset >= len) {
                    D(("OAuth2 message size mismatch"));
                    free(pi->oauth2_url);
                    pi->oauth2_url = NULL;
                    break;
                }

                free(pi->oauth2_url_complete);
                pi->oauth2_url_complete = strdup((char *) &buf[p + offset]);
                if (pi->oauth2_url_complete == NULL) {
                    D(("strdup failed"));
                    break;
                }

                offset = offset + strlen(pi->oauth2_url_complete) + 1;
                if (offset >= len) {
                    D(("OAuth2 message size mismatch"));
                    free(pi->oauth2_url_complete);
                    pi->oauth2_url_complete = NULL;
                    break;
                }

                /* This field is optional. */
                if (pi->oauth2_url_complete[0] == '\0') {
                    free(pi->oauth2_url_complete);
                    pi->oauth2_url_complete = NULL;
                }

                free(pi->oauth2_pin);
                pi->oauth2_pin = strdup((char *) &buf[p + offset]);
                if (pi->oauth2_pin == NULL) {
                    D(("strdup failed"));
                    break;
                }

                break;
            case SSS_PAM_PASSKEY_KRB_INFO:
                free(pi->passkey_prompt_pin);
                pi->passkey_prompt_pin = strdup((char *) &buf[p]);
                if (pi->passkey_prompt_pin == NULL) {
                    D(("strdup failed"));
                    break;
                }

                offset = strlen(pi->passkey_prompt_pin) + 1;
                if (offset >= len) {
                    D(("Passkey message size mismatch"));
                    free(pi->passkey_prompt_pin);
                    pi->passkey_prompt_pin = NULL;
                    break;
                }

                free(pi->passkey_key);
                pi->passkey_key = strdup((char *) &buf[p + offset]);
                if (pi->passkey_key == NULL) {
                    D(("strdup failed"));
                    break;
                }
                break;
            case SSS_PAM_PASSKEY_INFO:
                if (buf[p + (len - 1)] != '\0') {
                    D(("passkey info does not end with \\0."));
                    break;
                }

                free(pi->passkey_prompt_pin);
                pi->passkey_prompt_pin = strdup((char *) &buf[p]);
                if (pi->passkey_prompt_pin == NULL) {
                    D(("strdup failed"));
                    break;
                }
                break;
            default:
                D(("Unknown response type [%d]", type));
        }
        p += len;

        --c;
    }

    return PAM_SUCCESS;
}

bool is_string_empty_or_whitespace(const char *str)
{
    int i;

    if (str == NULL) {
        return true;
    }

    for (i = 0; str[i] != '\0'; i++) {
        if (!isspace(str[i])) {
            return false;
        }
    }

    return true;
}

static int get_pam_items(pam_handle_t *pamh, uint32_t flags,
                         struct pam_items *pi)
{
    int ret;

    pi->pam_authtok_type = SSS_AUTHTOK_TYPE_EMPTY;
    pi->pam_authtok = NULL;
    pi->pam_authtok_size = 0;
    pi->pam_newauthtok_type = SSS_AUTHTOK_TYPE_EMPTY;
    pi->pam_newauthtok = NULL;
    pi->pam_newauthtok_size = 0;
    pi->first_factor = NULL;

    ret = pam_get_item(pamh, PAM_SERVICE, (const void **) &(pi->pam_service));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pam_service == NULL) pi->pam_service="";
    pi->pam_service_size=strlen(pi->pam_service)+1;

    ret = pam_get_item(pamh, PAM_USER, (const void **) &(pi->pam_user));
    if (ret == PAM_PERM_DENIED && (flags & PAM_CLI_FLAGS_ALLOW_MISSING_NAME)) {
        pi->pam_user = "";
        ret = PAM_SUCCESS;
    }
    if (ret != PAM_SUCCESS) return ret;
    if (flags & PAM_CLI_FLAGS_ALLOW_MISSING_NAME) {
        if (is_string_empty_or_whitespace(pi->pam_user)) {
            pi->pam_user = "";
        }
    }
    if (pi->pam_user == NULL) {
        D(("No user found, aborting."));
        return PAM_BAD_ITEM;
    }
    if (strcmp(pi->pam_user, "root") == 0) {
        D(("pam_sss will not handle root."));
        return PAM_USER_UNKNOWN;
    }
    pi->pam_user_size=strlen(pi->pam_user)+1;


    ret = pam_get_item(pamh, PAM_TTY, (const void **) &(pi->pam_tty));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pam_tty == NULL) pi->pam_tty="";
    pi->pam_tty_size=strlen(pi->pam_tty)+1;

    ret = pam_get_item(pamh, PAM_RUSER, (const void **) &(pi->pam_ruser));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pam_ruser == NULL) pi->pam_ruser="";
    pi->pam_ruser_size=strlen(pi->pam_ruser)+1;

    ret = pam_get_item(pamh, PAM_RHOST, (const void **) &(pi->pam_rhost));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pam_rhost == NULL) pi->pam_rhost="";
    pi->pam_rhost_size=strlen(pi->pam_rhost)+1;

    ret = pam_get_item(pamh, PAM_AUTHTOK,
                       (const void **) &(pi->pamstack_authtok));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pamstack_authtok == NULL) pi->pamstack_authtok="";

    ret = pam_get_item(pamh, PAM_OLDAUTHTOK,
                       (const void **) &(pi->pamstack_oldauthtok));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pamstack_oldauthtok == NULL) pi->pamstack_oldauthtok="";

    pi->cli_pid = getpid();

    pi->login_name = pam_modutil_getlogin(pamh);
    if (pi->login_name == NULL) pi->login_name="";

    pi->domain_name = NULL;

    if (pi->requested_domains == NULL) pi->requested_domains = "";
    pi->requested_domains_size = strlen(pi->requested_domains) + 1;

    pi->otp_vendor = NULL;
    pi->otp_token_id = NULL;
    pi->otp_challenge = NULL;
    pi->password_prompting = false;

    pi->cert_list = NULL;
    pi->selected_cert = NULL;

    pi->pc = NULL;

    pi->flags = flags;

    return PAM_SUCCESS;
}

static void print_pam_items(struct pam_items *pi)
{
    if (pi == NULL) return;

    D(("Service: %s", CHECK_AND_RETURN_PI_STRING(pi->pam_service)));
    D(("User: %s", CHECK_AND_RETURN_PI_STRING(pi->pam_user)));
    D(("Tty: %s", CHECK_AND_RETURN_PI_STRING(pi->pam_tty)));
    D(("Ruser: %s", CHECK_AND_RETURN_PI_STRING(pi->pam_ruser)));
    D(("Rhost: %s", CHECK_AND_RETURN_PI_STRING(pi->pam_rhost)));
    D(("Pamstack_Authtok: %s",
            CHECK_AND_RETURN_PI_STRING(pi->pamstack_authtok)));
    D(("Pamstack_Oldauthtok: %s",
            CHECK_AND_RETURN_PI_STRING(pi->pamstack_oldauthtok)));
    D(("Authtok: %s", CHECK_AND_RETURN_PI_STRING(pi->pam_authtok)));
    D(("Newauthtok: %s", CHECK_AND_RETURN_PI_STRING(pi->pam_newauthtok)));
    D(("Cli_PID: %d", pi->cli_pid));
    D(("Child_PID: %d", pi->child_pid));
    D(("Requested domains: %s", pi->requested_domains));
    D(("Flags: %d", pi->flags));
}

static int send_and_receive(pam_handle_t *pamh, struct pam_items *pi,
                            enum sss_cli_command task, bool quiet_mode)
{
    int ret;
    int sret;
    int errnop;
    struct sss_cli_req_data rd;
    uint8_t *buf = NULL;
    uint8_t *repbuf = NULL;
    size_t replen;
    int pam_status = PAM_SYSTEM_ERR;

    print_pam_items(pi);

    ret = pack_message_v3(pi, &rd.len, &buf);
    if (ret != 0) {
        D(("pack_message failed."));
        pam_status = PAM_SYSTEM_ERR;
        goto done;
    }
    rd.data = buf;

    errnop = 0;
    ret = sss_pam_make_request(task, &rd, &repbuf, &replen, &errnop);

    sret = pam_set_data(pamh, FD_DESTRUCTOR, NULL, close_fd);
    if (sret != PAM_SUCCESS) {
        D(("pam_set_data failed, client might leaks fds"));
    }

    if (ret != PAM_SUCCESS) {
        /* If there is no PAM responder socket during the access control step
         * we assume this is on purpose, i.e. PAM responder is not configured.
         * PAM_USER_UNKNOWN is returned to the PAM stack to avoid unexpected
         * denials. */
        if (errnop == ESSS_NO_SOCKET && task == SSS_PAM_ACCT_MGMT) {
            pam_status = PAM_USER_UNKNOWN;
        } else {
            if (errnop != 0 && errnop != ESSS_NO_SOCKET) {
                logger(pamh, LOG_ERR, "Request to sssd failed. %s",
                                      ssscli_err2string(errnop));
            }

            pam_status = PAM_AUTHINFO_UNAVAIL;
        }
        goto done;
    }

/* FIXME: add an end signature */
    if (replen < (2*sizeof(int32_t))) {
        D(("response not in expected format."));
        pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    SAFEALIGN_COPY_UINT32(&pam_status, repbuf, NULL);
    ret = eval_response(pamh, replen, repbuf, pi);
    if (ret != PAM_SUCCESS) {
        D(("eval_response failed."));
        pam_status = ret;
        goto done;
    }

    switch (task) {
        case SSS_PAM_AUTHENTICATE:
            logger(pamh, (pam_status == PAM_SUCCESS ? LOG_INFO : LOG_NOTICE),
                   "authentication %s; logname=%s uid=%lu euid=%d tty=%s "
                   "ruser=%s rhost=%s user=%s",
                   pam_status == PAM_SUCCESS ? "success" : "failure",
                   pi->login_name, getuid(), (unsigned long) geteuid(),
                   pi->pam_tty, pi->pam_ruser, pi->pam_rhost, pi->pam_user);
            if (pam_status != PAM_SUCCESS) {
                /* don't log if quiet_mode is on and pam_status is
                 * User not known to the underlying authentication module
                 */
                if (!quiet_mode || pam_status != 10) {
                   logger(pamh, LOG_NOTICE, "received for user %s: %d (%s)",
                          pi->pam_user, pam_status,
                          pam_strerror(pamh,pam_status));
                }
            }
            break;
        case SSS_PAM_CHAUTHTOK_PRELIM:
            if (pam_status != PAM_SUCCESS) {
                /* don't log if quiet_mode is on and pam_status is
                 * User not known to the underlying authentication module
                 */
                if (!quiet_mode || pam_status != 10) {
                   logger(pamh, LOG_NOTICE,
                          "Authentication failed for user %s: %d (%s)",
                          pi->pam_user, pam_status,
                          pam_strerror(pamh,pam_status));
                }
            }
            break;
        case SSS_PAM_CHAUTHTOK:
            if (pam_status != PAM_SUCCESS) {
                   logger(pamh, LOG_NOTICE,
                          "Password change failed for user %s: %d (%s)",
                          pi->pam_user, pam_status,
                          pam_strerror(pamh,pam_status));
            }
            break;
        case SSS_PAM_ACCT_MGMT:
            if (pam_status != PAM_SUCCESS) {
                /* don't log if quiet_mode is on and pam_status is
                 * User not known to the underlying authentication module
                 */
                if (!quiet_mode || pam_status != 10) {
                   logger(pamh, LOG_NOTICE,
                          "Access denied for user %s: %d (%s)",
                          pi->pam_user, pam_status,
                          pam_strerror(pamh,pam_status));
                }
            }
            break;
        case SSS_PAM_OPEN_SESSION:
        case SSS_PAM_SETCRED:
        case SSS_PAM_CLOSE_SESSION:
        case SSS_PAM_PREAUTH:
            break;
        default:
            D(("Illegal task [%#x]", task));
            return PAM_SYSTEM_ERR;
    }

done:
    if (buf != NULL ) {
        _pam_overwrite_n((void *)buf, rd.len);
        free(buf);
    }
    free(repbuf);

    return pam_status;
}

static int prompt_password(pam_handle_t *pamh, struct pam_items *pi,
                           const char *prompt)
{
    int ret;
    char *answer = NULL;

    ret = do_pam_conversation(pamh, PAM_PROMPT_ECHO_OFF, prompt, NULL, &answer);
    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));
        return ret;
    }

    if (answer == NULL) {
        pi->pam_authtok = NULL;
        pi->pam_authtok_type = SSS_AUTHTOK_TYPE_EMPTY;
        pi->pam_authtok_size=0;
    } else {
        pi->pam_authtok = strdup(answer);
        _pam_overwrite((void *)answer);
        free(answer);
        answer=NULL;
        if (pi->pam_authtok == NULL) {
            return PAM_BUF_ERR;
        }
        pi->pam_authtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
        pi->pam_authtok_size=strlen(pi->pam_authtok);
    }

    return PAM_SUCCESS;
}

static int prompt_2fa(pam_handle_t *pamh, struct pam_items *pi,
                      const char *prompt_fa1, const char *prompt_fa2)
{
    int ret;
    const struct pam_conv *conv;
    const struct pam_message *mesg[2] = { NULL, NULL };
    struct pam_message m[2] = { {0}, {0} };
    struct pam_response *resp = NULL;
    size_t needed_size;

    ret = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
    if (ret != PAM_SUCCESS) {
        return ret;
    }
    if (conv == NULL || conv->conv == NULL) {
        logger(pamh, LOG_ERR, "No conversation function");
        return PAM_SYSTEM_ERR;
    }

    m[0].msg_style = PAM_PROMPT_ECHO_OFF;
    m[0].msg = prompt_fa1;
    m[1].msg_style = PAM_PROMPT_ECHO_OFF;
    m[1].msg = prompt_fa2;

    mesg[0] = (const struct pam_message *) m;
    /* The following assignment might look a bit odd but is recommended in the
     * pam_conv man page to make sure that the second argument of the PAM
     * conversation function can be interpreted in two different ways.
     * Basically it is important that both the actual struct pam_message and
     * the pointers to the struct pam_message are arrays. Since the assignment
     * makes clear that mesg[] and (*mesg)[] are arrays it should be kept this
     * way and not be replaced by other equivalent assignments. */
    mesg[1] = & (( *mesg )[1]);

    ret = conv->conv(2, mesg, &resp, conv->appdata_ptr);
    if (ret != PAM_SUCCESS) {
        D(("Conversation failure: %s.", pam_strerror(pamh, ret)));
        return ret;
    }

    if (resp == NULL) {
        D(("response expected, but resp==NULL"));
        return PAM_SYSTEM_ERR;
    }

    if (resp[0].resp == NULL || *(resp[0].resp) == '\0') {
        D(("Missing factor."));
        ret = PAM_CRED_INSUFFICIENT;
        goto done;
    }

    if (resp[1].resp == NULL || *(resp[1].resp) == '\0'
            || (pi->pam_service != NULL && strcmp(pi->pam_service, "sshd") == 0
                    && strcmp(resp[0].resp, resp[1].resp) == 0)) {
        /* Missing second factor, assume first factor contains combined 2FA
         * credentials.
         * Special handling for SSH with password authentication. Combined
         * 2FA credentials are used but SSH puts them in both responses. */

        pi->pam_authtok = strndup(resp[0].resp, MAX_AUTHTOK_SIZE);
        if (pi->pam_authtok == NULL) {
            D(("strndup failed."));
            ret = PAM_BUF_ERR;
            goto done;
        }
        pi->pam_authtok_size = strlen(pi->pam_authtok) + 1;
        pi->pam_authtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
    } else {

        ret = sss_auth_pack_2fa_blob(resp[0].resp, 0, resp[1].resp, 0, NULL, 0,
                                     &needed_size);
        if (ret != EAGAIN) {
            D(("sss_auth_pack_2fa_blob failed."));
            ret = PAM_BUF_ERR;
            goto done;
        }

        pi->pam_authtok = malloc(needed_size);
        if (pi->pam_authtok == NULL) {
            D(("malloc failed."));
            ret = PAM_BUF_ERR;
            goto done;
        }

        ret = sss_auth_pack_2fa_blob(resp[0].resp, 0, resp[1].resp, 0,
                                     (uint8_t *) pi->pam_authtok, needed_size,
                                     &needed_size);
        if (ret != EOK) {
            D(("sss_auth_pack_2fa_blob failed."));
            ret = PAM_BUF_ERR;
            goto done;
        }

        pi->pam_authtok_size = needed_size;
        pi->pam_authtok_type = SSS_AUTHTOK_TYPE_2FA;
        pi->first_factor = strndup(resp[0].resp, MAX_AUTHTOK_SIZE);
        if (pi->first_factor == NULL) {
            D(("strndup failed."));
            ret = PAM_BUF_ERR;
            goto done;
        }
    }

    ret = PAM_SUCCESS;

done:
    if (resp != NULL) {
        if (resp[0].resp != NULL) {
            _pam_overwrite((void *)resp[0].resp);
            free(resp[0].resp);
        }
        if (resp[1].resp != NULL) {
            _pam_overwrite((void *)resp[1].resp);
            free(resp[1].resp);
        }

        free(resp);
        resp = NULL;
    }

    return ret;
}

static int prompt_2fa_single(pam_handle_t *pamh, struct pam_items *pi,
                             const char *prompt)
{
    int ret;
    char *answer = NULL;

    ret = do_pam_conversation(pamh, PAM_PROMPT_ECHO_OFF, prompt, NULL, &answer);
    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));
        return ret;
    }

    if (answer == NULL) {
        pi->pam_authtok = NULL;
        pi->pam_authtok_type = SSS_AUTHTOK_TYPE_EMPTY;
        pi->pam_authtok_size=0;
    } else {
        pi->pam_authtok = strdup(answer);
        _pam_overwrite((void *)answer);
        free(answer);
        answer=NULL;
        if (pi->pam_authtok == NULL) {
            return PAM_BUF_ERR;
        }
        pi->pam_authtok_type = SSS_AUTHTOK_TYPE_2FA_SINGLE;
        pi->pam_authtok_size=strlen(pi->pam_authtok);
    }

    return PAM_SUCCESS;
}

static int prompt_oauth2(pam_handle_t *pamh, struct pam_items *pi)
{
    char *answer = NULL;
    char *msg;
    int ret;

    if (pi->oauth2_url_complete != NULL) {
        ret = asprintf(&msg, _("Authenticate at %1$s and press ENTER."),
                       pi->oauth2_url_complete);
    } else {
        ret = asprintf(&msg, _("Authenticate with PIN %1$s at %2$s and press "
                       "ENTER."), pi->oauth2_pin, pi->oauth2_url);
    }
    if (ret == -1) {
        return PAM_SYSTEM_ERR;
    }

    ret = do_pam_conversation(pamh, PAM_PROMPT_ECHO_OFF, msg, NULL, &answer);
    free(msg);
    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));
        return ret;
    }

    /* We don't care about answer here. We just need to notify that the
     * authentication has finished. */
    free(answer);

    pi->pam_authtok = strdup(pi->oauth2_pin);
    pi->pam_authtok_type = SSS_AUTHTOK_TYPE_OAUTH2;
    pi->pam_authtok_size=strlen(pi->oauth2_pin);

    return PAM_SUCCESS;
}

static int prompt_passkey(pam_handle_t *pamh, struct pam_items *pi,
                          const char *prompt_interactive, const char *prompt_touch)
{
    int ret;
    const struct pam_conv *conv;
    const struct pam_message *mesg[4] = { NULL, NULL, NULL, NULL };
    struct pam_message m[4] = { {0}, {0}, {0}, {0} };
    struct pam_response *resp = NULL;
    bool kerberos_preauth;
    bool prompt_pin;
    int pin_idx = 0;
    int msg_idx = 0;
    size_t needed_size;

    ret = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
    if (ret != PAM_SUCCESS) {
        return ret;
    }
    if (conv == NULL || conv->conv == NULL) {
        logger(pamh, LOG_ERR, "No conversation function");
        return PAM_SYSTEM_ERR;
    }

    kerberos_preauth = pi->passkey_key != NULL ? true : false;
    if (!kerberos_preauth) {
        m[msg_idx].msg_style = PAM_TEXT_INFO;
        m[msg_idx].msg = PASSKEY_LOCAL_AUTH_MSG;
        msg_idx++;
    }

    if ((strcasecmp(pi->passkey_prompt_pin, "false")) == 0) {
        prompt_pin = false;
    } else {
        prompt_pin = true;
    }

	/* Interactive, prompt a message and wait before continuing */
    if (prompt_interactive != NULL && prompt_interactive[0] != '\0') {
	    m[msg_idx].msg_style = PAM_PROMPT_ECHO_OFF;
	    m[msg_idx].msg = prompt_interactive;
	    msg_idx++;
    }

    /* Prompt for PIN
     *
     * If prompt_pin is false but a PIN is set on the device
     * we still prompt for PIN */
    if (prompt_pin) {
        m[msg_idx].msg_style = PAM_PROMPT_ECHO_OFF;
        m[msg_idx].msg = PASSKEY_DEFAULT_PIN_MSG;
        pin_idx = msg_idx;
        msg_idx++;
    }

    /* Prompt to remind the user to touch the device */
    if (prompt_touch != NULL && prompt_touch[0] != '\0') {
        m[msg_idx].msg_style = PAM_PROMPT_ECHO_OFF;
	    m[msg_idx].msg = prompt_touch;
        msg_idx++;
    }

    mesg[0] = (const struct pam_message *) m;
    /* The following assignment might look a bit odd but is recommended in the
     * pam_conv man page to make sure that the second argument of the PAM
     * conversation function can be interpreted in two different ways.
     * Basically it is important that both the actual struct pam_message and
     * the pointers to the struct pam_message are arrays. Since the assignment
     * makes clear that mesg[] and (*mesg)[] are arrays it should be kept this
     * way and not be replaced by other equivalent assignments. */
    for (int i = 1; i < msg_idx; i++) {
        mesg[i] = & (( *mesg )[i]);
    }

    ret = conv->conv(msg_idx, mesg, &resp, conv->appdata_ptr);
    if (ret != PAM_SUCCESS) {
        D(("Conversation failure: %s.", pam_strerror(pamh, ret)));
        return ret;
    }

    if (kerberos_preauth) {
        if (!prompt_pin) {
            resp[pin_idx].resp = NULL;
        }

        pi->pam_authtok_type = SSS_AUTHTOK_TYPE_PASSKEY_KRB;
        sss_auth_passkey_calc_size(pi->passkey_prompt_pin,
                                   pi->passkey_key,
                                   resp[pin_idx].resp,
                                   &needed_size);

        pi->pam_authtok = malloc(needed_size);
        if (pi->pam_authtok == NULL) {
            D(("malloc failed."));
            ret = PAM_BUF_ERR;
            goto done;
        }

        sss_auth_pack_passkey_blob((uint8_t *)pi->pam_authtok,
                                    pi->passkey_prompt_pin, pi->passkey_key,
                                    resp[pin_idx].resp);

    } else {
        if (!prompt_pin) {
            /* user verification = false, SSS_AUTHTOK_TYPE_PASSKEY will be reset to
             * SSS_AUTHTOK_TYPE_NULL in PAM responder
             */
            pi->pam_authtok_type = SSS_AUTHTOK_TYPE_PASSKEY;
            pi->pam_authtok = NULL;
            pi->pam_authtok_size = 0;
            ret = PAM_SUCCESS;
            goto done;
        } else {
            pi->pam_authtok_type = SSS_AUTHTOK_TYPE_PASSKEY;
            pi->pam_authtok = strdup(resp[pin_idx].resp);
            needed_size = strlen(pi->pam_authtok);
        }
    }

    pi->pam_authtok_size = needed_size;

    /* Fallback to password auth if no PIN was entered */
    if (prompt_pin) {
        if (resp[pin_idx].resp == NULL || resp[pin_idx].resp[0] == '\0') {
            ret = EIO;
            goto done;
        }
    }

    ret = PAM_SUCCESS;

done:
    if (resp != NULL) {
        if (resp[pin_idx].resp != NULL) {
            _pam_overwrite((void *)resp[pin_idx].resp);
            free(resp[pin_idx].resp);
        }

        free(resp);
        resp = NULL;
    }

    return ret;
}

#define SC_PROMPT_FMT "PIN for %s: "

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#define CERT_SEL_PROMPT_FMT "%s"
#define SEL_TITLE discard_const("Please select a certificate")

static int prompt_multi_cert_gdm(pam_handle_t *pamh, struct pam_items *pi)
{
#ifdef HAVE_GDM_PAM_EXTENSIONS
    int ret;
    size_t cert_count = 0;
    size_t c;
    const struct pam_conv *conv;
    struct cert_auth_info *cai;
    GdmPamExtensionChoiceListRequest *request = NULL;
    GdmPamExtensionChoiceListResponse *response = NULL;
    struct pam_message prompt_message;
    const struct pam_message *prompt_messages[1];
    struct pam_response *reply = NULL;
    char *prompt;

    if (!GDM_PAM_EXTENSION_SUPPORTED(GDM_PAM_EXTENSION_CHOICE_LIST)) {
        return ENOTSUP;
    }

    if (pi->cert_list == NULL) {
        return EINVAL;
    }

    DLIST_FOR_EACH(cai, pi->cert_list) {
        cert_count++;
    }

    ret = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (ret != PAM_SUCCESS) {
        ret = EIO;
        return ret;
    }

    request = calloc(1, GDM_PAM_EXTENSION_CHOICE_LIST_REQUEST_SIZE(cert_count));
    if (request == NULL) {
        ret = ENOMEM;
        goto done;
    }
    GDM_PAM_EXTENSION_CHOICE_LIST_REQUEST_INIT(request, SEL_TITLE, cert_count);

    c = 0;
    DLIST_FOR_EACH(cai, pi->cert_list) {
        ret = asprintf(&prompt, CERT_SEL_PROMPT_FMT, cai->prompt_str);
        if (ret == -1) {
            ret = ENOMEM;
            goto done;
        }
        free(cai->choice_list_id);
        ret = asprintf(&cai->choice_list_id, "%zu", c);
        if (ret == -1) {
            cai->choice_list_id = NULL;
            free(prompt);
            ret = ENOMEM;
            goto done;
        }

        request->list.items[c].key = cai->choice_list_id;
        request->list.items[c++].text = prompt;
    }

    GDM_PAM_EXTENSION_MESSAGE_TO_BINARY_PROMPT_MESSAGE(request,
                                                       &prompt_message);
    prompt_messages[0] = &prompt_message;

    ret = conv->conv(1, prompt_messages, &reply, conv->appdata_ptr);
    if (ret != PAM_SUCCESS) {
        ret = EIO;
        goto done;
    }

    ret = EIO;
    response = GDM_PAM_EXTENSION_REPLY_TO_CHOICE_LIST_RESPONSE(reply);
    if (response->key == NULL) {
        goto done;
    }

    DLIST_FOR_EACH(cai, pi->cert_list) {
        if (strcmp(response->key, cai->choice_list_id) == 0) {
            pam_info(pamh, "Certificate ‘%s’ selected", cai->key_id);
            pi->selected_cert = cai;
            ret = 0;
            break;
        }
    }

done:
    if (request != NULL) {
        for (c = 0; c < cert_count; c++) {
            free(discard_const(request->list.items[c++].text));
        }
        free(request);
    }
    free(response);

    return ret;
#else
    return ENOTSUP;
#endif
}

#define TEXT_CERT_SEL_PROMPT_FMT "%s\n[%zu]:\n%s\n"
#define TEXT_SEL_TITLE discard_const("Please select a certificate by typing " \
                                     "the corresponding number\n")

static int prompt_multi_cert(pam_handle_t *pamh, struct pam_items *pi)
{
    int ret;
    size_t cert_count = 0;
    size_t tries = 0;
    long int resp = -1;
    struct cert_auth_info *cai;
    char *prompt;
    char *tmp;
    char *answer;
    char *ep;

    /* First check if gdm extension is supported */
    ret = prompt_multi_cert_gdm(pamh, pi);
    if (ret != ENOTSUP) {
        return ret;
    }

    if (pi->cert_list == NULL) {
        return EINVAL;
    }

    prompt = strdup(TEXT_SEL_TITLE);
    if (prompt == NULL) {
        return ENOMEM;
    }

    DLIST_FOR_EACH(cai, pi->cert_list) {
        cert_count++;
        ret = asprintf(&tmp, TEXT_CERT_SEL_PROMPT_FMT, prompt, cert_count,
                                                       cai->prompt_str);
        free(prompt);
        if (ret == -1) {
            return ENOMEM;
        }

        prompt = tmp;
    }

    do {
        ret = do_pam_conversation(pamh, PAM_PROMPT_ECHO_ON, prompt, NULL,
                                  &answer);
        if (ret != PAM_SUCCESS) {
            D(("do_pam_conversation failed."));
            break;
        }

        errno = 0;
        resp = strtol(answer, &ep, 10);
        if (errno == 0 && *ep == '\0' && resp > 0 && resp <= cert_count) {
            /* do not free answer ealier because ep is pointing to it */
            free(answer);
            break;
        }
        free(answer);
        resp = -1;
    } while (++tries < 5);
    free(prompt);

    pi->selected_cert = NULL;
    ret = ENOENT;
    if (resp > 0 && resp <= cert_count) {
        cert_count = 0;
        DLIST_FOR_EACH(cai, pi->cert_list) {
            cert_count++;
            if (resp == cert_count) {
                pam_info(pamh, "Certificate ‘%s’ selected", cai->key_id);
                pi->selected_cert = cai;
                ret = 0;
                break;
            }
        }
    }

    return ret;
}

#define SC_INSERT_PROMPT _("Please (re)insert (different) Smartcard")

static int prompt_sc_pin(pam_handle_t *pamh, struct pam_items *pi)
{
    int ret;
    char *answer = NULL;
    char *prompt = NULL;
    size_t needed_size;
    const struct pam_conv *conv;
    const struct pam_message *mesg[2] = { NULL, NULL };
    struct pam_message m[2] = { { 0 }, { 0 } };
    struct pam_response *resp = NULL;
    struct cert_auth_info *cai = pi->selected_cert;

    if (cai == NULL && (SERVICE_IS_GDM_SMARTCARD(pi)
                            || (pi->flags & PAM_CLI_FLAGS_REQUIRE_CERT_AUTH))) {
        ret = asprintf(&prompt, SC_INSERT_PROMPT);
    } else if (cai == NULL || cai->token_name == NULL
                    || *cai->token_name == '\0') {
        return PAM_SYSTEM_ERR;
    } else {
        ret = asprintf(&prompt, SC_PROMPT_FMT, cai->token_name);
    }

    if (ret == -1) {
        D(("asprintf failed."));
        return PAM_SYSTEM_ERR;
    }

    if (cai == NULL) {
        ret = do_pam_conversation(pamh, PAM_TEXT_INFO, prompt, NULL, NULL);
        if (ret != PAM_SUCCESS) {
            D(("Conversation failure: %s, ignored", pam_strerror(pamh, ret)));
        }
    }

    if (pi->user_name_hint) {
        ret = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
        if (ret != PAM_SUCCESS) {
            free(prompt);
            return ret;
        }
        if (conv == NULL || conv->conv == NULL) {
            logger(pamh, LOG_ERR, "No conversation function");
            free(prompt);
            return PAM_SYSTEM_ERR;
        }

        m[0].msg_style = PAM_PROMPT_ECHO_OFF;
        m[0].msg = prompt;
        m[1].msg_style = PAM_PROMPT_ECHO_ON;
        m[1].msg = "User name hint: ";

        mesg[0] = (const struct pam_message *)m;
        /* The following assignment might look a bit odd but is recommended in the
         * pam_conv man page to make sure that the second argument of the PAM
         * conversation function can be interpreted in two different ways.
         * Basically it is important that both the actual struct pam_message and
         * the pointers to the struct pam_message are arrays. Since the assignment
         * makes clear that mesg[] and (*mesg)[] are arrays it should be kept this
         * way and not be replaced by other equivalent assignments. */
        mesg[1] = &((*mesg)[1]);

        ret = conv->conv(2, mesg, &resp, conv->appdata_ptr);
        free(prompt);
        if (ret != PAM_SUCCESS) {
            D(("Conversation failure: %s.", pam_strerror(pamh, ret)));
            return ret;
        }

        if (resp == NULL) {
            D(("response expected, but resp==NULL"));
            return PAM_SYSTEM_ERR;
        }

        if (resp[0].resp == NULL || *(resp[0].resp) == '\0') {
            D(("Missing PIN."));
            ret = PAM_CRED_INSUFFICIENT;
            goto done;
        }

        answer = strndup(resp[0].resp, MAX_AUTHTOK_SIZE);
        _pam_overwrite((void *)resp[0].resp);
        free(resp[0].resp);
        resp[0].resp = NULL;
        if (answer == NULL) {
            D(("strndup failed"));
            ret = PAM_BUF_ERR;
            goto done;
        }

        if (resp[1].resp != NULL && *(resp[1].resp) != '\0') {
            ret = pam_set_item(pamh, PAM_USER, resp[1].resp);
            free(resp[1].resp);
            resp[1].resp = NULL;
            if (ret != PAM_SUCCESS) {
                D(("Failed to set PAM_USER with user name hint [%s]",
                   pam_strerror(pamh, ret)));
                goto done;
            }

            ret = pam_get_item(pamh, PAM_USER, (const void **)&(pi->pam_user));
            if (ret != PAM_SUCCESS) {
                D(("Failed to get PAM_USER with user name hint [%s]",
                   pam_strerror(pamh, ret)));
                goto done;
            }

            pi->pam_user_size = strlen(pi->pam_user) + 1;
        }
    } else {
        ret = do_pam_conversation(pamh, PAM_PROMPT_ECHO_OFF, prompt, NULL,
                                  &answer);
        free(prompt);
        if (ret != PAM_SUCCESS) {
            D(("do_pam_conversation failed."));
            return ret;
        }
    }

    if (cai == NULL) {
        /* it is expected that the user just replaces the Smartcard which
         * would trigger gdm to restart the PAM module, so it is not
         * expected that this part of the code is reached. */
        ret = PAM_AUTHINFO_UNAVAIL;
        goto done;
    }

    if (answer == NULL || *answer == '\0') {
        D(("Missing PIN."));
        ret = PAM_CRED_INSUFFICIENT;
        goto done;
    } else {

        ret = sss_auth_pack_sc_blob(answer, 0, cai->token_name, 0,
                                    cai->module_name, 0,
                                    cai->key_id, 0,
                                    cai->label, 0,
                                    NULL, 0, &needed_size);
        if (ret != EAGAIN) {
            D(("sss_auth_pack_sc_blob failed."));
            ret = PAM_BUF_ERR;
            goto done;
        }

        pi->pam_authtok = malloc(needed_size);
        if (pi->pam_authtok == NULL) {
            D(("malloc failed."));
            ret = PAM_BUF_ERR;
            goto done;
        }

        ret = sss_auth_pack_sc_blob(answer, 0, cai->token_name, 0,
                                    cai->module_name, 0,
                                    cai->key_id, 0,
                                    cai->label, 0,
                                    (uint8_t *) pi->pam_authtok, needed_size,
                                    &needed_size);
        if (ret != EOK) {
            D(("sss_auth_pack_sc_blob failed."));
            free((void *)pi->pam_authtok);
            ret = PAM_BUF_ERR;
            goto done;
        }

        pi->pam_authtok_type = SSS_AUTHTOK_TYPE_SC_PIN;
        pi->pam_authtok_size = needed_size;
    }

    ret = PAM_SUCCESS;

done:
    _pam_overwrite((void *)answer);
    free(answer);
    answer=NULL;

    if (resp != NULL) {
        if (resp[0].resp != NULL) {
            _pam_overwrite((void *)resp[0].resp);
            free(resp[0].resp);
        }
        if (resp[1].resp != NULL) {
            _pam_overwrite((void *)resp[1].resp);
            free(resp[1].resp);
        }

        free(resp);
        resp = NULL;
    }

    return ret;
}

static int prompt_new_password(pam_handle_t *pamh, struct pam_items *pi)
{
    int ret;
    char *answer = NULL;

    ret = do_pam_conversation(pamh, PAM_PROMPT_ECHO_OFF,
                              _("New Password: "),
                              _("Reenter new Password: "),
                              &answer);
    if (ret != PAM_SUCCESS) {
        D(("do_pam_conversation failed."));
        return ret;
    }
    if (answer == NULL) {
        pi->pam_newauthtok = NULL;
        pi->pam_newauthtok_type = SSS_AUTHTOK_TYPE_EMPTY;
        pi->pam_newauthtok_size=0;
    } else {
        pi->pam_newauthtok = strdup(answer);
        _pam_overwrite((void *)answer);
        free(answer);
        answer=NULL;
        if (pi->pam_newauthtok == NULL) {
            return PAM_BUF_ERR;
        }
        pi->pam_newauthtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
        pi->pam_newauthtok_size=strlen(pi->pam_newauthtok);
    }

    return PAM_SUCCESS;
}

static void eval_argv(pam_handle_t *pamh, int argc, const char **argv,
                      uint32_t *flags, int *retries, bool *quiet_mode,
                      const char **domains)
{
    char *ep;

    *quiet_mode = false;

    for (; argc-- > 0; ++argv) {
        if (strcmp(*argv, "forward_pass") == 0) {
            *flags |= PAM_CLI_FLAGS_FORWARD_PASS;
        } else if (strcmp(*argv, "use_first_pass") == 0) {
            *flags |= PAM_CLI_FLAGS_USE_FIRST_PASS;
        } else if (strcmp(*argv, "use_authtok") == 0) {
            *flags |= PAM_CLI_FLAGS_USE_AUTHTOK;
        } else if (strncmp(*argv, OPT_DOMAINS_KEY, strlen(OPT_DOMAINS_KEY)) == 0) {
            if (*(*argv+strlen(OPT_DOMAINS_KEY)) == '\0') {
                logger(pamh, LOG_ERR, "Missing argument to option domains.");
                *domains = "";
            } else {
                *domains = *argv+strlen(OPT_DOMAINS_KEY);
            }

        } else if (strncmp(*argv, OPT_RETRY_KEY, strlen(OPT_RETRY_KEY)) == 0) {
            if (*(*argv+6) == '\0') {
                logger(pamh, LOG_ERR, "Missing argument to option retry.");
                *retries = 0;
            } else {
                errno = 0;
                *retries = strtol(*argv+6, &ep, 10);
                if (errno != 0) {
                    D(("strtol failed [%d][%s]", errno, strerror(errno)));
                    *retries = 0;
                }
                if (*ep != '\0') {
                    logger(pamh, LOG_ERR, "Argument to option retry contains "
                                          "extra characters.");
                    *retries = 0;
                }
                if (*retries < 0) {
                    logger(pamh, LOG_ERR, "Argument to option retry must not "
                                          "be negative.");
                    *retries = 0;
                }
            }
        } else if (strcmp(*argv, "quiet") == 0) {
            *quiet_mode = true;
        } else if (strcmp(*argv, "ignore_unknown_user") == 0) {
            *flags |= PAM_CLI_FLAGS_IGNORE_UNKNOWN_USER;
        } else if (strcmp(*argv, "ignore_authinfo_unavail") == 0) {
            *flags |= PAM_CLI_FLAGS_IGNORE_AUTHINFO_UNAVAIL;
        } else if (strcmp(*argv, "use_2fa") == 0) {
            *flags |= PAM_CLI_FLAGS_USE_2FA;
        } else if (strcmp(*argv, "allow_missing_name") == 0) {
            *flags |= PAM_CLI_FLAGS_ALLOW_MISSING_NAME;
        } else if (strcmp(*argv, "prompt_always") == 0) {
            *flags |= PAM_CLI_FLAGS_PROMPT_ALWAYS;
        } else if (strcmp(*argv, "try_cert_auth") == 0) {
            *flags |= PAM_CLI_FLAGS_TRY_CERT_AUTH;
        } else if (strcmp(*argv, "require_cert_auth") == 0) {
            *flags |= PAM_CLI_FLAGS_REQUIRE_CERT_AUTH;
        } else {
            logger(pamh, LOG_WARNING, "unknown option: %s", *argv);
        }
    }

    return;
}

static int prompt_by_config(pam_handle_t *pamh, struct pam_items *pi)
{
    size_t c;
    int ret = PAM_SUCCESS;

    if (pi->pc == NULL || *pi->pc == NULL) {
        return PAM_SYSTEM_ERR;
    }

    for (c = 0; pi->pc[c] != NULL; c++) {
        switch (pc_get_type(pi->pc[c])) {
        case PC_TYPE_PASSWORD:
            ret = prompt_password(pamh, pi, pc_get_password_prompt(pi->pc[c]));
            break;
        case PC_TYPE_2FA:
            ret = prompt_2fa(pamh, pi, pc_get_2fa_1st_prompt(pi->pc[c]),
                             pc_get_2fa_2nd_prompt(pi->pc[c]));
            break;
        case PC_TYPE_2FA_SINGLE:
            ret = prompt_2fa_single(pamh, pi,
                                    pc_get_2fa_single_prompt(pi->pc[c]));
            break;
        case PC_TYPE_PASSKEY:
            ret = prompt_passkey(pamh, pi,
                                 pc_get_passkey_inter_prompt(pi->pc[c]),
                                 pc_get_passkey_touch_prompt(pi->pc[c]));
            break;
        case PC_TYPE_SC_PIN:
            ret = prompt_sc_pin(pamh, pi);
            /* Todo: add extra string option */
            break;
        default:
            ret = PAM_SYSTEM_ERR;
        }

        /* If not credential where given try the next type otherwise we are
         * done. */
        if (ret == PAM_SUCCESS && pi->pam_authtok_size == 0) {
            continue;
        }

        break;
    }

    return ret;
}

static int get_authtok_for_authentication(pam_handle_t *pamh,
                                          struct pam_items *pi,
                                          uint32_t flags)
{
    int ret;
    const char *pin = NULL;

    if ((flags & PAM_CLI_FLAGS_USE_FIRST_PASS)
            || ( pi->pamstack_authtok != NULL
                    && *(pi->pamstack_authtok) != '\0'
                    && !(flags & PAM_CLI_FLAGS_PROMPT_ALWAYS))) {
        pi->pam_authtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
        pi->pam_authtok = strdup(pi->pamstack_authtok);
        if (pi->pam_authtok == NULL) {
            D(("option use_first_pass set, but no password found"));
            return PAM_BUF_ERR;
        }
        pi->pam_authtok_size = strlen(pi->pam_authtok);
    } else {
        if (pi->oauth2_url != NULL) {
            /* Prompt config is not supported for OAuth2. */
            ret = prompt_oauth2(pamh, pi);
        } else if (pi->pc != NULL) {
            ret = prompt_by_config(pamh, pi);
        } else {
            if (pi->cert_list != NULL) {
                if (pi->cert_list->next == NULL) {
                    /* Only one certificate */
                    pi->selected_cert = pi->cert_list;
                } else {
                    ret = prompt_multi_cert(pamh, pi);
                    if (ret != 0) {
                        D(("Failed to select certificate"));
                        return PAM_AUTHTOK_ERR;
                    }
                }
                ret = prompt_sc_pin(pamh, pi);
            } else if (SERVICE_IS_GDM_SMARTCARD(pi)
                    || (pi->flags & PAM_CLI_FLAGS_REQUIRE_CERT_AUTH)) {
               /* Use pin prompt as fallback for gdm-smartcard */
                ret = prompt_sc_pin(pamh, pi);
            } else if (flags & PAM_CLI_FLAGS_USE_2FA
                    || (pi->otp_vendor != NULL && pi->otp_token_id != NULL
                            && pi->otp_challenge != NULL)) {
                if (pi->password_prompting) {
                    ret = prompt_2fa(pamh, pi, _("First Factor: "),
                                     _("Second Factor (optional): "));
                } else {
                    ret = prompt_2fa(pamh, pi, _("First Factor: "),
                                     _("Second Factor: "));
                }
            } else if (pi->passkey_prompt_pin) {
                ret = prompt_passkey(pamh, pi,
                                     _("Insert your passkey device, then press ENTER."),
                                     "");
                /* Fallback to password auth if no PIN was entered */
                if (ret == EIO) {
                    ret = prompt_password(pamh, pi, _("Password: "));
                    if (pi->pam_authtok_size == 0) {
                        D(("Empty password failure"));
                        pi->passkey_prompt_pin = NULL;
                        return PAM_AUTHTOK_ERR;
                    }
                }
            } else {
                ret = prompt_password(pamh, pi, _("Password: "));
            }
        }
        if (ret != PAM_SUCCESS) {
            D(("failed to get password from user"));
            return ret;
        }

        if (flags & PAM_CLI_FLAGS_FORWARD_PASS) {
            if (pi->pam_authtok_type == SSS_AUTHTOK_TYPE_PASSWORD) {
                ret = pam_set_item(pamh, PAM_AUTHTOK, pi->pam_authtok);
            } else if (pi->pam_authtok_type == SSS_AUTHTOK_TYPE_SC_PIN) {
                pin = sss_auth_get_pin_from_sc_blob((uint8_t *) pi->pam_authtok,
                                                    pi->pam_authtok_size);
                if (pin != NULL) {
                    ret = pam_set_item(pamh, PAM_AUTHTOK, pin);
                } else {
                    ret = PAM_SYSTEM_ERR;
                }
            } else if (pi->pam_authtok_type == SSS_AUTHTOK_TYPE_2FA
                           && pi->first_factor != NULL) {
                ret = pam_set_item(pamh, PAM_AUTHTOK, pi->first_factor);
            } else {
                ret = PAM_SYSTEM_ERR;
            }
            if (ret != PAM_SUCCESS) {
                D(("Failed to set PAM_AUTHTOK [%s], "
                   "authtok may not be available for other modules",
                   pam_strerror(pamh,ret)));
            }
        }
    }

    return PAM_SUCCESS;
}

static int check_authtok_data(pam_handle_t *pamh, struct pam_items *pi)
{
    int pam_status;
    int *authtok_type;
    size_t *authtok_size;
    char *authtok_data;

    pam_status = pam_get_data(pamh, PAM_SSS_AUTHOK_TYPE,
                              (const void **) &authtok_type);
    if (pam_status != PAM_SUCCESS) {
        D(("pam_get_data failed."));
        return EIO;
    }

    pam_status = pam_get_data(pamh, PAM_SSS_AUTHOK_SIZE,
                              (const void **) &authtok_size);
    if (pam_status != PAM_SUCCESS) {
        D(("pam_get_data failed."));
        return EIO;
    }

    pam_status = pam_get_data(pamh, PAM_SSS_AUTHOK_DATA,
                              (const void **) &authtok_data);
    if (pam_status != PAM_SUCCESS) {
        D(("pam_get_data failed."));
        return EIO;
    }

    pi->pam_authtok = malloc(*authtok_size);
    if (pi->pam_authtok == NULL) {
        D(("malloc failed."));
        return ENOMEM;
    }
    memcpy(pi->pam_authtok, authtok_data, *authtok_size);

    pi->pam_authtok_type = *authtok_type;
    pi->pam_authtok_size = *authtok_size;

    return 0;
}

static int keep_authtok_data(pam_handle_t *pamh, struct pam_items *pi)
{
    int pam_status;
    int *authtok_type;
    size_t *authtok_size;
    char *authtok_data;

    authtok_type = malloc(sizeof(int));
    if (authtok_type == NULL) {
        D(("malloc failed."));
        return ENOMEM;
    }
    *authtok_type = pi->pam_authtok_type;

    pam_status = pam_set_data(pamh, PAM_SSS_AUTHOK_TYPE, authtok_type,
                              free_exp_data);
    if (pam_status != PAM_SUCCESS) {
        free(authtok_type);
        D(("pam_set_data failed."));
        return EIO;
    }

    authtok_size = malloc(sizeof(size_t));
    if (authtok_size == NULL) {
        D(("malloc failed."));
        return ENOMEM;
    }
    *authtok_size = pi->pam_authtok_size;

    pam_status = pam_set_data(pamh, PAM_SSS_AUTHOK_SIZE, authtok_size,
                              free_exp_data);
    if (pam_status != PAM_SUCCESS) {
        free(authtok_size);
        D(("pam_set_data failed."));
        return EIO;
    }

    authtok_data = malloc(pi->pam_authtok_size);
    if (authtok_data == NULL) {
        D(("malloc failed."));
        return ENOMEM;
    }
    memcpy(authtok_data, pi->pam_authtok, pi->pam_authtok_size);

    pam_status = pam_set_data(pamh, PAM_SSS_AUTHOK_DATA, authtok_data,
                              free_exp_data);
    if (pam_status != PAM_SUCCESS) {
        free(authtok_data);
        D(("pam_set_data failed."));
        return EIO;
    }

    return 0;
}

static int get_authtok_for_password_change(pam_handle_t *pamh,
                                           struct pam_items *pi,
                                           uint32_t flags,
                                           int pam_flags)
{
    int ret;
    const int *exp_data = NULL;
    ret = pam_get_data(pamh, PWEXP_FLAG, (const void **) &exp_data);
    if (ret != PAM_SUCCESS) {
        exp_data = NULL;
    }

    if (pam_flags & PAM_PRELIM_CHECK) {
        if (getuid() == 0 && !exp_data )
            return PAM_SUCCESS;

        if (flags & PAM_CLI_FLAGS_USE_2FA
                || (pi->otp_vendor != NULL && pi->otp_token_id != NULL
                        && pi->otp_challenge != NULL)) {
            if (pi->password_prompting) {
                ret = prompt_2fa(pamh, pi, _("First Factor (Current Password): "),
                                 _("Second Factor (optional): "));
            } else {
                ret = prompt_2fa(pamh, pi, _("First Factor (Current Password): "),
                                 _("Second Factor: "));
            }
        } else if ((flags & PAM_CLI_FLAGS_USE_FIRST_PASS)
                       && check_authtok_data(pamh, pi) != 0) {
            if (pi->pamstack_oldauthtok == NULL) {
                pi->pam_authtok_type = SSS_AUTHTOK_TYPE_EMPTY;
                pi->pam_authtok = NULL;
                pi->pam_authtok_size = 0;
            } else {
                pi->pam_authtok = strdup(pi->pamstack_oldauthtok);
                if (pi->pam_authtok == NULL) {
                    D(("strdup failed"));
                    return PAM_BUF_ERR;
                }
                pi->pam_authtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
                pi->pam_authtok_size = strlen(pi->pam_authtok);
            }
            ret = PAM_SUCCESS;
        } else {
            ret = prompt_password(pamh, pi, _("Current Password: "));
        }
        if (ret != PAM_SUCCESS) {
            D(("failed to get credentials from user"));
            return ret;
        }

        ret = pam_set_item(pamh, PAM_OLDAUTHTOK, pi->pam_authtok);
        if (ret != PAM_SUCCESS) {
            D(("Failed to set PAM_OLDAUTHTOK [%s], "
                "oldauthtok may not be available",
               pam_strerror(pamh,ret)));
               return ret;
        }

        if (pi->pam_authtok_type == SSS_AUTHTOK_TYPE_2FA) {
            ret = keep_authtok_data(pamh, pi);
            if (ret != 0) {
                D(("Failed to store authtok data to pam handle. Password "
                   "change might fail."));
            }
        }

        return PAM_SUCCESS;
    }

    if (check_authtok_data(pamh, pi) != 0) {
        if (pi->pamstack_oldauthtok == NULL) {
            if (getuid() != 0) {
                D(("no password found for chauthtok"));
                return PAM_BUF_ERR;
            } else {
                pi->pam_authtok_type = SSS_AUTHTOK_TYPE_EMPTY;
                pi->pam_authtok = NULL;
                pi->pam_authtok_size = 0;
            }
        } else {
            pi->pam_authtok = strdup(pi->pamstack_oldauthtok);
            if (pi->pam_authtok == NULL) {
                D(("strdup failed"));
                return PAM_BUF_ERR;
            }
            pi->pam_authtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
            pi->pam_authtok_size = strlen(pi->pam_authtok);
        }
    }

    if (flags & PAM_CLI_FLAGS_USE_AUTHTOK) {
        pi->pam_newauthtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
        pi->pam_newauthtok =  strdup(pi->pamstack_authtok);
        if (pi->pam_newauthtok == NULL) {
            D(("option use_authtok set, but no new password found"));
            return PAM_BUF_ERR;
        }
        pi->pam_newauthtok_size = strlen(pi->pam_newauthtok);
    } else {
        ret = prompt_new_password(pamh, pi);
        if (ret != PAM_SUCCESS) {
            D(("failed to get new password from user"));
            return ret;
        }

        if (flags & PAM_CLI_FLAGS_FORWARD_PASS) {
            ret = pam_set_item(pamh, PAM_AUTHTOK, pi->pam_newauthtok);
            if (ret != PAM_SUCCESS) {
                D(("Failed to set PAM_AUTHTOK [%s], "
                   "oldauthtok may not be available",
                   pam_strerror(pamh,ret)));
            }
        }
    }

    return PAM_SUCCESS;
}

#define SC_ENTER_LABEL_FMT "Please insert smart card labeled\n %s"
#define SC_ENTER_FMT "Please insert smart card"

static int check_login_token_name(pam_handle_t *pamh, struct pam_items *pi,
                                  int retries, bool quiet_mode)
{
    int ret;
    int pam_status;
    char *login_token_name;
    char *prompt = NULL;
    uint32_t orig_flags = pi->flags;

    login_token_name = getenv("PKCS11_LOGIN_TOKEN_NAME");
    if (login_token_name == NULL
            && !(pi->flags & PAM_CLI_FLAGS_REQUIRE_CERT_AUTH)) {
        return PAM_SUCCESS;
    }

    if (login_token_name == NULL) {
        ret = asprintf(&prompt, SC_ENTER_FMT);
    } else {
        ret = asprintf(&prompt, SC_ENTER_LABEL_FMT, login_token_name);
    }
    if (ret == -1) {
        return ENOMEM;
    }

    pi->flags |= PAM_CLI_FLAGS_REQUIRE_CERT_AUTH;

    /* TODO: check multiple cert case */
    while (pi->cert_list == NULL || pi->cert_list->token_name == NULL
                || (login_token_name != NULL
                        && strcmp(login_token_name,
                                  pi->cert_list->token_name) != 0)) {

        free_cert_list(pi->cert_list);
        pi->cert_list = NULL;
        if (retries < 0) {
            ret = PAM_AUTHINFO_UNAVAIL;
            goto done;
        }
        retries--;

        ret = do_pam_conversation(pamh, PAM_TEXT_INFO, prompt, NULL, NULL);
        if (ret != PAM_SUCCESS) {
            D(("do_pam_conversation failed."));
            goto done;
        }

        pam_status = send_and_receive(pamh, pi, SSS_PAM_PREAUTH, quiet_mode);
        if (pam_status != PAM_SUCCESS) {
            D(("send_and_receive returned [%d] during pre-auth", pam_status));
        /*
         * Since we are waiting for the right Smartcard to be inserted errors
         * can be ignored here.
         */
        }
    }

    ret = PAM_SUCCESS;

done:

    pi->flags = orig_flags;
    free(prompt);

    return ret;
}

static int pam_sss(enum sss_cli_command task, pam_handle_t *pamh,
                   int pam_flags, int argc, const char **argv)
{
    int ret;
    int pam_status;
    struct pam_items pi = { 0 };
    uint32_t flags = 0;
    const int *exp_data;
    int *pw_exp_data;
    bool retry = false;
    bool quiet_mode = false;
    int retries = 0;
    const char *domains = NULL;

    bindtextdomain(PACKAGE, LOCALEDIR);

    D(("Hello pam_sssd: %#x", task));

    eval_argv(pamh, argc, argv, &flags, &retries, &quiet_mode, &domains);

    /* Fail all authentication on misconfigured domains= parameter. The admin
     * probably wanted to restrict authentication, so it's safer to fail */
    if (domains && strcmp(domains, "") == 0) {
        return PAM_SYSTEM_ERR;
    }

    pi.requested_domains = domains;

    ret = get_pam_items(pamh, flags, &pi);
    if (ret != PAM_SUCCESS) {
        D(("get items returned error: %s", pam_strerror(pamh,ret)));
        if ((flags & PAM_CLI_FLAGS_TRY_CERT_AUTH)
                || (flags & PAM_CLI_FLAGS_REQUIRE_CERT_AUTH) ) {
            return PAM_AUTHINFO_UNAVAIL;
        }
        if (flags & PAM_CLI_FLAGS_IGNORE_UNKNOWN_USER && ret == PAM_USER_UNKNOWN) {
            ret = PAM_IGNORE;
        }
        if (flags & PAM_CLI_FLAGS_IGNORE_AUTHINFO_UNAVAIL
                && ret == PAM_AUTHINFO_UNAVAIL) {
            ret = PAM_IGNORE;
        }
        return ret;
    }

    do {
        retry = false;

        switch(task) {
            case SSS_PAM_AUTHENTICATE:
                /*
                 * Only do preauth if
                 * - PAM_CLI_FLAGS_USE_FIRST_PASS is not set
                 * - no password is on the stack or PAM_CLI_FLAGS_PROMPT_ALWAYS is set
                 * - preauth indicator file exists.
                 */
                if ( !(flags & PAM_CLI_FLAGS_USE_FIRST_PASS)
                        && (pi.pam_authtok == NULL
                                || (flags & PAM_CLI_FLAGS_PROMPT_ALWAYS))
                        && access(PAM_PREAUTH_INDICATOR, F_OK) == 0) {

                    if (flags & PAM_CLI_FLAGS_REQUIRE_CERT_AUTH) {
                        /* Do not use PAM_CLI_FLAGS_REQUIRE_CERT_AUTH in the first
                         * SSS_PAM_PREAUTH run. In case a card is already inserted
                         * we do not have to prompt to insert a card. */
                        pi.flags &= ~PAM_CLI_FLAGS_REQUIRE_CERT_AUTH;
                        pi.flags |= PAM_CLI_FLAGS_TRY_CERT_AUTH;
                    }

                    pam_status = send_and_receive(pamh, &pi, SSS_PAM_PREAUTH,
                                                  quiet_mode);

                    pi.flags = flags;
                    if (pam_status != PAM_SUCCESS) {
                        D(("send_and_receive returned [%d] during pre-auth",
                           pam_status));
                        /*
                         * Since we are only interested in the result message
                         * and will always use password authentication
                         * as a fallback (except for gdm-smartcard),
                         * errors can be ignored here.
                         */
                    }
                }

                if (flags & PAM_CLI_FLAGS_TRY_CERT_AUTH
                        && pi.cert_list == NULL) {
                    D(("No certificates for authentication available."));
                    overwrite_and_free_pam_items(&pi);
                    return PAM_AUTHINFO_UNAVAIL;
                }

                if (SERVICE_IS_GDM_SMARTCARD(&pi)
                        || (flags & PAM_CLI_FLAGS_REQUIRE_CERT_AUTH)) {
                    ret = check_login_token_name(pamh, &pi, retries,
                                                 quiet_mode);
                    if (ret != PAM_SUCCESS) {
                        D(("check_login_token_name failed.\n"));
                    }
                }

                ret = get_authtok_for_authentication(pamh, &pi, flags);
                if (ret != PAM_SUCCESS) {
                    D(("failed to get authentication token: %s",
                       pam_strerror(pamh, ret)));
                    return ret;
                }
                break;
            case SSS_PAM_CHAUTHTOK:
                /*
                 * Even if we only want to change the (long term) password
                 * there are cases where more than the password is needed to
                 * get the needed privileges in a backend to change the
                 * password.
                 *
                 * E.g. with mandatory 2-factor authentication we have to ask
                 * not only for the current password but for the second
                 * factor, e.g. the one-time token value, as well.
                 *
                 * The means the preauth step has to be done here as well but
                 * only if
                 * - PAM_PRELIM_CHECK is set
                 * - PAM_CLI_FLAGS_USE_FIRST_PASS is not set
                 * - no password is on the stack or PAM_CLI_FLAGS_PROMPT_ALWAYS is set
                 * - preauth indicator file exists.
                 */
                if ( (pam_flags & PAM_PRELIM_CHECK)
                        && !(flags & PAM_CLI_FLAGS_USE_FIRST_PASS)
                        && (pi.pam_authtok == NULL
                                || (flags & PAM_CLI_FLAGS_PROMPT_ALWAYS))
                        && access(PAM_PREAUTH_INDICATOR, F_OK) == 0) {
                    pam_status = send_and_receive(pamh, &pi, SSS_PAM_PREAUTH,
                                                  quiet_mode);
                    if (pam_status != PAM_SUCCESS) {
                        D(("send_and_receive returned [%d] during pre-auth",
                           pam_status));
                        /*
                         * Since we are only interested in the result message
                         * and will always use password authentication
                         * as a fallback, errors can be ignored here.
                         */
                    }
                }

                ret = get_authtok_for_password_change(pamh, &pi, flags, pam_flags);
                if (ret != PAM_SUCCESS) {
                    D(("failed to get tokens for password change: %s",
                       pam_strerror(pamh, ret)));
                    overwrite_and_free_pam_items(&pi);
                    return ret;
                }

                if (pam_flags & PAM_PRELIM_CHECK) {
                    if (pi.pam_authtok_type == SSS_AUTHTOK_TYPE_2FA) {
                        /* We cannot validate the credentials with an OTP
                         * token value during PAM_PRELIM_CHECK because it
                         * would be invalid for the actual password change. So
                         * we are done. */

                        return PAM_SUCCESS;
                    }
                    task = SSS_PAM_CHAUTHTOK_PRELIM;
                }
                break;
            case SSS_PAM_ACCT_MGMT:
            case SSS_PAM_SETCRED:
            case SSS_PAM_OPEN_SESSION:
            case SSS_PAM_CLOSE_SESSION:
                break;
            default:
                D(("Illegal task [%#x]", task));
                return PAM_SYSTEM_ERR;
        }

        pam_status = send_and_receive(pamh, &pi, task, quiet_mode);

        if (flags & PAM_CLI_FLAGS_IGNORE_UNKNOWN_USER
                && pam_status == PAM_USER_UNKNOWN) {
            pam_status = PAM_IGNORE;
        }
        if (flags & PAM_CLI_FLAGS_IGNORE_AUTHINFO_UNAVAIL
                && pam_status == PAM_AUTHINFO_UNAVAIL) {
            pam_status = PAM_IGNORE;
        }

        switch (task) {
            case SSS_PAM_AUTHENTICATE:
                /* We allow sssd to send the return code PAM_NEW_AUTHTOK_REQD during
                 * authentication, see sss_cli.h for details */
                if (pam_status == PAM_NEW_AUTHTOK_REQD) {
                    D(("Authtoken expired, trying to change it"));

                    pw_exp_data = malloc(sizeof(int));
                    if (pw_exp_data == NULL) {
                        D(("malloc failed."));
                        pam_status = PAM_BUF_ERR;
                        break;
                    }
                    *pw_exp_data = 1;

                    pam_status = pam_set_data(pamh, PWEXP_FLAG, pw_exp_data,
                                              free_exp_data);
                    if (pam_status != PAM_SUCCESS) {
                        D(("pam_set_data failed."));
                    }
                }
                break;
            case SSS_PAM_ACCT_MGMT:
                if (pam_status == PAM_SUCCESS &&
                    pam_get_data(pamh, PWEXP_FLAG, (const void **) &exp_data) ==
                                                                      PAM_SUCCESS) {
                    ret = do_pam_conversation(pamh, PAM_TEXT_INFO,
                                   _("Password expired. Change your password now."),
                                   NULL, NULL);
                    if (ret != PAM_SUCCESS) {
                        D(("do_pam_conversation failed."));
                    }
                    pam_status = PAM_NEW_AUTHTOK_REQD;
                }
                break;
            case SSS_PAM_CHAUTHTOK:
                if (pam_status != PAM_SUCCESS && pam_status != PAM_USER_UNKNOWN) {
                    ret = pam_set_item(pamh, PAM_AUTHTOK, NULL);
                    if (ret != PAM_SUCCESS) {
                        D(("Failed to unset PAM_AUTHTOK [%s]",
                           pam_strerror(pamh,ret)));
                    }
                    ret = pam_set_item(pamh, PAM_OLDAUTHTOK, NULL);
                    if (ret != PAM_SUCCESS) {
                        D(("Failed to unset PAM_OLDAUTHTOK [%s]",
                           pam_strerror(pamh,ret)));
                    }
                }
                break;
            case SSS_PAM_CHAUTHTOK_PRELIM:
                if (pam_status == PAM_PERM_DENIED && pi.pam_authtok_size == 0 &&
                    getuid() == 0 &&
                    pam_get_data(pamh, PWEXP_FLAG, (const void **) &exp_data) !=
                                                                      PAM_SUCCESS) {

                    ret = select_pw_reset_message(pamh, &pi);
                    if (ret != 0) {
                        D(("select_pw_reset_message failed.\n"));
                    }
                }
            default:
                /* nothing to do */
                break;
        }

        overwrite_and_free_pam_items(&pi);

        D(("retries [%d].", retries));

        if (pam_status != PAM_SUCCESS &&
            (task == SSS_PAM_AUTHENTICATE || task == SSS_PAM_CHAUTHTOK_PRELIM) &&
            retries > 0) {
            retry = true;
            retries--;

            flags &= ~PAM_CLI_FLAGS_USE_FIRST_PASS;
            ret = pam_set_item(pamh, PAM_AUTHTOK, NULL);
            if (ret != PAM_SUCCESS) {
                D(("Failed to unset PAM_AUTHTOK [%s]",
                   pam_strerror(pamh,ret)));
            }
            ret = pam_set_item(pamh, PAM_OLDAUTHTOK, NULL);
            if (ret != PAM_SUCCESS) {
                D(("Failed to unset PAM_OLDAUTHTOK [%s]",
                   pam_strerror(pamh,ret)));
            }
        }
    } while(retry);

    return pam_status;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv )
{
    return pam_sss(SSS_PAM_AUTHENTICATE, pamh, flags, argc, argv);
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv )
{
    return pam_sss(SSS_PAM_SETCRED, pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv )
{
    return pam_sss(SSS_PAM_ACCT_MGMT, pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv )
{
    return pam_sss(SSS_PAM_CHAUTHTOK, pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv )
{
    return pam_sss(SSS_PAM_OPEN_SESSION, pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv )
{
    return pam_sss(SSS_PAM_CLOSE_SESSION, pamh, flags, argc, argv);
}


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_sssd_modstruct ={
     "pam_sssd",
     pam_sm_authenticate,
     pam_sm_setcred,
     pam_sm_acct_mgmt,
     pam_sm_open_session,
     pam_sm_close_session,
     pam_sm_chauthtok
};

#endif
