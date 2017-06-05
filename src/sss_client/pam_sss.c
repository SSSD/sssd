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

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#include "sss_pam_compat.h"
#include "sss_pam_macros.h"

#include "sss_cli.h"
#include "pam_message.h"
#include "util/atomic_io.h"
#include "util/authtok-utils.h"

#include <libintl.h>
#define _(STRING) dgettext (PACKAGE, STRING)

#define FLAGS_USE_FIRST_PASS (1 << 0)
#define FLAGS_FORWARD_PASS   (1 << 1)
#define FLAGS_USE_AUTHTOK    (1 << 2)
#define FLAGS_IGNORE_UNKNOWN_USER (1 << 3)
#define FLAGS_IGNORE_AUTHINFO_UNAVAIL (1 << 4)
#define FLAGS_USE_2FA (1 << 5)
#define FLAGS_ALLOW_MISSING_NAME (1 << 6)
#define FLAGS_PROMPT_ALWAYS (1 << 7)

#define PWEXP_FLAG "pam_sss:password_expired_flag"
#define FD_DESTRUCTOR "pam_sss:fd_destructor"

#define PW_RESET_MSG_FILENAME_TEMPLATE SSSD_CONF_DIR"/customize/%s/pam_sss_pw_reset_message.%s"
#define PW_RESET_MSG_MAX_SIZE 4096

#define OPT_RETRY_KEY "retry="
#define OPT_DOMAINS_KEY "domains="

#define EXP_ACC_MSG _("Permission denied. ")
#define SRV_MSG     _("Server message: ")

#define DEBUG_MGS_LEN 1024
#define MAX_AUTHTOK_SIZE (1024*1024)
#define CHECK_AND_RETURN_PI_STRING(s) ((s != NULL && *s != '\0')? s : "(not available)")

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
    sss_pam_close_fd();
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

    free(pi->cert_user);
    pi->cert_user = NULL;

    free(pi->token_name);
    pi->token_name = NULL;

    free(pi->module_name);
    pi->module_name = NULL;

    free(pi->key_id);
    pi->key_id = NULL;
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
    const char* unit="second(s)";

    if (buflen != 2* sizeof(uint32_t)) {
        D(("User info response data has the wrong size"));
        return PAM_BUF_ERR;
    }
    memcpy(&expire, buf + sizeof(uint32_t), sizeof(uint32_t));
    if (expire >= DAYSEC) {
        expire /= DAYSEC;
        unit = "day(s)";
    } else if (expire >= HOURSEC) {
        expire /= HOURSEC;
        unit = "hour(s)";
    } else if (expire >= MINSEC) {
        expire /= MINSEC;
        unit = "minute(s)";
    }

    ret = snprintf(user_msg, sizeof(user_msg),
                   _("Your password will expire in %1$d %2$s."), expire, unit);
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
        case SSS_PAM_USER_INFO_ACCOUNT_EXPIRED:
            ret = user_info_account_expired(pamh, buflen, buf);
            break;
        default:
            D(("Unknown user info type [%d]", type));
            ret = PAM_SYSTEM_ERR;
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

                free(pi->cert_user);
                pi->cert_user = strdup((char *) &buf[p]);
                if (pi->cert_user == NULL) {
                    D(("strdup failed"));
                    break;
                }

                if (type == SSS_PAM_CERT_INFO && *pi->cert_user == '\0') {
                    D(("Invalid CERT message"));
                    break;
                }

                if (type == SSS_PAM_CERT_INFO_WITH_HINT) {
                    pi->user_name_hint = true;
                } else {
                    pi->user_name_hint = false;
                }

                if ((pi->pam_user == NULL || *(pi->pam_user) == '\0')
                        && *pi->cert_user != '\0') {
                    ret = pam_set_item(pamh, PAM_USER, pi->cert_user);
                    if (ret != PAM_SUCCESS) {
                        D(("Failed to set PAM_USER during "
                           "Smartcard authentication [%s]",
                           pam_strerror(pamh, ret)));
                        break;
                    }

                    ret = pam_get_item(pamh, PAM_USER,
                                       (const void **)&(pi->pam_user));
                    if (ret != PAM_SUCCESS) {
                        D(("Failed to get PAM_USER during "
                           "Smartcard authentication [%s]",
                           pam_strerror(pamh, ret)));
                        break;
                    }

                    pi->pam_user_size = strlen(pi->pam_user) + 1;
                }

                offset = strlen(pi->cert_user) + 1;
                if (offset >= len) {
                    D(("Cert message size mismatch"));
                    free(pi->cert_user);
                    pi->cert_user = NULL;
                    break;
                }
                free(pi->token_name);
                pi->token_name = strdup((char *) &buf[p + offset]);
                if (pi->token_name == NULL) {
                    D(("strdup failed"));
                    free(pi->cert_user);
                    pi->cert_user = NULL;
                    break;
                }

                offset += strlen(pi->token_name) + 1;
                if (offset >= len) {
                    D(("Cert message size mismatch"));
                    free(pi->cert_user);
                    pi->cert_user = NULL;
                    free(pi->token_name);
                    pi->token_name = NULL;
                    break;
                }
                free(pi->module_name);
                pi->module_name = strdup((char *) &buf[p + offset]);
                if (pi->module_name == NULL) {
                    D(("strdup failed"));
                    break;
                }

                offset += strlen(pi->module_name) + 1;
                if (offset >= len) {
                    D(("Cert message size mismatch"));
                    free(pi->cert_user);
                    pi->cert_user = NULL;
                    free(pi->token_name);
                    pi->token_name = NULL;
                    free(pi->module_name);
                    pi->module_name = NULL;
                    break;
                }
                free(pi->key_id);
                pi->key_id = strdup((char *) &buf[p + offset]);
                if (pi->key_id == NULL) {
                    D(("strdup failed"));
                    break;
                }
                D(("cert user: [%s] token name: [%s] module: [%s] key id: [%s]",
                    pi->cert_user, pi->token_name, pi->module_name,
                    pi->key_id));
                break;
            case SSS_PASSWORD_PROMPTING:
                D(("Password prompting available."));
                pi->password_prompting = true;
                break;
            default:
                D(("Unknown response type [%d]", type));
        }
        p += len;

        --c;
    }

    return PAM_SUCCESS;
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
    if (ret == PAM_PERM_DENIED && (flags & FLAGS_ALLOW_MISSING_NAME)) {
        pi->pam_user = "";
        ret = PAM_SUCCESS;
    }
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pam_user == NULL) {
        if (flags & FLAGS_ALLOW_MISSING_NAME) {
            pi->pam_user = "";
        } else {
            D(("No user found, aborting."));
            return PAM_BAD_ITEM;
        }
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

    pi->cert_user = NULL;
    pi->token_name = NULL;
    pi->module_name = NULL;
    pi->key_id = NULL;

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
    D(("Requested domains: %s", pi->requested_domains));
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
        if (errnop != 0) {
            logger(pamh, LOG_ERR, "Request to sssd failed. %s", ssscli_err2string(errnop));
        }
        pam_status = PAM_AUTHINFO_UNAVAIL;
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

#define SC_PROMPT_FMT "PIN for %s"

static int prompt_sc_pin(pam_handle_t *pamh, struct pam_items *pi)
{
    int ret;
    char *answer = NULL;
    char *prompt;
    size_t size;
    size_t needed_size;
    const struct pam_conv *conv;
    const struct pam_message *mesg[2] = { NULL, NULL };
    struct pam_message m[2] = { { 0 }, { 0 } };
    struct pam_response *resp = NULL;

    if (pi->token_name == NULL || *pi->token_name == '\0') {
        return EINVAL;
    }

    size = sizeof(SC_PROMPT_FMT) + strlen(pi->token_name);
    prompt = malloc(size);
    if (prompt == NULL) {
        D(("malloc failed."));
        return ENOMEM;
    }

    ret = snprintf(prompt, size, SC_PROMPT_FMT, pi->token_name);
    if (ret < 0 || ret >= size) {
        D(("snprintf failed."));
        free(prompt);
        return EFAULT;
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

    if (answer == NULL) {
        pi->pam_authtok = NULL;
        pi->pam_authtok_type = SSS_AUTHTOK_TYPE_EMPTY;
        pi->pam_authtok_size=0;
    } else {

        ret = sss_auth_pack_sc_blob(answer, 0, pi->token_name, 0,
                                    pi->module_name, 0,
                                    pi->key_id, 0,
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

        ret = sss_auth_pack_sc_blob(answer, 0, pi->token_name, 0,
                                    pi->module_name, 0,
                                    pi->key_id, 0,
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
            *flags |= FLAGS_FORWARD_PASS;
        } else if (strcmp(*argv, "use_first_pass") == 0) {
            *flags |= FLAGS_USE_FIRST_PASS;
        } else if (strcmp(*argv, "use_authtok") == 0) {
            *flags |= FLAGS_USE_AUTHTOK;
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
            *flags |= FLAGS_IGNORE_UNKNOWN_USER;
        } else if (strcmp(*argv, "ignore_authinfo_unavail") == 0) {
            *flags |= FLAGS_IGNORE_AUTHINFO_UNAVAIL;
        } else if (strcmp(*argv, "use_2fa") == 0) {
            *flags |= FLAGS_USE_2FA;
        } else if (strcmp(*argv, "allow_missing_name") == 0) {
            *flags |= FLAGS_ALLOW_MISSING_NAME;
        } else if (strcmp(*argv, "prompt_always") == 0) {
            *flags |= FLAGS_PROMPT_ALWAYS;
        } else {
            logger(pamh, LOG_WARNING, "unknown option: %s", *argv);
        }
    }

    return;
}

static int get_authtok_for_authentication(pam_handle_t *pamh,
                                          struct pam_items *pi,
                                          uint32_t flags)
{
    int ret;

    if ((flags & FLAGS_USE_FIRST_PASS)
            || ( pi->pamstack_authtok != NULL
                    && *(pi->pamstack_authtok) != '\0'
                    && !(flags & FLAGS_PROMPT_ALWAYS))) {
        pi->pam_authtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
        pi->pam_authtok = strdup(pi->pamstack_authtok);
        if (pi->pam_authtok == NULL) {
            D(("option use_first_pass set, but no password found"));
            return PAM_BUF_ERR;
        }
        pi->pam_authtok_size = strlen(pi->pam_authtok);
    } else {
        if (flags & FLAGS_USE_2FA
                || (pi->otp_vendor != NULL && pi->otp_token_id != NULL
                        && pi->otp_challenge != NULL)) {
            if (pi->password_prompting) {
                ret = prompt_2fa(pamh, pi, _("First Factor: "),
                                 _("Second Factor (optional): "));
            } else {
                ret = prompt_2fa(pamh, pi, _("First Factor: "),
                                 _("Second Factor: "));
            }
        } else if (pi->token_name != NULL && *(pi->token_name) != '\0') {
            ret = prompt_sc_pin(pamh, pi);
        } else {
            ret = prompt_password(pamh, pi, _("Password: "));
        }
        if (ret != PAM_SUCCESS) {
            D(("failed to get password from user"));
            return ret;
        }

        if (flags & FLAGS_FORWARD_PASS) {
            if (pi->pam_authtok_type == SSS_AUTHTOK_TYPE_PASSWORD) {
                ret = pam_set_item(pamh, PAM_AUTHTOK, pi->pam_authtok);
            } else if (pi->pam_authtok_type == SSS_AUTHTOK_TYPE_2FA
                           && pi->first_factor != NULL) {
                ret = pam_set_item(pamh, PAM_AUTHTOK, pi->first_factor);
            } else {
                ret = EINVAL;
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

static int get_authtok_for_password_change(pam_handle_t *pamh,
                                           struct pam_items *pi,
                                           uint32_t flags,
                                           int pam_flags)
{
    int ret;
    const int *exp_data = NULL;
    pam_get_data(pamh, PWEXP_FLAG, (const void **) &exp_data);

    /* we query for the old password during PAM_PRELIM_CHECK to make
     * pam_sss work e.g. with pam_cracklib */
    if (pam_flags & PAM_PRELIM_CHECK) {
        if ( (getuid() != 0 || exp_data ) && !(flags & FLAGS_USE_FIRST_PASS)) {
            ret = prompt_password(pamh, pi, _("Current Password: "));
            if (ret != PAM_SUCCESS) {
                D(("failed to get password from user"));
                return ret;
            }

            ret = pam_set_item(pamh, PAM_OLDAUTHTOK, pi->pam_authtok);
            if (ret != PAM_SUCCESS) {
                D(("Failed to set PAM_OLDAUTHTOK [%s], "
                   "oldauthtok may not be available",
                   pam_strerror(pamh,ret)));
                   return ret;
            }
        }

        return PAM_SUCCESS;
    }

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

    if (flags & FLAGS_USE_AUTHTOK) {
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

        if (flags & FLAGS_FORWARD_PASS) {
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

#define SC_ENTER_FMT "Please enter smart card labeled\n %s\nand press enter"

static int check_login_token_name(pam_handle_t *pamh, struct pam_items *pi,
                                  bool quiet_mode)
{
    int ret;
    int pam_status;
    char *login_token_name;
    char *prompt = NULL;
    size_t size;
    char *answer = NULL;

    login_token_name = getenv("PKCS11_LOGIN_TOKEN_NAME");
    if (login_token_name == NULL) {
        return PAM_SUCCESS;
    }

    while (pi->token_name == NULL
            || strcmp(login_token_name, pi->token_name) != 0) {
        size = sizeof(SC_ENTER_FMT) + strlen(login_token_name);
        prompt = malloc(size);
        if (prompt == NULL) {
            D(("malloc failed."));
            return ENOMEM;
        }

        ret = snprintf(prompt, size, SC_ENTER_FMT,
                       login_token_name);
        if (ret < 0 || ret >= size) {
            D(("snprintf failed."));
            free(prompt);
            return EFAULT;
        }

        ret = do_pam_conversation(pamh, PAM_PROMPT_ECHO_OFF, prompt,
                                  NULL, &answer);
        free(prompt);
        if (ret != PAM_SUCCESS) {
            D(("do_pam_conversation failed."));
            return ret;
        } else {
            free(answer);
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

    return PAM_SUCCESS;
}

static int pam_sss(enum sss_cli_command task, pam_handle_t *pamh,
                   int pam_flags, int argc, const char **argv)
{
    int ret;
    int pam_status;
    struct pam_items pi;
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
        if (flags & FLAGS_IGNORE_UNKNOWN_USER && ret == PAM_USER_UNKNOWN) {
            ret = PAM_IGNORE;
        }
        if (flags & FLAGS_IGNORE_AUTHINFO_UNAVAIL
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
                 * - FLAGS_USE_FIRST_PASS is not set
                 * - no password is on the stack or FLAGS_PROMPT_ALWAYS is set
                 * - preauth indicator file exists.
                 */
                if ( !(flags & FLAGS_USE_FIRST_PASS)
                        && (pi.pam_authtok == NULL
                                || (flags & FLAGS_PROMPT_ALWAYS))
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

                if (strcmp(pi.pam_service, "gdm-smartcard") == 0) {
                    ret = check_login_token_name(pamh, &pi, quiet_mode);
                    if (ret != PAM_SUCCESS) {
                        D(("check_login_token_name failed.\n"));
                        return ret;
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
                ret = get_authtok_for_password_change(pamh, &pi, flags, pam_flags);
                if (ret != PAM_SUCCESS) {
                    D(("failed to get tokens for password change: %s",
                       pam_strerror(pamh, ret)));
                    overwrite_and_free_pam_items(&pi);
                    return ret;
                }
                if (pam_flags & PAM_PRELIM_CHECK) {
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

        if (flags & FLAGS_IGNORE_UNKNOWN_USER
                && pam_status == PAM_USER_UNKNOWN) {
            pam_status = PAM_IGNORE;
        }
        if (flags & FLAGS_IGNORE_AUTHINFO_UNAVAIL
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

            flags &= ~FLAGS_USE_FIRST_PASS;
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
