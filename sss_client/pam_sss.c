/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include "sss_pam_macros.h"

#include "sss_cli.h"

#include <libintl.h>
#define _(STRING) dgettext (PACKAGE, STRING)
#include "config.h"

#define FLAGS_USE_FIRST_PASS (1 << 0)
#define FLAGS_FORWARD_PASS   (1 << 1)
#define FLAGS_USE_AUTHTOK    (1 << 2)

struct pam_items {
    const char* pam_service;
    const char* pam_user;
    const char* pam_tty;
    const char* pam_ruser;
    const char* pam_rhost;
    char* pam_authtok;
    char* pam_newauthtok;
    const char* pamstack_authtok;
    const char* pamstack_oldauthtok;
    size_t pam_service_size;
    size_t pam_user_size;
    size_t pam_tty_size;
    size_t pam_ruser_size;
    size_t pam_rhost_size;
    int pam_authtok_type;
    size_t pam_authtok_size;
    int pam_newauthtok_type;
    size_t pam_newauthtok_size;
    pid_t cli_pid;
    const char *login_name;
};

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


static size_t add_authtok_item(enum pam_item_type type,
                               enum sss_authtok_type authtok_type,
                               const char *tok, const size_t size,
                               uint8_t *buf) {
    size_t rp=0;
    uint32_t c;

    if (tok == NULL) return 0;

    c = type;
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    c = size + sizeof(uint32_t);
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    c = authtok_type;
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    memcpy(&buf[rp], tok, size);
    rp += size;

    return rp;
}


static size_t add_uint32_t_item(enum pam_item_type type, const uint32_t val,
                                uint8_t *buf) {
    size_t rp=0;
    uint32_t c;

    c = type;
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    c = sizeof(uint32_t);
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    c = val;
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    return rp;
}

static size_t add_string_item(enum pam_item_type type, const char *str,
                           const size_t size, uint8_t *buf) {
    size_t rp=0;
    uint32_t c;

    if (str == NULL || *str == '\0') return 0;

    c = type;
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    c = size;
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    memcpy(&buf[rp], str, size);
    rp += size;

    return rp;
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
}

static int pack_message_v3(struct pam_items *pi, size_t *size,
                           uint8_t **buffer) {
    int len;
    uint8_t *buf;
    int rp;
    uint32_t terminator = END_OF_PAM_REQUEST;

    len = sizeof(uint32_t) +
          2*sizeof(uint32_t) + pi->pam_user_size +
          sizeof(uint32_t);
    len += *pi->pam_service != '\0' ?
                2*sizeof(uint32_t) + pi->pam_service_size : 0;
    len += *pi->pam_tty != '\0' ?
                2*sizeof(uint32_t) + pi->pam_tty_size : 0;
    len += *pi->pam_ruser != '\0' ?
                2*sizeof(uint32_t) + pi->pam_ruser_size : 0;
    len += *pi->pam_rhost != '\0' ?
                2*sizeof(uint32_t) + pi->pam_rhost_size : 0;
    len += pi->pam_authtok != NULL ?
                3*sizeof(uint32_t) + pi->pam_authtok_size : 0;
    len += pi->pam_newauthtok != NULL ?
                3*sizeof(uint32_t) + pi->pam_newauthtok_size : 0;
    len += 3*sizeof(uint32_t); /* cli_pid */

    buf = malloc(len);
    if (buf == NULL) {
        D(("malloc failed."));
        return PAM_BUF_ERR;
    }

    rp = 0;
    ((uint32_t *)(&buf[rp]))[0] = START_OF_PAM_REQUEST;
    rp += sizeof(uint32_t);

    rp += add_string_item(PAM_ITEM_USER, pi->pam_user, pi->pam_user_size,
                          &buf[rp]);

    rp += add_string_item(PAM_ITEM_SERVICE, pi->pam_service,
                          pi->pam_service_size, &buf[rp]);

    rp += add_string_item(PAM_ITEM_TTY, pi->pam_tty, pi->pam_tty_size,
                          &buf[rp]);

    rp += add_string_item(PAM_ITEM_RUSER, pi->pam_ruser, pi->pam_ruser_size,
                          &buf[rp]);

    rp += add_string_item(PAM_ITEM_RHOST, pi->pam_rhost, pi->pam_rhost_size,
                          &buf[rp]);

    rp += add_uint32_t_item(PAM_ITEM_CLI_PID, (uint32_t) pi->cli_pid, &buf[rp]);

    rp += add_authtok_item(PAM_ITEM_AUTHTOK, pi->pam_authtok_type,
                           pi->pam_authtok, pi->pam_authtok_size, &buf[rp]);

    rp += add_authtok_item(PAM_ITEM_NEWAUTHTOK, pi->pam_newauthtok_type,
                           pi->pam_newauthtok, pi->pam_newauthtok_size,
                           &buf[rp]);

    memcpy(&buf[rp], &terminator, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    if (rp != len) {
        D(("error during packet creation."));
        return PAM_BUF_ERR;
    }

    *size = len;
    *buffer = buf;

    return 0;
}

static int null_strcmp(const char *s1, const char *s2) {
    if (s1 == NULL && s2 == NULL) return 0;
    if (s1 == NULL && s2 != NULL) return -1;
    if (s1 != NULL && s2 == NULL) return 1;
    return strcmp(s1, s2);
}

enum {
    PAM_CONV_DONE = 0,
    PAM_CONV_STD,
    PAM_CONV_REENTER,
};

static int do_pam_conversation(pam_handle_t *pamh, const int msg_style,
                               const char *msg,
                               const char *reenter_msg,
                               char **answer)
{
    int ret;
    int state = PAM_CONV_STD;
    struct pam_conv *conv;
    struct pam_message *mesg[1];
    struct pam_response *resp=NULL;

    if ((msg_style == PAM_TEXT_INFO || msg_style == PAM_ERROR_MSG) &&
        msg == NULL) return PAM_SYSTEM_ERR;

    if ((msg_style == PAM_PROMPT_ECHO_OFF ||
         msg_style == PAM_PROMPT_ECHO_ON) &&
        (msg == NULL || answer == NULL)) return PAM_SYSTEM_ERR;

    ret=pam_get_item(pamh, PAM_CONV, (const void **) &conv);
    if (ret != PAM_SUCCESS) return ret;

    do {
        mesg[0] = malloc(sizeof(struct pam_message));
        if (mesg[0] == NULL) {
            D(("Malloc failed."));
            return PAM_SYSTEM_ERR;
        }

        mesg[0]->msg_style = msg_style;
        if (state == PAM_CONV_REENTER) {
            mesg[0]->msg = reenter_msg;
        } else {
            mesg[0]->msg = msg;
        }

        ret=conv->conv(1, (const struct pam_message **) mesg, &resp,
                       conv->appdata_ptr);
        free(mesg[0]);
        if (ret != PAM_SUCCESS) {
            D(("Conversation failure: %s.",  pam_strerror(pamh,ret)));
            return ret;
        }

        if (msg_style == PAM_PROMPT_ECHO_OFF ||
            msg_style == PAM_PROMPT_ECHO_ON) {
            if (resp == NULL) {
                D(("response expected, but resp==NULL"));
                return PAM_SYSTEM_ERR;
            }

            if (state == PAM_CONV_REENTER) {
                if (null_strcmp(*answer, resp[0].resp) != 0) {
                    logger(pamh, LOG_NOTICE, "Passwords do not match.");
                    _pam_overwrite((void *)resp[0].resp);
                    free(resp[0].resp);
                    if (*answer != NULL) {
                        _pam_overwrite((void *)*answer);
                        free(*answer);
                        *answer = NULL;
                    }
                    ret = do_pam_conversation(pamh, PAM_ERROR_MSG,
                                              _("Passwords do not match"),
                                              NULL, NULL);
                    if (ret != PAM_SUCCESS) {
                        D(("do_pam_conversation failed."));
                        return PAM_SYSTEM_ERR;
                    }
                    return PAM_CRED_ERR;
                }
                _pam_overwrite((void *)resp[0].resp);
                free(resp[0].resp);
            } else {
                if (resp[0].resp == NULL) {
                    D(("Empty password"));
                    *answer = NULL;
                } else {
                    *answer = strndup(resp[0].resp, MAX_AUTHTOK_SIZE);
                    _pam_overwrite((void *)resp[0].resp);
                    free(resp[0].resp);
                    if(*answer == NULL) {
                        D(("strndup failed"));
                        return PAM_BUF_ERR;
                    }
                }
            }
            free(resp);
            resp = NULL;
        }

        if (reenter_msg != NULL && state == PAM_CONV_STD) {
            state = PAM_CONV_REENTER;
        } else {
            state = PAM_CONV_DONE;
        }
    } while (state != PAM_CONV_DONE);

    return PAM_SUCCESS;
}

static int eval_response(pam_handle_t *pamh, size_t buflen, uint8_t *buf)
{
    int ret;
    size_t p=0;
    char *env_item;
    int32_t c;
    int32_t type;
    int32_t len;
    int32_t pam_status;

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
            case PAM_USER_INFO:
                if (buf[p + (len -1)] != '\0') {
                    D(("user info does not end with \\0."));
                    break;
                }
                logger(pamh, LOG_INFO, "user info: [%s]", &buf[p]);
                break;
            case PAM_DOMAIN_NAME:
                D(("domain name: [%s]", &buf[p]));
                break;
            case ENV_ITEM:
            case PAM_ENV_ITEM:
            case ALL_ENV_ITEM:
                if (buf[p + (len -1)] != '\0') {
                    D(("env item does not end with \\0."));
                    break;
                }

                D(("env item: [%s]", &buf[p]));
                if (type == PAM_ENV_ITEM || type == ALL_ENV_ITEM) {
                    ret = pam_putenv(pamh, (char *)&buf[p]);
                    if (ret != PAM_SUCCESS) {
                        D(("pam_putenv failed."));
                        break;
                    }
                }

                if (type == ENV_ITEM || type == ALL_ENV_ITEM) {
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
        }
        p += len;

        --c;
    }

    return PAM_SUCCESS;
}

static int get_pam_items(pam_handle_t *pamh, struct pam_items *pi)
{
    int ret;

    pi->pam_authtok_type = SSS_AUTHTOK_TYPE_EMPTY;
    pi->pam_authtok = NULL;
    pi->pam_authtok_size = 0;
    pi->pam_newauthtok_type = SSS_AUTHTOK_TYPE_EMPTY;
    pi->pam_newauthtok = NULL;
    pi->pam_newauthtok_size = 0;

    ret = pam_get_item(pamh, PAM_SERVICE, (const void **) &(pi->pam_service));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pam_service == NULL) pi->pam_service="";
    pi->pam_service_size=strlen(pi->pam_service)+1;

    ret = pam_get_item(pamh, PAM_USER, (const void **) &(pi->pam_user));
    if (ret != PAM_SUCCESS) return ret;
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
}

static int send_and_receive(pam_handle_t *pamh, struct pam_items *pi,
                            enum sss_cli_command task)
{
    int ret;
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

    ret = sss_pam_make_request(task, &rd, &repbuf, &replen, &errnop);

    if (ret != NSS_STATUS_SUCCESS) {
        logger(pamh, LOG_ERR, "Request to sssd failed.");
        pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

/* FIXME: add an end signature */
    if (replen < (2*sizeof(int32_t))) {
        D(("response not in expected format."));
        pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    pam_status = ((int32_t *)repbuf)[0];
    ret = eval_response(pamh, replen, repbuf);
    if (ret != PAM_SUCCESS) {
        D(("eval_response failed."));
        pam_status = ret;
        goto done;
    }
    logger(pamh, (pam_status == PAM_SUCCESS ? LOG_INFO : LOG_NOTICE),
           "authentication %s; logname=%s uid=%d euid=%d tty=%s ruser=%s "
           "rhost=%s user=%s",
           pam_status == PAM_SUCCESS ? "success" : "failure",
           pi->login_name, getuid(), geteuid(), pi->pam_tty, pi->pam_ruser,
           pi->pam_rhost, pi->pam_user);
    if (pam_status != PAM_SUCCESS) {
           logger(pamh, LOG_NOTICE, "received for user %s: %d (%s)",
                  pi->pam_user, pam_status, pam_strerror(pamh,pam_status));
    }

done:
    if (buf != NULL ) {
        _pam_overwrite_n((void *)buf, rd.len);
        free(buf);
    }
    free(repbuf);

    return pam_status;
}

static int prompt_password(pam_handle_t *pamh, struct pam_items *pi)
{
    int ret;
    char *answer = NULL;

    ret = do_pam_conversation(pamh, PAM_PROMPT_ECHO_OFF, _("Password: "),
                              NULL, &answer);
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
                      uint32_t *flags)
{
    for (; argc-- > 0; ++argv) {
        if (strcmp(*argv, "forward_pass") == 0) {
            *flags |= FLAGS_FORWARD_PASS;
        } else if (strcmp(*argv, "use_first_pass") == 0) {
            *flags |= FLAGS_USE_FIRST_PASS;
        } else if (strcmp(*argv, "use_authtok") == 0) {
            *flags |= FLAGS_USE_AUTHTOK;
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

    if (flags & FLAGS_USE_FIRST_PASS) {
        pi->pam_authtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
        pi->pam_authtok = strdup(pi->pamstack_authtok);
        if (pi->pam_authtok == NULL) {
            D(("option use_first_pass set, but no password found"));
            return PAM_BUF_ERR;
        }
        pi->pam_authtok_size = strlen(pi->pam_authtok);
    } else {
        ret = prompt_password(pamh, pi);
        if (ret != PAM_SUCCESS) {
            D(("failed to get password from user"));
            return ret;
        }

        if (flags & FLAGS_FORWARD_PASS) {
            ret = pam_set_item(pamh, PAM_AUTHTOK, pi->pam_authtok);
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

    /* we query for the old password during PAM_PRELIM_CHECK to make
     * pam_sss work e.g. with pam_cracklib */
    if (pam_flags & PAM_PRELIM_CHECK) {
        if (getuid() != 0 && !(flags & FLAGS_USE_FIRST_PASS)) {
            ret = prompt_password(pamh, pi);
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

static int pam_sss(enum sss_cli_command task, pam_handle_t *pamh,
                   int pam_flags, int argc, const char **argv)
{
    int ret;
    struct pam_items pi;
    uint32_t flags = 0;

    bindtextdomain(PACKAGE, LOCALEDIR);

    D(("Hello pam_sssd: %d", task));

    eval_argv(pamh, argc, argv, &flags);

    ret = get_pam_items(pamh, &pi);
    if (ret != PAM_SUCCESS) {
        D(("get items returned error: %s", pam_strerror(pamh,ret)));
        return ret;
    }


    switch(task) {
        case SSS_PAM_AUTHENTICATE:
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
            D(("Illegal task [%d]", task));
            return PAM_SYSTEM_ERR;
    }

    ret = send_and_receive(pamh, &pi, task);

    if (ret == PAM_AUTHTOK_EXPIRED && task == SSS_PAM_AUTHENTICATE) {
        D(("Authtoken expired, trying to change it"));
        ret = do_pam_conversation(pamh, PAM_ERROR_MSG,
                                  _("Password has expired."), NULL, NULL);
        if (ret != PAM_SUCCESS) {
            D(("do_pam_conversation failed."));
            return PAM_SYSTEM_ERR;
        }

        pi.pamstack_oldauthtok = pi.pam_authtok;
        ret = get_authtok_for_password_change(pamh, &pi, flags, pam_flags);
        if (ret != PAM_SUCCESS) {
            D(("failed to get tokens for password change: %s",
               pam_strerror(pamh, ret)));
            return ret;
        }

        ret = send_and_receive(pamh, &pi, SSS_PAM_CHAUTHTOK);
    }

    overwrite_and_free_authtoks(&pi);

    return ret;
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
