
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
#include <security/pam_misc.h>
#include <security/pam_ext.h>

#include "sss_cli.h"

#define FLAGS_USE_FIRST_PASS (1 << 0)
#define FLAGS_FORWARD_PASS   (1 << 1)
#define FLAGS_USE_AUTHTOK    (1 << 2)

struct pam_items {
    const char* pam_service;
    const char* pam_user;
    const char* pam_tty;
    const char* pam_ruser;
    const char* pam_rhost;
    const char* pam_authtok;
    const char* pam_newauthtok;
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
};

#define DEBUG_MGS_LEN 1024

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

static int pack_message(struct pam_items *pi, size_t *size, uint8_t **buffer) {
    int len;
    uint8_t *buf;
    int rp;

    len = pi->pam_user_size +
          pi->pam_service_size +
          pi->pam_tty_size +
          pi->pam_ruser_size +
          pi->pam_rhost_size +
          2*sizeof(uint32_t) + pi->pam_authtok_size +
          2*sizeof(uint32_t) + pi->pam_newauthtok_size +
          sizeof(uint32_t);

    buf = malloc(len);
    if (buf == NULL) {
        D(("malloc failed."));
        return PAM_BUF_ERR;
    }

    memcpy(buf, pi->pam_user, pi->pam_user_size);
    rp = pi->pam_user_size;

    memcpy(&buf[rp],  pi->pam_service, pi->pam_service_size);
    rp += pi->pam_service_size;

    memcpy(&buf[rp],  pi->pam_tty, pi->pam_tty_size);
    rp += pi->pam_tty_size;

    memcpy(&buf[rp],  pi->pam_ruser, pi->pam_ruser_size);
    rp += pi->pam_ruser_size;

    memcpy(&buf[rp],  pi->pam_rhost, pi->pam_rhost_size);
    rp += pi->pam_rhost_size;

    ((uint32_t *)(&buf[rp]))[0] = pi->pam_authtok_type;
    rp += sizeof(uint32_t);
    ((uint32_t *)(&buf[rp]))[0] = pi->pam_authtok_size;
    rp += sizeof(uint32_t);
    memcpy(&buf[rp],  pi->pam_authtok, pi->pam_authtok_size);
    rp += pi->pam_authtok_size;
    _pam_overwrite((void *)pi->pam_authtok);
    free((void *)pi->pam_authtok);
    pi->pam_authtok = NULL;

    ((uint32_t *)(&buf[rp]))[0] = pi->pam_newauthtok_type;
    rp += sizeof(uint32_t);
    ((uint32_t *)(&buf[rp]))[0] = pi->pam_newauthtok_size;
    rp += sizeof(uint32_t);
    memcpy(&buf[rp],  pi->pam_newauthtok, pi->pam_newauthtok_size);
    rp += pi->pam_newauthtok_size;
    _pam_overwrite((void *)pi->pam_newauthtok);
    free((void *)pi->pam_newauthtok);
    pi->pam_newauthtok = NULL;

    ((uint32_t *)(&buf[rp]))[0] = END_OF_PAM_REQUEST;
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

    if ((msg_style == PAM_PROMPT_ECHO_OFF || msg_style == PAM_PROMPT_ECHO_ON) &&
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

        if (msg_style == PAM_PROMPT_ECHO_OFF || msg_style == PAM_PROMPT_ECHO_ON) {
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
                                              "Passwords do not match", NULL,
                                              NULL);
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
                    *answer = strdup(resp[0].resp);
                    _pam_overwrite((void *)resp[0].resp);
                    free(resp[0].resp);
                    if(*answer == NULL) {
                        D(("strdup failed"));
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
    int32_t *c;
    int32_t *type;
    int32_t *len;
    int32_t *pam_status;

    if (buflen < (2*sizeof(int32_t))) {
        D(("response buffer is too small"));
        return PAM_BUF_ERR;
    }

    pam_status = ((int32_t *)(buf+p));
    p += sizeof(int32_t);


    c = ((int32_t *)(buf+p));
    p += sizeof(int32_t);

    while(*c>0) {
        if (buflen < (p+2*sizeof(int32_t))) {
            D(("response buffer is too small"));
            return PAM_BUF_ERR;
        }

        type = ((int32_t *)(buf+p));
        p += sizeof(int32_t);

        len = ((int32_t *)(buf+p));
        p += sizeof(int32_t);

        if (buflen < (p + *len)) {
            D(("response buffer is too small"));
            return PAM_BUF_ERR;
        }

        switch(*type) {
            case PAM_USER_INFO:
                if (buf[p + (*len -1)] != '\0') {
                    D(("user info does not end with \\0."));
                    break;
                }
                logger(pamh, LOG_INFO, "user info: [%s]", &buf[p]);
                ret = do_pam_conversation(pamh, PAM_USER_INFO, (char *) &buf[p],
                                          NULL, NULL);
                if (ret != PAM_SUCCESS) {
                    D(("do_pam_conversation, canot display user info."));
                }
                break;
            case PAM_DOMAIN_NAME:
                D(("domain name: [%s]", &buf[p]));
                break;
            case ENV_ITEM:
            case PAM_ENV_ITEM:
            case ALL_ENV_ITEM:
                if (buf[p + (*len -1)] != '\0') {
                    D(("env item does not end with \\0."));
                    break;
                }

                D(("env item: [%s]", &buf[p]));
                if (*type == PAM_ENV_ITEM || *type == ALL_ENV_ITEM) {
                    ret = pam_putenv(pamh, (char *)&buf[p]);
                    if (ret != PAM_SUCCESS) {
                        D(("pam_putenv failed."));
                        break;
                    }
                }

                if (*type == ENV_ITEM || *type == ALL_ENV_ITEM) {
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
        p += *len;

        --(*c);
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
    if (pi->pam_user == NULL) pi->pam_user="";
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

    ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &(pi->pamstack_authtok));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pamstack_authtok == NULL) pi->pamstack_authtok="";

    ret = pam_get_item(pamh, PAM_OLDAUTHTOK, (const void **) &(pi->pamstack_oldauthtok));
    if (ret != PAM_SUCCESS) return ret;
    if (pi->pamstack_oldauthtok == NULL) pi->pamstack_oldauthtok="";

    return PAM_SUCCESS;
}

static void print_pam_items(struct pam_items pi)
{
    D(("Service: %s", *pi.pam_service!='\0' ? pi.pam_service : "(not available)"));
    D(("User: %s", *pi.pam_user!='\0' ? pi.pam_user : "(not available)"));
    D(("Tty: %s", *pi.pam_tty!='\0' ? pi.pam_tty : "(not available)"));
    D(("Ruser: %s", *pi.pam_ruser!='\0' ? pi.pam_ruser : "(not available)"));
    D(("Rhost: %s", *pi.pam_rhost!='\0' ? pi.pam_rhost : "(not available)"));
    D(("Pamstack_Authtok: %s", *pi.pamstack_authtok!='\0' ? pi.pamstack_authtok : "(not available)"));
    D(("Pamstack_Oldauthtok: %s", *pi.pamstack_oldauthtok!='\0' ? pi.pamstack_oldauthtok : "(not available)"));
    if (pi.pam_authtok != NULL) {
        D(("Authtok: %s", *pi.pam_authtok!='\0' ? pi.pam_authtok : "(not available)"));
    }
    if (pi.pam_newauthtok != NULL) {
        D(("Newauthtok: %s", *pi.pam_newauthtok!='\0' ? pi.pam_newauthtok : "(not available)"));
    }
}

static int pam_sss(int task, pam_handle_t *pamh, int pam_flags, int argc,
                   const char **argv)
{
    int ret;
    int errnop;
    struct pam_items pi;
    struct sss_cli_req_data rd;
    uint8_t *buf=NULL;
    uint8_t *repbuf=NULL;
    size_t replen;
    int pam_status;
    uint32_t flags = 0;
    char *answer;

    D(("Hello pam_sssd: %d", task));

    for (; argc-- > 0; ++argv) {
        if (strcmp(*argv, "forward_pass") == 0) {
            flags |= FLAGS_FORWARD_PASS;
        } else if (strcmp(*argv, "use_first_pass") == 0) {
            flags |= FLAGS_USE_FIRST_PASS;
        } else if (strcmp(*argv, "use_authtok") == 0) {
            flags |= FLAGS_USE_AUTHTOK;
        } else {
            logger(pamh, LOG_WARNING, "unknown option: %s", *argv);
        }
    }

/* TODO: add useful prelim check */
    if (task == SSS_PAM_CHAUTHTOK && (pam_flags & PAM_PRELIM_CHECK)) {
        D(("ignoring PAM_PRELIM_CHECK"));
        return PAM_SUCCESS;
    }

    ret = get_pam_items(pamh, &pi);
    if (ret != PAM_SUCCESS) {
        D(("get items returned error: %s", pam_strerror(pamh,ret)));
        return ret;
    }

    if (*pi.pam_user == '\0') {
        D(("No user found, aborting."));
        return PAM_BAD_ITEM;
    }

    if (strcmp(pi.pam_user, "root") == 0) {
        D(("pam_sss will not handle root."));
        return PAM_USER_UNKNOWN;
    }

    if (task == SSS_PAM_AUTHENTICATE ||
        (task == SSS_PAM_CHAUTHTOK && getuid() != 0)) {
        if (flags & FLAGS_USE_FIRST_PASS) {
            pi.pam_authtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
            if (task == SSS_PAM_AUTHENTICATE) {
                pi.pam_authtok = strdup(pi.pamstack_authtok);
            } else if (task == SSS_PAM_CHAUTHTOK) {
                pi.pam_authtok = strdup(pi.pamstack_oldauthtok);
            } else {
                D(("internal logic error"));
                return PAM_SYSTEM_ERR;
            }
            if (pi.pam_authtok == NULL) {
                pam_status = PAM_BUF_ERR;
                goto done;
            }
            pi.pam_authtok_size = strlen(pi.pam_authtok);
        } else {
            ret = do_pam_conversation(pamh, PAM_PROMPT_ECHO_OFF, "Password: ",
                                      NULL, &answer);
            if (ret != PAM_SUCCESS) {
                D(("do_pam_conversation failed."));
                pam_status = ret;
                goto done;
            }

            if (answer == NULL) {
                pi.pam_authtok = NULL;
                pi.pam_authtok_type = SSS_AUTHTOK_TYPE_EMPTY;
                pi.pam_authtok_size=0;
            } else {
                pi.pam_authtok = strdup(answer);
                _pam_overwrite((void *)answer);
                free(answer);
                answer=NULL;
                if (pi.pam_authtok == NULL) {
                    pam_status = PAM_BUF_ERR;
                    goto done;
                }
                pi.pam_authtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
                pi.pam_authtok_size=strlen(pi.pam_authtok);
            }

            if (flags & FLAGS_FORWARD_PASS) {
                if (task == SSS_PAM_AUTHENTICATE) {
                    ret = pam_set_item(pamh, PAM_AUTHTOK, pi.pam_authtok);
                } else if (task == SSS_PAM_CHAUTHTOK) {
                    ret = pam_set_item(pamh, PAM_OLDAUTHTOK, pi.pam_authtok);
                } else {
                    D(("internal logic error"));
                    return PAM_SYSTEM_ERR;
                }
                if (ret != PAM_SUCCESS) {
                    D(("Failed to set PAM_AUTHTOK, authtok may not be available for other modules"));
                }
            }
        }
     }

     if (task == SSS_PAM_CHAUTHTOK) {
        if (flags & FLAGS_USE_AUTHTOK) {
            pi.pam_newauthtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
            pi.pam_newauthtok =  strdup(pi.pamstack_authtok);
            if (pi.pam_newauthtok == NULL) {
                pam_status = PAM_BUF_ERR;
                goto done;
            }
            pi.pam_newauthtok_size = strlen(pi.pam_newauthtok);
        } else {
            ret = do_pam_conversation(pamh, PAM_PROMPT_ECHO_OFF,
                                      "New Password: ",
                                      "Reenter new Password: ",
                                      &answer);
            if (ret != PAM_SUCCESS) {
                D(("do_pam_conversation failed."));
                pam_status = ret;
                goto done;
            }
            if (answer == NULL) {
                pi.pam_newauthtok = NULL;
                pi.pam_newauthtok_type = SSS_AUTHTOK_TYPE_EMPTY;
                pi.pam_newauthtok_size=0;
            } else {
                pi.pam_newauthtok = strdup(answer);
                _pam_overwrite((void *)answer);
                free(answer);
                answer=NULL;
                if (pi.pam_newauthtok == NULL) {
                    pam_status = PAM_BUF_ERR;
                    goto done;
                }
                pi.pam_newauthtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
                pi.pam_newauthtok_size=strlen(pi.pam_authtok);
            }

            if (flags & FLAGS_FORWARD_PASS) {
                ret = pam_set_item(pamh, PAM_AUTHTOK, pi.pam_newauthtok);
                if (ret != PAM_SUCCESS) {
                    D(("Failed to set PAM_AUTHTOK, authtok may not be available for other modules"));
                }
            }
        }
    }

    print_pam_items(pi);

    ret = pack_message(&pi, &rd.len, &buf);
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
           "received for user %s: %d (%s)", pi.pam_user, pam_status,
           pam_strerror(pamh,pam_status));

done:
    if (buf != NULL ) {
        _pam_overwrite_n((void *)buf, rd.len);
        free(buf);
    }
    if (repbuf != NULL) free(repbuf);

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
