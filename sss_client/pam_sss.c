
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <security/pam_modules.h>
#include <security/pam_misc.h>

#include "sss_cli.h" 

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
    int pam_service_size;
    int pam_user_size;
    int pam_tty_size;
    int pam_ruser_size;
    int pam_rhost_size;
    int pam_authtok_type;
    int pam_authtok_size;
    int pam_newauthtok_type;
    int pam_newauthtok_size;
};


static int get_pam_items(pam_handle_t *pamh, struct pam_items *pi) {
    int ret;

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

static void print_pam_items(struct pam_items pi) {
    D(("Service: %s", *pi.pam_service!='\0' ? pi.pam_service : "(not available)"));
    D(("User: %s", *pi.pam_user!='\0' ? pi.pam_user : "(not available)"));
    D(("Tty: %s", *pi.pam_tty!='\0' ? pi.pam_tty : "(not available)"));
    D(("Ruser: %s", *pi.pam_ruser!='\0' ? pi.pam_ruser : "(not available)"));
    D(("Rhost: %s", *pi.pam_rhost!='\0' ? pi.pam_rhost : "(not available)"));
    D(("Authtok: %s", *pi.pamstack_authtok!='\0' ? pi.pamstack_authtok : "(not available)"));
    D(("Oldauthtok: %s", *pi.pamstack_oldauthtok!='\0' ? pi.pamstack_oldauthtok : "(not available)"));
}

static int pam_sss(int task, pam_handle_t *pamh, int flags, int argc,
                   const char **argv) {
    int ret;
    int errnop;
    struct pam_items pi;
    struct sss_cli_req_data rd;
    uint8_t *repbuf=NULL;
    size_t replen;
    size_t rp;
    char *buf=NULL;
    struct pam_conv *conv;
    struct pam_message *mesg[1];
    struct pam_response *resp=NULL;
    int pam_status;
    char *domain;

    D(("Hello pam_sssd: %d", task));

    ret = get_pam_items(pamh, &pi);
    if (ret != PAM_SUCCESS) {
        D(("get items returned error: %s", pam_strerror(pamh,ret)));
        return ret;
    }

    pi.pam_authtok_type = SSS_AUTHTOK_TYPE_EMPTY;
    pi.pam_authtok = NULL;
    pi.pam_authtok_size = 0;
    pi.pam_newauthtok_type = SSS_AUTHTOK_TYPE_EMPTY;
    pi.pam_newauthtok = NULL;
    pi.pam_newauthtok_size = 0;
/* according to pam_conv(3) only one message should be requested by conv to
 * keep compatibility to Solaris. Therefore we make separate calls to request
 * AUTHTOK and OLDAUTHTOK. */
    if (task == SSS_PAM_AUTHENTICATE || task == SSS_PAM_CHAUTHTOK) {
        ret=pam_get_item(pamh, PAM_CONV, (const void **) &conv);
        if (ret != PAM_SUCCESS) return ret;

        mesg[0] = malloc(sizeof(struct pam_message));
        if (mesg[0] == NULL) {
            D(("Malloc failed.\n"));
            return PAM_SYSTEM_ERR;
        }
        mesg[0]->msg_style = PAM_PROMPT_ECHO_OFF;
        mesg[0]->msg = strdup("Password: ");

        ret=conv->conv(1, (const struct pam_message **) mesg, &resp,
                       conv->appdata_ptr);
        free((void *)mesg[0]->msg);
        free(mesg[0]);
        if (ret != PAM_SUCCESS) {
            D(("Conversation failure: %s.\n",  pam_strerror(pamh,ret)));
            pam_status = ret;
            goto done;
        }

        if (resp[0].resp == NULL) {
            D(("Empty password\n"));
            pi.pam_authtok = NULL;
            pi.pam_authtok_type = SSS_AUTHTOK_TYPE_EMPTY;
        } else {
            pi.pam_authtok = strdup(resp[0].resp);
            pi.pam_authtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
        }
        pi.pam_authtok_size=strlen(pi.pam_authtok);
    }

    if (task == SSS_PAM_CHAUTHTOK) {
        ret=pam_get_item(pamh, PAM_CONV, (const void **) &conv);
        if (ret != PAM_SUCCESS) return ret;

        mesg[0] = malloc(sizeof(struct pam_message));
        if (mesg[0] == NULL) {
            D(("Malloc failed.\n"));
            return PAM_SYSTEM_ERR;
        }
        mesg[0]->msg_style = PAM_PROMPT_ECHO_OFF;
        mesg[0]->msg = strdup("New Password: ");

        ret=conv->conv(1, (const struct pam_message **) mesg, &resp,
                       conv->appdata_ptr);
        free((void *)mesg[0]->msg);
        free(mesg[0]);
        if (ret != PAM_SUCCESS) {
            D(("Conversation failure: %s.\n",  pam_strerror(pamh,ret)));
            pam_status = ret;
            goto done;
        }

        if (resp[0].resp == NULL) {
            D(("Empty password\n"));
            pi.pam_newauthtok = NULL;
            pi.pam_newauthtok_type = SSS_AUTHTOK_TYPE_EMPTY;
        } else {
            pi.pam_newauthtok = strdup(resp[0].resp);
            pi.pam_newauthtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
        }
        pi.pam_newauthtok_size=strlen(pi.pam_newauthtok);
    }

    print_pam_items(pi);

    if (pi.pam_user) {
        rd.len = pi.pam_user_size +
                 pi.pam_service_size +
                 pi.pam_tty_size +
                 pi.pam_ruser_size +
                 pi.pam_rhost_size +
                 2*sizeof(uint32_t) + pi.pam_authtok_size +
                 2*sizeof(uint32_t) + pi.pam_newauthtok_size +
                 sizeof(uint32_t);
        buf = malloc(rd.len);

        memcpy(buf, pi.pam_user, pi.pam_user_size);
        rp = pi.pam_user_size;

        memcpy(&buf[rp],  pi.pam_service, pi.pam_service_size);
        rp += pi.pam_service_size;

        memcpy(&buf[rp],  pi.pam_tty, pi.pam_tty_size);
        rp += pi.pam_tty_size;

        memcpy(&buf[rp],  pi.pam_ruser, pi.pam_ruser_size);
        rp += pi.pam_ruser_size;

        memcpy(&buf[rp],  pi.pam_rhost, pi.pam_rhost_size);
        rp += pi.pam_rhost_size;

        ((uint32_t *)(&buf[rp]))[0] = pi.pam_authtok_type;
        rp += sizeof(uint32_t);
        ((uint32_t *)(&buf[rp]))[0] = pi.pam_authtok_size;
        rp += sizeof(uint32_t);
        memcpy(&buf[rp],  pi.pam_authtok, pi.pam_authtok_size);
        rp += pi.pam_authtok_size;
        _pam_overwrite((void *)pi.pam_authtok);
        free((void *)pi.pam_authtok);

        ((uint32_t *)(&buf[rp]))[0] = pi.pam_newauthtok_type;
        rp += sizeof(uint32_t);
        ((uint32_t *)(&buf[rp]))[0] = pi.pam_newauthtok_size;
        rp += sizeof(uint32_t);
        memcpy(&buf[rp],  pi.pam_newauthtok, pi.pam_newauthtok_size);
        rp += pi.pam_newauthtok_size;
        _pam_overwrite((void *)pi.pam_newauthtok);
        free((void *)pi.pam_newauthtok);

        ((uint32_t *)(&buf[rp]))[0] = END_OF_PAM_REQUEST;
        rp += sizeof(uint32_t);

        if (rp != rd.len) {
            D(("error during packet creation."));
            pam_status = PAM_ABORT;
            goto done;
        }
        rd.data = buf;

        ret = sss_pam_make_request(task, &rd, &repbuf, &replen, &errnop);

        if (ret != NSS_STATUS_SUCCESS) {
            D(("sss_pam_make_request failed."));
            pam_status = ret;
            goto done;
        }

        if (replen<sizeof(int) || repbuf[replen-1]!='\0') {
            D(("response not in expected format."));
            pam_status=PAM_SYSTEM_ERR;
            goto done;
        }

        pam_status = ((int32_t *)repbuf)[0];
        domain = (char *)(repbuf + sizeof(uint32_t));
        D(("received: %d (%s)", pam_status, pam_strerror(pamh,pam_status)));
        D(("received: %s", domain));
    } else {
        D(("no user found, doing nothing"));
        return PAM_SUCCESS;
    }

done:
    if ( resp != NULL ) {
        _pam_overwrite((void *)resp[0].resp);
        free(resp[0].resp);
        free(resp);
    }
    if ( buf != NULL && repbuf != NULL) _pam_overwrite_n(buf, rd.len);
    free(buf);
    free(repbuf);

    return pam_status;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv ) {
    return pam_sss(SSS_PAM_AUTHENTICATE, pamh, flags, argc, argv);
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv ) {
    return pam_sss(SSS_PAM_SETCRED, pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv ) {
    return pam_sss(SSS_PAM_ACCT_MGMT, pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv ) {
    return pam_sss(SSS_PAM_CHAUTHTOK, pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv ) {
    return pam_sss(SSS_PAM_OPEN_SESSION, pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv ) {
    return pam_sss(SSS_PAM_CLOSE_SESSION, pamh, flags, argc, argv);
}


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_sssd_modstruct = {
     "pam_sssd",
     pam_sm_authenticate,
     pam_sm_setcred,
     pam_sm_acct_mgmt,
     pam_sm_open_session,
     pam_sm_close_session,
     pam_sm_chauthtok
};

#endif
