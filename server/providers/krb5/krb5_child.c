/*
    SSSD

    Kerberos 5 Backend Module -- tgt_req and changepw child

    Authors:
        Sumit Bose <sbose@redhat.com>

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
#include <krb5/krb5.h>
#include <sys/types.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/dp_backend.h"
#include "providers/krb5/krb5_auth.h"

struct response {
    size_t max_size;
    size_t size;
    uint8_t *buf;
};

static struct response *init_response(TALLOC_CTX *mem_ctx) {
    struct response *r;
    r = talloc(mem_ctx, struct response);
    r->buf = talloc_size(mem_ctx, MAX_CHILD_MSG_SIZE);
    if (r->buf == NULL) {
        DEBUG(1, ("talloc_size failed.\n"));
        return NULL;
    }
    r->max_size = MAX_CHILD_MSG_SIZE;
    r->size = 0;

    return r;
}

static errno_t pack_response_packet(struct response *resp, int status, int type, const char *data)
{
    int len;
    int p=0;

    len = strlen(data)+1;
    if ((3*sizeof(int32_t) + len +1) > resp->max_size) {
        DEBUG(1, ("response message too big.\n"));
        return ENOMEM;
    }

    ((int32_t *)(&resp->buf[p]))[0] = status;
    p += sizeof(int32_t);

    ((int32_t *)(&resp->buf[p]))[0] = type;
    p += sizeof(int32_t);

    ((int32_t *)(&resp->buf[p]))[0] = len;
    p += sizeof(int32_t);

    memcpy(&resp->buf[p], data, len);
    p += len;

    resp->size = p;

    return EOK;
}

static struct response * prepare_response_message(struct krb5_req *kr,
                                        krb5_error_code kerr, int pam_status)
{
    const char *cc_name = NULL;
    char *msg = NULL;
    const char *krb5_msg = NULL;
    int ret;
    struct response *resp;

    resp = init_response(kr);
    if (resp == NULL) {
        DEBUG(1, ("init_response failed.\n"));
        return NULL;
    }

    if (kerr == 0) {
        cc_name = krb5_cc_get_name(kr->ctx, kr->cc);
        if (cc_name == NULL) {
            DEBUG(1, ("krb5_cc_get_name failed.\n"));
            return NULL;
        }

        msg = talloc_asprintf(kr, "%s=%s",CCACHE_ENV_NAME, cc_name);
        if (msg == NULL) {
            DEBUG(1, ("talloc_asprintf failed.\n"));
            return NULL;
        }

        ret = pack_response_packet(resp, PAM_SUCCESS, PAM_ENV_ITEM, msg);
        talloc_zfree(msg);
    } else {
        krb5_msg = krb5_get_error_message(krb5_error_ctx, kerr);
        if (krb5_msg == NULL) {
            DEBUG(1, ("krb5_get_error_message failed.\n"));
            return NULL;
        }

        ret = pack_response_packet(resp, pam_status, PAM_USER_INFO, krb5_msg);
        krb5_free_error_message(krb5_error_ctx, krb5_msg);
    }

    if (ret != EOK) {
        DEBUG(1, ("pack_response_packet failed.\n"));
        return NULL;
    }

    return resp;
}

static errno_t become_user(uid_t uid, gid_t gid)
{
    int ret;
    ret = setgid(gid);
    if (ret == -1) {
        DEBUG(1, ("setgid failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    ret = setuid(uid);
    if (ret == -1) {
        DEBUG(1, ("setuid failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    ret = setegid(gid);
    if (ret == -1) {
        DEBUG(1, ("setegid failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    ret = seteuid(uid);
    if (ret == -1) {
        DEBUG(1, ("seteuid failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    return EOK;
}

static krb5_error_code get_and_save_tgt(struct krb5_req *kr,
                                        char *password)
{
    krb5_error_code kerr = 0;

    kerr = krb5_get_init_creds_password(kr->ctx, kr->creds, kr->princ,
                                        password, NULL, NULL, 0, NULL,
                                        kr->options);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        return kerr;
    }

    kerr = krb5_cc_default(kr->ctx, &kr->cc);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        return kerr;
    }

    kerr = krb5_cc_initialize(kr->ctx, kr->cc, kr->princ);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        return kerr;
    }

    kerr = krb5_cc_store_cred(kr->ctx, kr->cc, kr->creds);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        krb5_cc_destroy(kr->ctx, kr->cc);
        return kerr;
    }

    return 0;

}

void changepw_child(int fd, struct krb5_req *kr)
{
    int ret;
    krb5_error_code kerr = 0;
    char *pass_str = NULL;
    char *newpass_str = NULL;
    struct response *resp = NULL;
    int pam_status = PAM_SYSTEM_ERR;
    int result_code = -1;
    krb5_data result_code_string;
    krb5_data result_string;

    if (kr->pd->priv != 1) {
        ret = become_user(kr->pd->pw_uid, kr->pd->gr_gid);
        if (ret != EOK) {
            DEBUG(1, ("become_user failed.\n"));
            kerr = KRB5KRB_ERR_GENERIC;
            goto sendresponse;
        }
    } else {
/* TODO: implement password reset by root */
        DEBUG(1, ("Password reset not implemented.\n"));
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

    kerr = krb5_get_init_creds_password(kr->ctx, kr->creds, kr->princ,
                                        pass_str, NULL, NULL, 0,
                                        kr->krb5_ctx->changepw_principle,
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

    newpass_str = talloc_strndup(kr, (const char *) kr->pd->newauthtok,
                              kr->pd->newauthtok_size);
    if (newpass_str == NULL) {
        DEBUG(1, ("talloc_strndup failed.\n"));
        kerr = KRB5KRB_ERR_GENERIC;
        goto sendresponse;
    }

    kerr = krb5_change_password(kr->ctx, kr->creds, newpass_str, &result_code,
                                &result_code_string, &result_string);

    if (kerr != 0 || result_code != 0) {
        if (kerr != 0) {
            KRB5_DEBUG(1, kerr);
        }

        if (result_code_string.length > 0) {
            DEBUG(1, ("krb5_change_password failed [%d][%.*s].\n", result_code,
                      result_code_string.length, result_code_string.data));
        }

        if (result_string.length > 0) {
            DEBUG(1, ("krb5_change_password failed [%d][%.*s].\n", result_code,
                      result_string.length, result_string.data));
        }

        goto sendresponse;
    }


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
    resp = prepare_response_message(kr, kerr, pam_status);
    if (resp == NULL) {
        DEBUG(1, ("prepare_response_message failed.\n"));
        krb5_cc_destroy(kr->ctx, kr->cc);
        _exit(-1);
    }

    ret = write(fd, resp->buf, resp->size);
    if (ret == -1) {
        DEBUG(1, ("write failed [%d][%s].\n", errno, strerror(errno)));
        krb5_cc_destroy(kr->ctx, kr->cc);
        _exit(ret);
    }

    krb5_cc_close(kr->ctx, kr->cc);


    _exit(0);
}

void tgt_req_child(int fd, struct krb5_req *kr)
{
    int ret;
    krb5_error_code kerr = 0;
    char *pass_str = NULL;
    int pam_status = PAM_SYSTEM_ERR;
    struct response *resp = NULL;

    ret = become_user(kr->pd->pw_uid, kr->pd->gr_gid);
    if (ret != EOK) {
        DEBUG(1, ("become_user failed.\n"));
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

    kerr = get_and_save_tgt(kr, pass_str);
    memset(pass_str, 0, kr->pd->authtok_size);
    talloc_zfree(pass_str);
    memset(kr->pd->authtok, 0, kr->pd->authtok_size);

    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        if (kerr == KRB5_KDC_UNREACH) {
            pam_status = PAM_AUTHINFO_UNAVAIL;
        }
    }

sendresponse:
    resp = prepare_response_message(kr, kerr, pam_status);
    if (resp == NULL) {
        DEBUG(1, ("prepare_response_message failed.\n"));
        krb5_cc_destroy(kr->ctx, kr->cc);
        _exit(-1);
    }

    ret = write(fd, resp->buf, resp->size);
    if (ret == -1) {
        DEBUG(1, ("write failed [%d][%s].\n", errno, strerror(errno)));
        krb5_cc_destroy(kr->ctx, kr->cc);
        _exit(ret);
    }

    krb5_cc_close(kr->ctx, kr->cc);


    _exit(0);
}
