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
#include <unistd.h>
#include <sys/stat.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/dp_backend.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_utils.h"

struct krb5_req {
    krb5_context ctx;
    krb5_ccache cc;
    krb5_principal princ;
    char* name;
    krb5_creds *creds;
    krb5_get_init_creds_opt *options;
    pid_t child_pid;
    int read_from_child_fd;
    int write_to_child_fd;

    struct be_req *req;
    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;
    errno_t (*child_req)(int fd, struct krb5_req *kr);

    char *ccname;
};

static krb5_context krb5_error_ctx;
static const char *__krb5_error_msg;
#define KRB5_DEBUG(level, krb5_error) do { \
    __krb5_error_msg = krb5_get_error_message(krb5_error_ctx, krb5_error); \
    DEBUG(level, ("%d: [%d][%s]\n", __LINE__, krb5_error, __krb5_error_msg)); \
    krb5_free_error_message(krb5_error_ctx, __krb5_error_msg); \
} while(0);

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

static struct response *prepare_response_message(struct krb5_req *kr,
                                        krb5_error_code kerr, int pam_status)
{
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
        if (kr->cc == NULL || kr->ccname == NULL) {
            DEBUG(1, ("Error obtaining ccname.\n"));
            return NULL;
        }

        msg = talloc_asprintf(kr, "%s=%s",CCACHE_ENV_NAME, kr->ccname);
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

static krb5_error_code get_and_save_tgt(struct krb5_req *kr,
                                        char *password)
{
    krb5_error_code kerr = 0;
    int fd = -1;
    size_t ccname_len = 0;
    size_t offset = 0;

    kerr = krb5_get_init_creds_password(kr->ctx, kr->creds, kr->princ,
                                        password, NULL, NULL, 0, NULL,
                                        kr->options);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        return kerr;
    }

    if (kr->ccname[0] == '/' || strncmp(kr->ccname, "FILE:", 5) == 0) {
        offset = 0;
        if (kr->ccname[0] == 'F') {
            offset = 5;
        }
        ccname_len = strlen(kr->ccname + offset);
        if (ccname_len >= 6 &&
            strcmp(kr->ccname + (ccname_len-6), "XXXXXX")==0 ) {
            fd = mkstemp(kr->ccname + offset);
            if (fd == -1) {
                DEBUG(1, ("mkstemp failed [%d][%s].\n", errno,
                          strerror(errno)));
                kerr = KRB5KRB_ERR_GENERIC;
                goto done;
            }
        }
    }

    kerr = krb5_cc_resolve(kr->ctx, kr->ccname, &kr->cc);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto done;
    }

    kerr = krb5_cc_initialize(kr->ctx, kr->cc, kr->princ);
    if (fd != -1) {
        close(fd);
    }
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto done;
    }

    kerr = krb5_cc_store_cred(kr->ctx, kr->cc, kr->creds);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        krb5_cc_destroy(kr->ctx, kr->cc);
        kr->cc = NULL;
        goto done;
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
    errno_t err;
    char *pass_str = NULL;
    char *newpass_str = NULL;
    struct response *resp = NULL;
    int pam_status = PAM_SYSTEM_ERR;
    int result_code = -1;
    krb5_data result_code_string;
    krb5_data result_string;

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
    resp = prepare_response_message(kr, kerr, pam_status);
    if (resp == NULL) {
        DEBUG(1, ("prepare_response_message failed.\n"));
        krb5_cc_destroy(kr->ctx, kr->cc);
        kr->cc = NULL;
        return ENOMEM;
    }

    ret = write(fd, resp->buf, resp->size);
    if (ret == -1) {
        err = errno;
        DEBUG(1, ("write failed [%d][%s].\n", errno, strerror(errno)));
        krb5_cc_destroy(kr->ctx, kr->cc);
        kr->cc = NULL;
        return err;
    }

    if (kr->cc != NULL) {
        krb5_cc_close(kr->ctx, kr->cc);
        kr->cc = NULL;
    }

    return EOK;
}

static errno_t tgt_req_child(int fd, struct krb5_req *kr)
{
    int ret;
    krb5_error_code kerr = 0;
    errno_t err;
    char *pass_str = NULL;
    int pam_status = PAM_SYSTEM_ERR;
    struct response *resp = NULL;

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
        kr->cc = NULL;
        return ENOMEM;
    }

    ret = write(fd, resp->buf, resp->size);
    if (ret == -1) {
        err = errno;
        DEBUG(1, ("write failed [%d][%s].\n", errno, strerror(errno)));
        krb5_cc_destroy(kr->ctx, kr->cc);
        kr->cc = NULL;
        return err;
    }

    if (kr->cc != NULL) {
        krb5_cc_close(kr->ctx, kr->cc);
        kr->cc = NULL;
    }

    return EOK;
}

static errno_t unpack_buffer(uint8_t *buf, size_t size, struct pam_data *pd,
                             char **ccname)
{
    size_t p = 0;
    uint32_t *len;
    uint8_t *str;

    len = ((uint32_t *)(buf+p));
    pd->cmd = *len;
    p += sizeof(uint32_t);

    len = ((uint32_t *)(buf+p));
    p += sizeof(uint32_t);
    str = talloc_memdup(pd, buf+p, sizeof(char) * (*len + 1));
    if (str == NULL) return ENOMEM;
    str[*len] = '\0';
    pd->upn = (char *) str;
    p += *len;

    len = ((uint32_t *)(buf+p));
    p += sizeof(uint32_t);
    str = talloc_memdup(pd, buf+p, sizeof(char) * (*len + 1));
    if (str == NULL) return ENOMEM;
    str[*len] = '\0';
    *ccname = (char *) str;
    p += *len;

    len = ((uint32_t *)(buf+p));
    p += sizeof(uint32_t);
    str = talloc_memdup(pd, buf+p, sizeof(char) * (*len + 1));
    if (str == NULL) return ENOMEM;
    str[*len] = '\0';
    pd->authtok = str;
    pd->authtok_size = *len + 1;
    p += *len;

    if (pd->cmd == SSS_PAM_CHAUTHTOK) {
        len = ((uint32_t *)(buf+p));
        p += sizeof(uint32_t);
        str = talloc_memdup(pd, buf+p, sizeof(char) * (*len + 1));
        if (str == NULL) return ENOMEM;
        str[*len] = '\0';
        pd->newauthtok = str;
        pd->newauthtok_size = *len + 1;
        p += *len;
    } else {
        pd->newauthtok = NULL;
        pd->newauthtok_size = 0;
    }

    return EOK;
}

static int krb5_cleanup(void *ptr)
{
    struct krb5_req *kr = talloc_get_type(ptr, struct krb5_req);
    if (kr == NULL) return EOK;

    if (kr->options != NULL)
        krb5_get_init_creds_opt_free(kr->ctx, kr->options);
    if (kr->creds != NULL) {
        krb5_free_cred_contents(kr->ctx, kr->creds);
        krb5_free_creds(kr->ctx, kr->creds);
    }
    if (kr->name != NULL)
        krb5_free_unparsed_name(kr->ctx, kr->name);
    if (kr->princ != NULL)
        krb5_free_principal(kr->ctx, kr->princ);
    if (kr->cc != NULL)
        krb5_cc_close(kr->ctx, kr->cc);
    if (kr->ctx != NULL)
        krb5_free_context(kr->ctx);

    if (kr->krb5_ctx != NULL) {
        memset(kr->krb5_ctx, 0, sizeof(struct krb5_ctx));
    }
    memset(kr, 0, sizeof(struct krb5_req));

    return EOK;
}

static int krb5_setup(struct pam_data *pd, const char *user_princ_str,
                      struct krb5_req **krb5_req)
{
    struct krb5_req *kr = NULL;
    krb5_error_code kerr = 0;

    kr = talloc_zero(pd, struct krb5_req);
    if (kr == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        kerr = ENOMEM;
        goto failed;
    }
    talloc_set_destructor((TALLOC_CTX *) kr, krb5_cleanup);

    kr->krb5_ctx = talloc_zero(kr, struct krb5_ctx);
    if (kr->krb5_ctx == NULL) {
        DEBUG(1, ("talloc failed.\n"));
        kerr = ENOMEM;
        goto failed;
    }

    kr->krb5_ctx->changepw_principle = getenv(SSSD_KRB5_CHANGEPW_PRINCIPLE);
    if (kr->krb5_ctx->changepw_principle == NULL) {
        DEBUG(1, ("Cannot read [%s] from environment.\n",
                  SSSD_KRB5_CHANGEPW_PRINCIPLE));
        if (pd->cmd == SSS_PAM_CHAUTHTOK) {
            goto failed;
        }
    }

    kr->krb5_ctx->realm = getenv(SSSD_KRB5_REALM);
    if (kr->krb5_ctx->realm == NULL) {
        DEBUG(2, ("Cannot read [%s] from environment.\n", SSSD_KRB5_REALM));
    }

    kr->pd = pd;

    switch(pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            kr->child_req = tgt_req_child;
            break;
        case SSS_PAM_CHAUTHTOK:
            kr->child_req = changepw_child;
            break;
        default:
            DEBUG(1, ("PAM command [%d] not supported.\n", pd->cmd));
            kerr = EINVAL;
            goto failed;
    }

    kerr = krb5_init_context(&kr->ctx);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto failed;
    }

    kerr = krb5_parse_name(kr->ctx, user_princ_str, &kr->princ);
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

    kerr = krb5_get_init_creds_opt_alloc(kr->ctx, &kr->options);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto failed;
    }

/* TODO: set options, e.g.
 *  krb5_get_init_creds_opt_set_tkt_life
 *  krb5_get_init_creds_opt_set_renew_life
 *  krb5_get_init_creds_opt_set_forwardable
 *  krb5_get_init_creds_opt_set_proxiable
 *  krb5_get_init_creds_opt_set_etype_list
 *  krb5_get_init_creds_opt_set_address_list
 *  krb5_get_init_creds_opt_set_preauth_list
 *  krb5_get_init_creds_opt_set_salt
 *  krb5_get_init_creds_opt_set_change_password_prompt
 *  krb5_get_init_creds_opt_set_pa
 */

    *krb5_req = kr;
    return EOK;

failed:
    talloc_free(kr);

    return kerr;
}

int main(int argc, char *argv[])
{
    uint8_t *buf = NULL;
    int ret;
    struct pam_data *pd = NULL;
    struct krb5_req *kr = NULL;
    char *ccname;

    debug_prg_name = argv[0];

    pd = talloc(NULL, struct pam_data);

    buf = talloc_size(pd, sizeof(uint8_t)*512);
    if (buf == NULL) {
        DEBUG(1, ("malloc failed.\n"));
        _exit(-1);
    }

    ret = read(STDIN_FILENO, buf, 512);
    if (ret == -1) {
        DEBUG(1, ("read failed [%d][%s].\n", errno, strerror(errno)));
        talloc_free(pd);
        exit(-1);
    }
    close(STDIN_FILENO);

    ret = unpack_buffer(buf, ret, pd, &ccname);
    if (ret != EOK) {
        DEBUG(1, ("unpack_buffer failed.\n"));
        talloc_free(pd);
        exit(-1);
    }

    ret = krb5_setup(pd, pd->upn, &kr);
    if (ret != EOK) {
        DEBUG(1, ("krb5_setup failed.\n"));
        talloc_free(pd);
        exit(-1);
    }
    kr->ccname = ccname;

    ret = kr->child_req(STDOUT_FILENO, kr);
    if (ret != EOK) {
        DEBUG(1, ("Child request failed.\n"));
    }

    close(STDOUT_FILENO);
    talloc_free(pd);

    return 0;
}
