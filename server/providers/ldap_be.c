/*
    SSSD

    LDAP Backend Module

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2008 Red Hat

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

#include <errno.h>
#include <ldap.h>
#include <sys/time.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/dp_backend.h"
#include "db/sysdb.h"
#include "../sss_client/sss_cli.h"

struct ldap_ctx {
    char *ldap_uri;
    char *default_bind_dn;
    char *user_search_base;
    char *user_name_attribute;
    char *user_object_class;
    char *default_authtok_type;
    uint32_t default_authtok_size;
    char *default_authtok;
};

struct ldap_ops;
struct ldap_req;

struct ldap_ops {
    void (*op)(struct ldap_req *);
    struct ldap_ops *next;
};

enum ldap_be_ops {
    LDAP_NOOP = 0x0000,
    LDAP_OP_INIT = 0x0001,
    LDAP_CHECK_INIT_RESULT,
    LDAP_CHECK_STD_BIND,
    LDAP_CHECK_SEARCH_DN_RESULT,
    LDAP_CHECK_USER_BIND
};

struct ldap_req {
    struct be_req *req;
    struct pam_data *pd;
    struct ldap_ctx *ldap_ctx;
    LDAP *ldap;
    struct ldap_ops *ops;
    char *user_dn;
    event_fd_handler_t next_task;
    enum ldap_be_ops next_op;
    int msgid;
};

static int schedule_next_task(struct ldap_req *lr, struct timeval tv,
                              event_timed_handler_t task)
{
    int ret;
    struct timed_event *te;
    struct timeval timeout;

    ret = gettimeofday(&timeout, NULL);
    if (ret == -1) {
        DEBUG(1, ("gettimeofday failed [%d][%s].\n", errno, strerror(errno)));
        return ret;
    }
    timeout.tv_sec += tv.tv_sec;
    timeout.tv_usec += tv.tv_usec;


    te = event_add_timed(lr->req->be_ctx->ev, lr, timeout, task, lr); 
    if (te == NULL) {
        return EIO;
    }

    return EOK;
}

static int wait_for_fd(struct ldap_req *lr)
{
    int ret;
    int fd;
    struct fd_event *fde;

    ret = ldap_get_option(lr->ldap, LDAP_OPT_DESC, &fd);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("ldap_get_option failed.\n"));
        return ret;
    }

    fde = event_add_fd(lr->req->be_ctx->ev, lr, fd, EVENT_FD_READ, lr->next_task, lr);
    if (fde == NULL) {
        return EIO;
    }

    return EOK;
}

static int ldap_pam_chauthtok(struct ldap_req *lr)
{
    BerElement *ber=NULL;
    int ret;
    int pam_status=PAM_SUCCESS;
    struct berval *bv;
    int msgid;
    LDAPMessage *result=NULL;
    int ldap_ret;

    ber = ber_alloc_t( LBER_USE_DER );
    if (ber == NULL) {
        DEBUG(1, ("ber_alloc_t failed.\n"));
        return PAM_SYSTEM_ERR;
    }

    ret = ber_printf( ber, "{tststs}", LDAP_TAG_EXOP_MODIFY_PASSWD_ID,
                     lr->user_dn,
                     LDAP_TAG_EXOP_MODIFY_PASSWD_OLD, lr->pd->authtok,
                     LDAP_TAG_EXOP_MODIFY_PASSWD_NEW, lr->pd->newauthtok);
    if (ret == -1) {
        DEBUG(1, ("ber_printf failed.\n"));
        pam_status = PAM_SYSTEM_ERR;
        goto cleanup;
    }

    ret = ber_flatten(ber, &bv);
    if (ret == -1) {
        DEBUG(1, ("ber_flatten failed.\n"));
        pam_status = PAM_SYSTEM_ERR;
        goto cleanup;
    }

    ret = ldap_extended_operation(lr->ldap, LDAP_EXOP_MODIFY_PASSWD, bv,
                                  NULL, NULL, &msgid);
    if (ret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_extended_operation failed.\n"));
        pam_status = PAM_SYSTEM_ERR;
        goto cleanup;
    }

    ret = ldap_result(lr->ldap, msgid, FALSE, NULL, &result);
    if (ret == -1) {
        DEBUG(1, ("ldap_result failed.\n"));
        pam_status = PAM_SYSTEM_ERR;
        goto cleanup;
    }
    ret = ldap_parse_result(lr->ldap, result, &ldap_ret, NULL, NULL, NULL,
                            NULL, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_parse_result failed.\n"));
        pam_status = PAM_SYSTEM_ERR;
        goto cleanup;
    }
    DEBUG(3, ("LDAP_EXOP_MODIFY_PASSWD result: [%d][%s]\n", ldap_ret,
              ldap_err2string(ldap_ret)));

    ldap_msgfree(result);

    if (ldap_ret != LDAP_SUCCESS) pam_status = PAM_SYSTEM_ERR;

cleanup:
    ber_bvfree(bv);
    ber_free(ber, 1);
    return pam_status;
}

static int ldap_be_init(struct ldap_req *lr)
{
    int ret;
    int status=EOK;
    int ldap_vers = LDAP_VERSION3;
    int msgid;

    ret = ldap_initialize(&(lr->ldap), lr->ldap_ctx->ldap_uri);
    if (ret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_initialize failed: %s\n", strerror(errno)));
        return EIO;
    }

    /* LDAPv3 is needed for TLS */
    ret = ldap_set_option(lr->ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_vers);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("ldap_set_option failed: %s\n", ldap_err2string(ret)));
        status = EIO;
        goto cleanup;
    }

    /* For now TLS is forced. Maybe it would be necessary to make this
     * configurable to allow people to expose their passwords over the
     * network. */
    ret = ldap_start_tls(lr->ldap, NULL, NULL, &msgid);
    if (ret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_start_tls failed: %s\n", ldap_err2string(ret)));
        status = EIO;
        goto cleanup;
    }

    lr->msgid = msgid;

    return EOK;

cleanup:
    ldap_unbind_ext(lr->ldap, NULL, NULL);
    lr->ldap = NULL;
    return status;
}

static int ldap_be_bind(struct ldap_req *lr)
{
    int ret;
    int msgid;
    char *dn=NULL;
    struct berval pw;

    pw.bv_len = 0;
    pw.bv_val = NULL;

    if (lr->user_dn != NULL) {
        dn = lr->user_dn;
        pw.bv_len = lr->pd->authtok_size;
        pw.bv_val = (char *) lr->pd->authtok;
    }
    if (lr->user_dn == NULL && lr->ldap_ctx->default_bind_dn != NULL) {
        dn = lr->ldap_ctx->default_bind_dn;
        pw.bv_len = lr->ldap_ctx->default_authtok_size;
        pw.bv_val = lr->ldap_ctx->default_authtok;
    }

    DEBUG(3, ("Trying to bind as [%s][%*s]\n", dn, pw.bv_len, pw.bv_val));
    ret = ldap_sasl_bind(lr->ldap, dn, LDAP_SASL_SIMPLE, &pw, NULL, NULL,
                         &msgid);
    if (ret == -1 || msgid == -1) {
        DEBUG(1, ("ldap_bind failed\n"));
        return LDAP_OTHER;
    }
    lr->msgid = msgid;
    return LDAP_SUCCESS;
}

static void ldap_be_loop(struct event_context *ev, struct fd_event *te,
                     uint16_t fd, void *pvt)
{
    int ret;
    int pam_status=PAM_SUCCESS;
    int ldap_ret;
    struct ldap_req *lr;
    struct be_pam_handler *ph;
    struct be_req *req;
    LDAPMessage *result=NULL;
    LDAPMessage *msg=NULL;
    struct timeval no_timeout={0, 0};
    char *errmsgp = NULL;
/* FIXME: user timeout form config */
    char *filter=NULL;
    char *attrs[] = { LDAP_NO_ATTRS, NULL };

    lr = talloc_get_type(pvt, struct ldap_req); 

    switch (lr->next_op) {
        case LDAP_OP_INIT:
            ret = ldap_be_init(lr);
            if (ret != EOK) {
                DEBUG(1, ("ldap_be_init failed.\n"));
                lr->ldap = NULL;
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
        case LDAP_CHECK_INIT_RESULT:
            ret = ldap_result(lr->ldap, lr->msgid, FALSE, &no_timeout, &result);
            if (ret == -1) {
                DEBUG(1, ("ldap_result failed.\n"));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
            if (ret == 0) {
                DEBUG(1, ("ldap_result not ready yet, waiting.\n"));
                lr->next_task = ldap_be_loop;
                lr->next_op = LDAP_CHECK_INIT_RESULT;
                ret = wait_for_fd(lr);
                if (ret != EOK) {
                    DEBUG(1, ("schedule_next_task failed.\n"));
                    pam_status = PAM_SYSTEM_ERR;
                    goto done;
                }
                return;
            }

            ret = ldap_parse_result(lr->ldap, result, &ldap_ret, NULL, NULL, NULL, NULL, 0);
            if (ret != LDAP_SUCCESS) {
                DEBUG(1, ("ldap_parse_result failed.\n"));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
            DEBUG(3, ("ldap_start_tls result: [%d][%s]\n", ldap_ret, ldap_err2string(ldap_ret)));

            if (ldap_ret != LDAP_SUCCESS) {
                DEBUG(1, ("setting up TLS failed.\n"));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }

/* FIXME: take care that ldap_install_tls might block */
            ret = ldap_install_tls(lr->ldap);
            if (ret != LDAP_SUCCESS) {
                DEBUG(1, ("ldap_install_tls failed.\n"));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }

            ret = ldap_be_bind(lr);
            if (ret != LDAP_SUCCESS) {
                DEBUG(1, ("ldap_be_bind failed.\n"));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
        case LDAP_CHECK_STD_BIND:
            ret = ldap_result(lr->ldap, lr->msgid, FALSE, &no_timeout, &result);
            if (ret == -1) {
                DEBUG(1, ("ldap_result failed.\n"));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
            if (ret == 0) {
                DEBUG(1, ("ldap_result not ready yet, waiting.\n"));
                lr->next_task = ldap_be_loop;
                lr->next_op = LDAP_CHECK_STD_BIND;
                ret = wait_for_fd(lr);
                if (ret != EOK) {
                    DEBUG(1, ("schedule_next_task failed.\n"));
                    pam_status = PAM_SYSTEM_ERR;
                    goto done;
                }
                return;
            }

            ret = ldap_parse_result(lr->ldap, result, &ldap_ret, NULL, &errmsgp,
                                    NULL, NULL, 0);
            if (ret != LDAP_SUCCESS) {
                DEBUG(1, ("ldap_parse_result failed.\n"));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
            DEBUG(3, ("Bind result: [%d][%s][%s]\n", ldap_ret,
                      ldap_err2string(ldap_ret), errmsgp));
            if (ldap_ret != LDAP_SUCCESS) {
                DEBUG(1, ("bind failed.\n"));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }

            filter = talloc_asprintf(lr->ldap_ctx,
                                     "(&(%s=%s)(objectclass=%s))",
                                     lr->ldap_ctx->user_name_attribute,
                                     lr->pd->user,
                                     lr->ldap_ctx->user_object_class);

            DEBUG(4, ("calling ldap_search_ext with [%s].\n", filter));
            ret = ldap_search_ext(lr->ldap,
                                  lr->ldap_ctx->user_search_base,
                                  LDAP_SCOPE_SUBTREE,
                                  filter,
                                  attrs,
                                  TRUE,
                                  NULL,
                                  NULL,
                                  NULL,
                                  0,
                                  &(lr->msgid));
            if (ret != LDAP_SUCCESS) {
                DEBUG(1, ("ldap_search_ext failed [%d][%s].\n", ret, ldap_err2string(ret)));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
        case LDAP_CHECK_SEARCH_DN_RESULT:
            ret = ldap_result(lr->ldap, lr->msgid, TRUE, &no_timeout, &result);
            if (ret == -1) {
                DEBUG(1, ("ldap_result failed.\n"));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
            if (ret == 0) {
                DEBUG(1, ("ldap_result not ready yet, waiting.\n"));
                lr->next_task = ldap_be_loop;
                lr->next_op = LDAP_CHECK_SEARCH_DN_RESULT;
                ret = wait_for_fd(lr);
                if (ret != EOK) {
                    DEBUG(1, ("schedule_next_task failed.\n"));
                    pam_status = PAM_SYSTEM_ERR;
                    goto done;
                }
                return;
            }

            msg = ldap_first_message(lr->ldap, result);
            if (msg == NULL) {
                DEBUG(1, ("ldap_first_message failed.\n"));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }

            do {
                switch ( ldap_msgtype(msg) ) {
                    case LDAP_RES_SEARCH_ENTRY:
                        if (lr->user_dn != NULL) {
                            DEBUG(1, ("Found more than one object with filter [%s].\n",
                                      filter));
                            pam_status = PAM_SYSTEM_ERR;
                            goto done;
                        }
                        lr->user_dn = ldap_get_dn(lr->ldap, msg);
                        if (lr->user_dn == NULL) {
                            DEBUG(1, ("ldap_get_dn failed.\n"));
                            pam_status = PAM_SYSTEM_ERR;
                            goto done;
                        }

                        if ( *(lr->user_dn) == '\0' ) {
                            DEBUG(1, ("No user found.\n"));
                            pam_status = PAM_USER_UNKNOWN;
                            goto done;
                        }
                        DEBUG(3, ("Found dn: %s\n",lr->user_dn));

                        ldap_msgfree(result);
                        result = NULL;
                        break;
                    default:
                        DEBUG(3, ("ignoring message with type %d.\n", ldap_msgtype(msg)));
                }
            } while( (msg=ldap_next_message(lr->ldap, msg)) != NULL );

            ret = ldap_be_bind(lr);
            if (ret != LDAP_SUCCESS) {
                DEBUG(1, ("ldap_be_bind failed.\n"));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
        case LDAP_CHECK_USER_BIND:
            ret = ldap_result(lr->ldap, lr->msgid, FALSE, &no_timeout, &result);
            if (ret == -1) {
                DEBUG(1, ("ldap_result failed.\n"));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
            if (ret == 0) {
                DEBUG(1, ("ldap_result not ready yet, waiting.\n"));
                lr->next_task = ldap_be_loop;
                lr->next_op = LDAP_CHECK_USER_BIND;
                ret = wait_for_fd(lr);
                if (ret != EOK) {
                    DEBUG(1, ("schedule_next_task failed.\n"));
                    pam_status = PAM_SYSTEM_ERR;
                    goto done;
                }
                return;
            }

            ret = ldap_parse_result(lr->ldap, result, &ldap_ret, NULL, &errmsgp,
                                    NULL, NULL, 0);
            if (ret != LDAP_SUCCESS) {
                DEBUG(1, ("ldap_parse_result failed.\n"));
                pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
            DEBUG(3, ("Bind result: [%d][%s][%s]\n", ldap_ret,
                      ldap_err2string(ldap_ret), errmsgp));
            switch (ldap_ret) {
                case LDAP_SUCCESS:
                    pam_status = PAM_SUCCESS;
                    break;
                case LDAP_INVALID_CREDENTIALS:
                    pam_status = PAM_CRED_INSUFFICIENT;
                    goto done;
                    break;
                default:
                    pam_status = PAM_SYSTEM_ERR;
                    goto done;
            }

            switch (lr->pd->cmd) {
                case SSS_PAM_AUTHENTICATE:
                    pam_status = PAM_SUCCESS;
                    break;
                case SSS_PAM_CHAUTHTOK:
                    pam_status = ldap_pam_chauthtok(lr);
                    break;
                case SSS_PAM_ACCT_MGMT:
                case SSS_PAM_SETCRED:
                case SSS_PAM_OPEN_SESSION:
                case SSS_PAM_CLOSE_SESSION:
                    pam_status = PAM_SUCCESS;
                    break;
                default:
                    DEBUG(1, ("Unknown pam command %d.\n", lr->pd->cmd));
                    pam_status = PAM_SYSTEM_ERR;
            }
            break;
        default:
            DEBUG(1, ("Unknown ldap backend operation %d.\n", lr->next_op));
            pam_status = PAM_SYSTEM_ERR;
    }

done:
    ldap_memfree(errmsgp);
    ldap_msgfree(result);
    talloc_free(filter);
    if (lr->ldap != NULL) ldap_unbind_ext(lr->ldap, NULL, NULL);
    req = lr->req;
    ph = talloc_get_type(lr->req->req_data, struct be_pam_handler);
    ph->pam_status = pam_status;

    talloc_free(lr);

    req->fn(req, pam_status, NULL);
}

static void ldap_start(struct event_context *ev, struct timed_event *te,
                     struct timeval tv, void *pvt)
{
    int ret;
    int pam_status;
    struct ldap_req *lr;
    struct be_req *req;
    struct be_pam_handler *ph;

    lr = talloc_get_type(pvt, struct ldap_req); 

    ret = ldap_be_init(lr);
    if (ret != EOK) {
        DEBUG(1, ("ldap_be_init failed.\n"));
        lr->ldap = NULL;
        pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    lr->next_task = ldap_be_loop;
    lr->next_op = LDAP_CHECK_INIT_RESULT;
    ret = wait_for_fd(lr);
    if (ret != EOK) {
        DEBUG(1, ("schedule_next_task failed.\n"));
        pam_status = PAM_SYSTEM_ERR;
        goto done;
    }
    return;

done:
    if (lr->ldap != NULL ) ldap_unbind_ext(lr->ldap, NULL, NULL);
    req = lr->req;
    ph = talloc_get_type(lr->req->req_data, struct be_pam_handler);
    ph->pam_status = pam_status;

    talloc_free(lr);

    req->fn(req, pam_status, NULL);
}

static void ldap_pam_handler(struct be_req *req)
{
    int ret;
    int pam_status=PAM_SUCCESS;
    struct ldap_req *lr;
    struct ldap_ctx *ldap_ctx;
    struct be_pam_handler *ph;
    struct pam_data *pd;
    struct timeval timeout;

    ph = talloc_get_type(req->req_data, struct be_pam_handler);
    pd = ph->pd;

    ldap_ctx = talloc_get_type(req->be_ctx->pvt_data, struct ldap_ctx);

    lr = talloc(req, struct ldap_req);

    lr->ldap = NULL;
    lr->req = req;
    lr->pd = pd;
    lr->ldap_ctx = ldap_ctx;
    lr->user_dn = NULL;
    lr->next_task = NULL;
    lr->next_op = LDAP_NOOP;

    timeout.tv_sec=0;
    timeout.tv_usec=0;
    ret = schedule_next_task(lr, timeout, ldap_start);
    if (ret != EOK) {
        DEBUG(1, ("schedule_next_task failed.\n"));
        pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    return;

done:
    talloc_free(lr);

    ph->pam_status = pam_status;
    req->fn(req, pam_status, NULL);
}

struct be_mod_ops ldap_mod_ops = {
    .check_online = NULL,
    .get_account_info = NULL,
    .pam_handler = ldap_pam_handler
};


int sssm_ldap_init(struct be_ctx *bectx, struct be_mod_ops **ops, void **pvt_data)
{
    struct ldap_ctx *ctx;
    char *ldap_uri;
    char *default_bind_dn;
    char *default_authtok_type;
    char *default_authtok;
    char *user_search_base;
    char *user_name_attribute;
    char *user_object_class;
    int ret;

    ctx = talloc(bectx, struct ldap_ctx);
    if (!ctx) {
        return ENOMEM;
    }

/* TODO: add validation checks for ldapUri, user_search_base,
 * user_name_attribute, etc */
    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                           "ldapUri", "ldap://localhost", &ldap_uri);
    if (ret != EOK) goto done;
    ctx->ldap_uri = ldap_uri;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                           "defaultBindDn", NULL, &default_bind_dn);
    if (ret != EOK) goto done;
    ctx->default_bind_dn = default_bind_dn;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                           "defaultAuthtokType", NULL, &default_authtok_type);
    if (ret != EOK) goto done;
    ctx->default_authtok_type = default_authtok_type;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                           "userSearchBase", NULL, &user_search_base);
    if (ret != EOK) goto done;
    if (user_search_base == NULL) {
        DEBUG(1, ("missing userSearchBase.\n"));
        ret = EINVAL;
        goto done;
    }
    ctx->user_search_base = user_search_base;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                           "userNameAttribute", "uid", &user_name_attribute);
    if (ret != EOK) goto done;
    ctx->user_name_attribute = user_name_attribute;

    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                           "userObjectClass", "posixAccount",
                           &user_object_class);
    if (ret != EOK) goto done;
    ctx->user_object_class = user_object_class;

/* TODO: better to have a blob object than a string here */
    ret = confdb_get_string(bectx->cdb, ctx, bectx->conf_path,
                           "defaultAuthtok", NULL, &default_authtok);
    if (ret != EOK) goto done;
    ctx->default_authtok = default_authtok;
    ctx->default_authtok_size = (default_authtok==NULL?0:strlen(default_authtok));



    *ops = &ldap_mod_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}
