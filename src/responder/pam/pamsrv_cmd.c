/*
   SSSD

   PAM Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2009
   Copyright (C) Sumit Bose <sbose@redhat.com>	2009

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

#include <time.h>
#include "util/util.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "responder/common/negcache.h"
#include "providers/data_provider.h"
#include "responder/pam/pamsrv.h"
#include "db/sysdb.h"

static void pam_reply(struct pam_auth_req *preq);

static int extract_authtok(uint32_t *type, uint32_t *size, uint8_t **tok, uint8_t *body, size_t blen, size_t *c) {
    uint32_t data_size;

    if (blen-(*c) < 2*sizeof(uint32_t)) return EINVAL;

    memcpy(&data_size, &body[*c], sizeof(uint32_t));
    *c += sizeof(uint32_t);
    if (data_size < sizeof(uint32_t) || (*c)+(data_size) > blen) return EINVAL;
    *size = data_size - sizeof(uint32_t);

    memcpy(type, &body[*c], sizeof(uint32_t));
    *c += sizeof(uint32_t);

    *tok = body+(*c);

    *c += (*size);

    return EOK;
}

static int extract_string(char **var, uint8_t *body, size_t blen, size_t *c) {
    uint32_t size;
    uint8_t *str;

    if (blen-(*c) < sizeof(uint32_t)+1) return EINVAL;

    memcpy(&size, &body[*c], sizeof(uint32_t));
    *c += sizeof(uint32_t);
    if (*c+size > blen) return EINVAL;

    str = body+(*c);

    if (str[size-1]!='\0') return EINVAL;

    *c += size;

    *var = (char *) str;

    return EOK;
}

static int extract_uint32_t(uint32_t *var, uint8_t *body, size_t blen, size_t *c) {
    uint32_t size;

    if (blen-(*c) < 2*sizeof(uint32_t)) return EINVAL;

    memcpy(&size, &body[*c], sizeof(uint32_t));
    *c += sizeof(uint32_t);

    memcpy(var, &body[*c], sizeof(uint32_t));
    *c += sizeof(uint32_t);

    return EOK;
}

static int pam_parse_in_data_v2(struct sss_names_ctx *snctx,
                             struct pam_data *pd,
                             uint8_t *body, size_t blen)
{
    size_t c;
    uint32_t type;
    uint32_t size;
    char *pam_user;
    int ret;
    uint32_t terminator = SSS_END_OF_PAM_REQUEST;

    if (blen < 4*sizeof(uint32_t)+2 ||
        ((uint32_t *)body)[0] != SSS_START_OF_PAM_REQUEST ||
        memcmp(&body[blen - sizeof(uint32_t)], &terminator, sizeof(uint32_t)) != 0) {
        DEBUG(1, ("Received data is invalid.\n"));
        return EINVAL;
    }

    c = sizeof(uint32_t);
    do {
        memcpy(&type, &body[c], sizeof(uint32_t));
        c += sizeof(uint32_t);
        if (c > blen) return EINVAL;

        switch(type) {
            case SSS_PAM_ITEM_USER:
                ret = extract_string(&pam_user, body, blen, &c);
                if (ret != EOK) return ret;

                ret = sss_parse_name(pd, snctx, pam_user,
                                     &pd->domain, &pd->user);
                if (ret != EOK) return ret;
                break;
            case SSS_PAM_ITEM_SERVICE:
                ret = extract_string(&pd->service, body, blen, &c);
                if (ret != EOK) return ret;
                break;
            case SSS_PAM_ITEM_TTY:
                ret = extract_string(&pd->tty, body, blen, &c);
                if (ret != EOK) return ret;
                break;
            case SSS_PAM_ITEM_RUSER:
                ret = extract_string(&pd->ruser, body, blen, &c);
                if (ret != EOK) return ret;
                break;
            case SSS_PAM_ITEM_RHOST:
                ret = extract_string(&pd->rhost, body, blen, &c);
                if (ret != EOK) return ret;
                break;
            case SSS_PAM_ITEM_CLI_PID:
                ret = extract_uint32_t(&pd->cli_pid,
                                       body, blen, &c);
                if (ret != EOK) return ret;
                break;
            case SSS_PAM_ITEM_AUTHTOK:
                ret = extract_authtok(&pd->authtok_type, &pd->authtok_size,
                                      &pd->authtok, body, blen, &c);
                if (ret != EOK) return ret;
                break;
            case SSS_PAM_ITEM_NEWAUTHTOK:
                ret = extract_authtok(&pd->newauthtok_type,
                                      &pd->newauthtok_size,
                                      &pd->newauthtok, body, blen, &c);
                if (ret != EOK) return ret;
                break;
            case SSS_END_OF_PAM_REQUEST:
                if (c != blen) return EINVAL;
                break;
            default:
                DEBUG(1,("Ignoring unknown data type [%d].\n", type));
                size = ((uint32_t *)&body[c])[0];
                c += size+sizeof(uint32_t);
        }
    } while(c < blen);

    if (pd->user == NULL || *pd->user == '\0') return EINVAL;

    DEBUG_PAM_DATA(4, pd);

    return EOK;

}

static int pam_parse_in_data_v3(struct sss_names_ctx *snctx,
                             struct pam_data *pd,
                             uint8_t *body, size_t blen)
{
    int ret;

    ret = pam_parse_in_data_v2(snctx, pd, body, blen);
    if (ret != EOK) {
        DEBUG(1, ("pam_parse_in_data_v2 failed.\n"));
        return ret;
    }

    if (pd->cli_pid == 0) {
        DEBUG(1, ("Missing client PID.\n"));
        return EINVAL;
    }

    return EOK;
}

static int pam_parse_in_data(struct sss_names_ctx *snctx,
                             struct pam_data *pd,
                             uint8_t *body, size_t blen)
{
    int start;
    int end;
    int last;
    int ret;

    last = blen - 1;
    end = 0;

    /* user name */
    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;

    ret = sss_parse_name(pd, snctx, (char *)&body[start], &pd->domain, &pd->user);
    if (ret != EOK) return ret;

    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;
    pd->service = (char *) &body[start];

    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;
    pd->tty = (char *) &body[start];

    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;
    pd->ruser = (char *) &body[start];

    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;
    pd->rhost = (char *) &body[start];

    start = end;
    pd->authtok_type = (int) body[start];

    start += sizeof(uint32_t);
    pd->authtok_size = (int) body[start];

    start += sizeof(uint32_t);
    end = start + pd->authtok_size;
    if (pd->authtok_size == 0) {
        pd->authtok = NULL;
    } else {
        if (end <= blen) {
            pd->authtok = (uint8_t *) &body[start];
        } else {
            DEBUG(1, ("Invalid authtok size: %d\n", pd->authtok_size));
            return EINVAL;
        }
    }

    start = end;
    pd->newauthtok_type = (int) body[start];

    start += sizeof(uint32_t);
    pd->newauthtok_size = (int) body[start];

    start += sizeof(uint32_t);
    end = start + pd->newauthtok_size;

    if (pd->newauthtok_size == 0) {
        pd->newauthtok = NULL;
    } else {
        if (end <= blen) {
            pd->newauthtok = (uint8_t *) &body[start];
        } else {
            DEBUG(1, ("Invalid newauthtok size: %d\n", pd->newauthtok_size));
            return EINVAL;
        }
    }

    DEBUG_PAM_DATA(4, pd);

    return EOK;
}

/*=Save-Last-Login-State===================================================*/

struct set_last_login_state {
    struct tevent_context *ev;
    struct sysdb_ctx *dbctx;

    struct sss_domain_info *dom;
    const char *username;
    struct sysdb_attrs *attrs;

    struct sysdb_handle *handle;

    struct ldb_result *res;
};

static void set_last_login_trans_done(struct tevent_req *subreq);
static void set_last_login_attrs_done(struct tevent_req *subreq);
static void set_last_login_done(struct tevent_req *subreq);

static struct tevent_req *set_last_login_send(TALLOC_CTX *memctx,
                                              struct tevent_context *ev,
                                              struct sysdb_ctx *dbctx,
                                              struct sss_domain_info *dom,
                                              const char *username,
                                              struct sysdb_attrs *attrs)
{
    struct tevent_req *req, *subreq;
    struct set_last_login_state *state;

    req = tevent_req_create(memctx, &state, struct set_last_login_state);
    if (!req) {
        return NULL;
    }

    state->ev = ev;
    state->dbctx = dbctx;
    state->dom = dom;
    state->username = username;
    state->attrs = attrs;
    state->handle = NULL;

    subreq = sysdb_transaction_send(state, state->ev, state->dbctx);
    if (!subreq) {
        talloc_free(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, set_last_login_trans_done, req);

    return req;
}

static void set_last_login_trans_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct set_last_login_state *state = tevent_req_data(req,
                                                struct set_last_login_state);
    int ret;

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("Unable to acquire sysdb transaction lock\n"));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_set_user_attr_send(state, state->ev, state->handle,
                                      state->dom, state->username,
                                      state->attrs, SYSDB_MOD_REP);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, set_last_login_attrs_done, req);
}

static void set_last_login_attrs_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct set_last_login_state *state = tevent_req_data(req,
                                                struct set_last_login_state);
    int ret;

    ret = sysdb_set_user_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(4, ("set_user_attr_callback, status [%d][%s]\n",
                  ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, set_last_login_done, req);
}

static void set_last_login_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_transaction_commit_recv(subreq);
    if (ret != EOK) {
        DEBUG(2, ("set_last_login failed.\n"));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int set_last_login_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/*=========================================================================*/


static void set_last_login_reply(struct tevent_req *req);

static errno_t set_last_login(struct pam_auth_req *preq)
{
    struct tevent_req *req;
    struct sysdb_ctx *dbctx;
    struct sysdb_attrs *attrs;
    errno_t ret;

    attrs = sysdb_new_attrs(preq);
    if (!attrs) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_ONLINE_AUTH, time(NULL));
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_LOGIN, time(NULL));
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_get_ctx_from_list(preq->cctx->rctx->db_list, preq->domain,
                                  &dbctx);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb context not found for this domain!\n"));
        goto fail;
    }

    req = set_last_login_send(preq, preq->cctx->ev, dbctx,
                              preq->domain, preq->pd->user, attrs);
    if (!req) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(req, set_last_login_reply, preq);

    return EOK;

fail:
    return ret;
}

static void set_last_login_reply(struct tevent_req *req)
{
    struct pam_auth_req *preq = tevent_req_callback_data(req,
                                                         struct pam_auth_req);
    int ret;

    ret = set_last_login_recv(req);
    if (ret != EOK) {
        preq->pd->pam_status = PAM_SYSTEM_ERR;
    } else {
        preq->pd->last_auth_saved = true;
    }

    preq->callback(preq);
}

static void pam_reply_delay(struct tevent_context *ev, struct tevent_timer *te,
                            struct timeval tv, void *pvt)
{
    struct pam_auth_req *preq;

    DEBUG(4, ("pam_reply_delay get called.\n"));

    preq = talloc_get_type(pvt, struct pam_auth_req);

    pam_reply(preq);
}

static void pam_cache_auth_done(struct tevent_req *req);

static void pam_reply(struct pam_auth_req *preq)
{
    struct cli_ctx *cctx;
    uint8_t *body;
    size_t blen;
    int ret;
    int32_t resp_c;
    int32_t resp_size;
    struct response_data *resp;
    int p;
    struct timeval tv;
    struct tevent_timer *te;
    struct pam_data *pd;
    struct tevent_req *req;
    struct sysdb_ctx *sysdb;
    struct pam_ctx *pctx;
    uint32_t user_info_type;

    pd = preq->pd;
    cctx = preq->cctx;

    DEBUG(4, ("pam_reply get called.\n"));

    if (pd->pam_status == PAM_AUTHINFO_UNAVAIL) {
        switch(pd->cmd) {
            case SSS_PAM_AUTHENTICATE:
                if ((preq->domain != NULL) &&
                    (preq->domain->cache_credentials == true) &&
                    (pd->offline_auth == false)) {

                    /* do auth with offline credentials */
                    pd->offline_auth = true;

                    ret = sysdb_get_ctx_from_list(preq->cctx->rctx->db_list,
                                                  preq->domain, &sysdb);
                    if (ret != EOK) {
                        DEBUG(0, ("Fatal: Sysdb CTX not found for "
                                  "domain [%s]!\n", preq->domain->name));
                        goto done;
                    }

                    pctx = talloc_get_type(preq->cctx->rctx->pvt_ctx,
                                           struct pam_ctx);

                    req = sysdb_cache_auth_send(preq, preq->cctx->ev, sysdb,
                                                preq->domain, pd->user,
                                                pd->authtok, pd->authtok_size,
                                                pctx->rctx->cdb, false);
                    if (req == NULL) {
                        DEBUG(1, ("Failed to setup offline auth.\n"));
                        /* this error is not fatal, continue */
                    } else {
                        tevent_req_set_callback(req, pam_cache_auth_done, preq);
                        return;
                    }
                }
                break;
            case SSS_PAM_CHAUTHTOK_PRELIM:
            case SSS_PAM_CHAUTHTOK:
                DEBUG(5, ("Password change not possible while offline.\n"));
                pd->pam_status = PAM_AUTHTOK_ERR;
                user_info_type = SSS_PAM_USER_INFO_OFFLINE_CHPASS;
                pam_add_response(pd, SSS_PAM_USER_INFO, sizeof(uint32_t),
                                 (const uint8_t *) &user_info_type);
                break;
/* TODO: we need the pam session cookie here to make sure that cached
 * authentication was successful */
            case SSS_PAM_SETCRED:
            case SSS_PAM_ACCT_MGMT:
            case SSS_PAM_OPEN_SESSION:
            case SSS_PAM_CLOSE_SESSION:
                DEBUG(2, ("Assuming offline authentication setting status for "
                          "pam call %d to PAM_SUCCESS.\n", pd->cmd));
                pd->pam_status = PAM_SUCCESS;
                break;
            default:
                DEBUG(1, ("Unknown PAM call [%d].\n", pd->cmd));
                pd->pam_status = PAM_MODULE_UNKNOWN;
        }
    }

    if (pd->response_delay > 0) {
        ret = gettimeofday(&tv, NULL);
        if (ret != EOK) {
            DEBUG(1, ("gettimeofday failed [%d][%s].\n",
                      errno, strerror(errno)));
            goto done;
        }
        tv.tv_sec += pd->response_delay;
        tv.tv_usec = 0;
        pd->response_delay = 0;

        te = tevent_add_timer(cctx->ev, cctx, tv, pam_reply_delay, preq);
        if (te == NULL) {
            DEBUG(1, ("Failed to add event pam_reply_delay.\n"));
            goto done;
        }

        return;
    }

    /* If this was a successful login, save the lastLogin time */
    if (pd->cmd == SSS_PAM_AUTHENTICATE &&
        pd->pam_status == PAM_SUCCESS &&
        preq->domain->cache_credentials &&
        !pd->offline_auth &&
        !pd->last_auth_saved &&
        NEED_CHECK_PROVIDER(preq->domain->provider)) {
        ret = set_last_login(preq);
        if (ret != EOK) {
            goto done;
        }

        return;
    }

    ret = sss_packet_new(cctx->creq, 0, sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        goto done;
    }

    if (pd->domain != NULL) {
        pam_add_response(pd, SSS_PAM_DOMAIN_NAME, strlen(pd->domain)+1,
                         (uint8_t *) pd->domain);
    }

    resp_c = 0;
    resp_size = 0;
    resp = pd->resp_list;
    while(resp != NULL) {
        resp_c++;
        resp_size += resp->len;
        resp = resp->next;
    }

    ret = sss_packet_grow(cctx->creq->out, sizeof(int32_t) +
                                           sizeof(int32_t) +
                                           resp_c * 2* sizeof(int32_t) +
                                           resp_size);
    if (ret != EOK) {
        goto done;
    }

    sss_packet_get_body(cctx->creq->out, &body, &blen);
    DEBUG(4, ("blen: %d\n", blen));
    p = 0;

    memcpy(&body[p], &pd->pam_status, sizeof(int32_t));
    p += sizeof(int32_t);

    memcpy(&body[p], &resp_c, sizeof(int32_t));
    p += sizeof(int32_t);

    resp = pd->resp_list;
    while(resp != NULL) {
        memcpy(&body[p], &resp->type, sizeof(int32_t));
        p += sizeof(int32_t);
        memcpy(&body[p], &resp->len, sizeof(int32_t));
        p += sizeof(int32_t);
        memcpy(&body[p], resp->data, resp->len);
        p += resp->len;

        resp = resp->next;
    }

done:
    sss_cmd_done(cctx, preq);
}

static void pam_cache_auth_done(struct tevent_req *req)
{
    int ret;
    struct pam_auth_req *preq = tevent_req_callback_data(req,
                                                         struct pam_auth_req);
    uint32_t resp_type;
    size_t resp_len;
    uint8_t *resp;
    time_t expire_date = 0;
    time_t delayed_until = -1;
    long long dummy;

    ret = sysdb_cache_auth_recv(req, &expire_date, &delayed_until);
    talloc_zfree(req);

    switch (ret) {
        case EOK:
            preq->pd->pam_status = PAM_SUCCESS;

            resp_type = SSS_PAM_USER_INFO_OFFLINE_AUTH;
            resp_len = sizeof(uint32_t) + sizeof(long long);
            resp = talloc_size(preq->pd, resp_len);
            if (resp == NULL) {
                DEBUG(1, ("talloc_size failed, cannot prepare user info.\n"));
            } else {
                memcpy(resp, &resp_type, sizeof(uint32_t));
                dummy = (long long) expire_date;
                memcpy(resp+sizeof(uint32_t), &dummy, sizeof(long long));
                ret = pam_add_response(preq->pd, SSS_PAM_USER_INFO, resp_len,
                                       (const uint8_t *) resp);
                if (ret != EOK) {
                    DEBUG(1, ("pam_add_response failed.\n"));
                }
            }
            break;
        case ENOENT:
            preq->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
            break;
        case EINVAL:
            preq->pd->pam_status = PAM_AUTH_ERR;
            break;
        case EACCES:
            preq->pd->pam_status = PAM_PERM_DENIED;
            if (delayed_until >= 0) {
                resp_type = SSS_PAM_USER_INFO_OFFLINE_AUTH_DELAYED;
                resp_len = sizeof(uint32_t) + sizeof(long long);
                resp = talloc_size(preq->pd, resp_len);
                if (resp == NULL) {
                    DEBUG(1, ("talloc_size failed, cannot prepare user info.\n"));
                } else {
                    memcpy(resp, &resp_type, sizeof(uint32_t));
                    dummy = (long long) delayed_until;
                    memcpy(resp+sizeof(uint32_t), &dummy, sizeof(long long));
                    ret = pam_add_response(preq->pd, SSS_PAM_USER_INFO, resp_len,
                                           (const uint8_t *) resp);
                    if (ret != EOK) {
                        DEBUG(1, ("pam_add_response failed.\n"));
                    }
                }
            }
            break;
        default:
            preq->pd->pam_status = PAM_SYSTEM_ERR;
    }

    pam_reply(preq);
    return;
}

static void pam_check_user_dp_callback(uint16_t err_maj, uint32_t err_min,
                                       const char *err_msg, void *ptr);
static void pam_check_user_callback(void *ptr, int status,
                                    struct ldb_result *res);
static void pam_dom_forwarder(struct pam_auth_req *preq);

/* TODO: we should probably return some sort of cookie that is set in the
 * PAM_ENVIRONMENT, so that we can save performing some calls and cache
 * data. */

static int pam_forwarder(struct cli_ctx *cctx, int pam_cmd)
{
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct pam_auth_req *preq;
    struct pam_data *pd;
    uint8_t *body;
    size_t blen;
    int timeout;
    int ret;
    errno_t ncret;
    struct pam_ctx *pctx =
            talloc_get_type(cctx->rctx->pvt_ctx, struct pam_ctx);
    uint32_t terminator = SSS_END_OF_PAM_REQUEST;
    preq = talloc_zero(cctx, struct pam_auth_req);
    if (!preq) {
        return ENOMEM;
    }
    preq->cctx = cctx;

    preq->pd = talloc_zero(preq, struct pam_data);
    if (!preq->pd) {
        talloc_free(preq);
        return ENOMEM;
    }
    pd = preq->pd;

    sss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen >= sizeof(uint32_t) &&
        memcmp(&body[blen - sizeof(uint32_t)], &terminator, sizeof(uint32_t)) != 0) {
        DEBUG(1, ("Received data not terminated.\n"));
        ret = EINVAL;
        goto done;
    }

    pd->cmd = pam_cmd;
    pd->priv = cctx->priv;

    switch (cctx->cli_protocol_version->version) {
        case 1:
            ret = pam_parse_in_data(cctx->rctx->names, pd, body, blen);
            break;
        case 2:
            ret = pam_parse_in_data_v2(cctx->rctx->names, pd, body, blen);
            break;
        case 3:
            ret = pam_parse_in_data_v3(cctx->rctx->names, pd, body, blen);
            break;
        default:
            DEBUG(1, ("Illegal protocol version [%d].\n",
                      cctx->cli_protocol_version->version));
            ret = EINVAL;
    }
    if (ret != EOK) {
        ret = EINVAL;
        goto done;
    }

    /* now check user is valid */
    if (pd->domain) {
        for (dom = cctx->rctx->domains; dom; dom = dom->next) {
            if (strcasecmp(dom->name, pd->domain) == 0) break;
        }
        if (!dom) {
            ret = ENOENT;
            goto done;
        }
        preq->domain = dom;
    }
    else {
        for (dom = preq->cctx->rctx->domains; dom; dom = dom->next) {
            if (dom->fqnames) continue;

            ncret = sss_ncache_check_user(pctx->ncache, pctx->neg_timeout,
                                          dom->name, pd->user);
            if (ncret == ENOENT) {
                /* User not found in the negative cache
                 * Proceed with PAM actions
                 */
                break;
            }

            /* Try the next domain */
            DEBUG(4, ("User [%s@%s] filtered out (negative cache). "
                      "Trying next domain.\n",
                      pd->user, dom->name));
        }
        if (!dom) {
            ret = ENOENT;
            goto done;
        }
        preq->domain = dom;
    }

    if (preq->domain->provider == NULL) {
        DEBUG(1, ("Domain [%s] has no auth provider.\n", preq->domain->name));
        ret = EINVAL;
        goto done;
    }

    /* When auth is requested always search the provider first,
     * do not rely on cached data unless the provider is completely
     * offline */
    if (NEED_CHECK_PROVIDER(preq->domain->provider) &&
        (pam_cmd == SSS_PAM_AUTHENTICATE || pam_cmd == SSS_PAM_SETCRED)) {

        /* no need to re-check later on */
        preq->check_provider = false;
        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        ret = sss_dp_send_acct_req(preq->cctx->rctx, preq,
                                   pam_check_user_dp_callback, preq,
                                   timeout, preq->domain->name,
                                   false, SSS_DP_INITGROUPS,
                                   preq->pd->user, 0);
    }
    else {
        preq->check_provider = NEED_CHECK_PROVIDER(preq->domain->provider);

        ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                      preq->domain, &sysdb);
        if (ret != EOK) {
            DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
            goto done;
        }
        ret = sysdb_getpwnam(preq, sysdb,
                             preq->domain, preq->pd->user,
                             pam_check_user_callback, preq);
    }

done:
    if (ret != EOK) {
        switch (ret) {
        case ENOENT:
            pd->pam_status = PAM_USER_UNKNOWN;
            break;
        default:
            pd->pam_status = PAM_SYSTEM_ERR;
        }
        pam_reply(preq);
    }
    return EOK;
}

static void pam_check_user_dp_callback(uint16_t err_maj, uint32_t err_min,
                                       const char *err_msg, void *ptr)
{
    struct pam_auth_req *preq = talloc_get_type(ptr, struct pam_auth_req);
    struct sysdb_ctx *sysdb;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    /* always try to see if we have the user in cache even if the provider
     * returned an error */
    ret = sysdb_get_ctx_from_list(preq->cctx->rctx->db_list,
                                  preq->domain, &sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
        goto done;
    }
    ret = sysdb_getpwnam(preq, sysdb,
                         preq->domain, preq->pd->user,
                         pam_check_user_callback, preq);

done:
    if (ret != EOK) {
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        pam_reply(preq);
    }
}

static void pam_check_user_callback(void *ptr, int status,
                                    struct ldb_result *res)
{
    struct pam_auth_req *preq = talloc_get_type(ptr, struct pam_auth_req);
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    uint64_t cacheExpire;
    bool call_provider = false;
    time_t timeout;
    int ret;

    if (status != LDB_SUCCESS) {
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        pam_reply(preq);
        return;
    }

    timeout = SSS_CLI_SOCKET_TIMEOUT/2;

    if (preq->check_provider) {
        switch (res->count) {
        case 0:
            call_provider = true;
            break;

        case 1:
            cacheExpire = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                      SYSDB_CACHE_EXPIRE, 0);
            if (cacheExpire < time(NULL)) {
                call_provider = true;
            }
            break;

        default:
            DEBUG(1, ("check user call returned more than one result !?!\n"));
            preq->pd->pam_status = PAM_SYSTEM_ERR;
            pam_reply(preq);
            return;
        }
    }

    if (call_provider) {

        /* dont loop forever :-) */
        preq->check_provider = false;

        /* keep around current data in case backend is offline */
        if (res->count) {
            preq->data = talloc_steal(preq, res);
        }

        ret = sss_dp_send_acct_req(preq->cctx->rctx, preq,
                                   pam_check_user_dp_callback, preq,
                                   timeout, preq->domain->name,
                                   false, SSS_DP_USER,
                                   preq->pd->user, 0);
        if (ret != EOK) {
            DEBUG(3, ("Failed to dispatch request: %d(%s)\n",
                      ret, strerror(ret)));
            preq->pd->pam_status = PAM_SYSTEM_ERR;
            pam_reply(preq);
        }
        return;
    }

    switch (res->count) {
    case 0:
        if (!preq->pd->domain) {
            /* search next as the domain was unknown */

            ret = EOK;

            /* skip domains that require FQnames or have negative caches */
            for (dom = preq->domain->next; dom; dom = dom->next) {

                if (dom->fqnames) continue;

#if HAVE_NEG_CACHE
                ncret = nss_ncache_check_user(nctx->ncache,
                                              nctx->neg_timeout,
                                              dom->name, cmdctx->name);
                if (ncret == ENOENT) break;

                neghit = true;
#endif
                break;
            }
#if HAVE_NEG_CACHE
            /* reset neghit if we still have a domain to check */
            if (dom) neghit = false;

           if (neghit) {
                DEBUG(2, ("User [%s] does not exist! (negative cache)\n",
                          cmdctx->name));
                ret = ENOENT;
            }
#endif
            if (dom == NULL) {
                DEBUG(2, ("No matching domain found for [%s], fail!\n",
                          preq->pd->user));
                ret = ENOENT;
            }

            if (ret == EOK) {
                preq->domain = dom;
                preq->data = NULL;

                DEBUG(4, ("Requesting info for [%s@%s]\n",
                          preq->pd->user, preq->domain->name));

                /* When auth is requested always search the provider first,
                 * do not rely on cached data unless the provider is
                 * completely offline */
                if (NEED_CHECK_PROVIDER(preq->domain->provider) &&
                    (preq->pd->cmd == SSS_PAM_AUTHENTICATE ||
                     preq->pd->cmd == SSS_PAM_SETCRED)) {

                    /* no need to re-check later on */
                    preq->check_provider = false;

                    ret = sss_dp_send_acct_req(preq->cctx->rctx, preq,
                                               pam_check_user_dp_callback,
                                               preq, timeout,
                                               preq->domain->name,
                                               false, SSS_DP_USER,
                                               preq->pd->user, 0);
                }
                else {
                    preq->check_provider = NEED_CHECK_PROVIDER(preq->domain->provider);

                    ret = sysdb_get_ctx_from_list(preq->cctx->rctx->db_list,
                                                  preq->domain, &sysdb);
                    if (ret != EOK) {
                        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
                        preq->pd->pam_status = PAM_SYSTEM_ERR;
                        pam_reply(preq);
                        return;
                    }
                    ret = sysdb_getpwnam(preq, sysdb,
                                         preq->domain, preq->pd->user,
                                         pam_check_user_callback, preq);
                }
                if (ret != EOK) {
                    DEBUG(1, ("Failed to make request to our cache!\n"));
                }
            }

            /* we made another call, end here */
            if (ret == EOK) return;
        }
        else {
            ret = ENOENT;
        }

        DEBUG(2, ("No results for check user call\n"));

#if HAVE_NEG_CACHE
        /* set negative cache only if not result of cache check */
        if (!neghit) {
            ret = nss_ncache_set_user(nctx->ncache, false,
                                      dctx->domain->name, cmdctx->name);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
        }
#endif

        if (ret != EOK) {
            if (ret == ENOENT) {
                preq->pd->pam_status = PAM_USER_UNKNOWN;
            } else {
                preq->pd->pam_status = PAM_SYSTEM_ERR;
            }
            pam_reply(preq);
            return;
        }
        break;

    case 1:

        /* BINGO */
        pam_dom_forwarder(preq);
        return;

    default:
        DEBUG(1, ("check user call returned more than one result !?!\n"));
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        pam_reply(preq);
    }
}

static void pam_dom_forwarder(struct pam_auth_req *preq)
{
    int ret;

    if (!preq->pd->domain) {
        preq->pd->domain = preq->domain->name;
    }

    if (!NEED_CHECK_PROVIDER(preq->domain->provider)) {
        preq->callback = pam_reply;
        ret = LOCAL_pam_handler(preq);
    }
    else {
        preq->callback = pam_reply;
        ret = pam_dp_send_req(preq, SSS_CLI_SOCKET_TIMEOUT/2);
        DEBUG(4, ("pam_dp_send_req returned %d\n", ret));
    }

    if (ret != EOK) {
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        pam_reply(preq);
    }
}

static int pam_cmd_authenticate(struct cli_ctx *cctx) {
    DEBUG(4, ("entering pam_cmd_authenticate\n"));
    return pam_forwarder(cctx, SSS_PAM_AUTHENTICATE);
}

static int pam_cmd_setcred(struct cli_ctx *cctx) {
    DEBUG(4, ("entering pam_cmd_setcred\n"));
    return pam_forwarder(cctx, SSS_PAM_SETCRED);
}

static int pam_cmd_acct_mgmt(struct cli_ctx *cctx) {
    DEBUG(4, ("entering pam_cmd_acct_mgmt\n"));
    return pam_forwarder(cctx, SSS_PAM_ACCT_MGMT);
}

static int pam_cmd_open_session(struct cli_ctx *cctx) {
    DEBUG(4, ("entering pam_cmd_open_session\n"));
    return pam_forwarder(cctx, SSS_PAM_OPEN_SESSION);
}

static int pam_cmd_close_session(struct cli_ctx *cctx) {
    DEBUG(4, ("entering pam_cmd_close_session\n"));
    return pam_forwarder(cctx, SSS_PAM_CLOSE_SESSION);
}

static int pam_cmd_chauthtok(struct cli_ctx *cctx) {
    DEBUG(4, ("entering pam_cmd_chauthtok\n"));
    return pam_forwarder(cctx, SSS_PAM_CHAUTHTOK);
}

static int pam_cmd_chauthtok_prelim(struct cli_ctx *cctx) {
    DEBUG(4, ("entering pam_cmd_chauthtok_prelim\n"));
    return pam_forwarder(cctx, SSS_PAM_CHAUTHTOK_PRELIM);
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version pam_cli_protocol_version[] = {
        {3, "2009-09-14", "make cli_pid mandatory"},
        {2, "2009-05-12", "new format <type><size><data>"},
        {1, "2008-09-05", "initial version, \\0 terminated strings"},
        {0, NULL, NULL}
    };

    return pam_cli_protocol_version;
}

struct sss_cmd_table *get_pam_cmds(void)
{
    static struct sss_cmd_table sss_cmds[] = {
        {SSS_GET_VERSION, sss_cmd_get_version},
        {SSS_PAM_AUTHENTICATE, pam_cmd_authenticate},
        {SSS_PAM_SETCRED, pam_cmd_setcred},
        {SSS_PAM_ACCT_MGMT, pam_cmd_acct_mgmt},
        {SSS_PAM_OPEN_SESSION, pam_cmd_open_session},
        {SSS_PAM_CLOSE_SESSION, pam_cmd_close_session},
        {SSS_PAM_CHAUTHTOK, pam_cmd_chauthtok},
        {SSS_PAM_CHAUTHTOK_PRELIM, pam_cmd_chauthtok_prelim},
        {SSS_CLI_NULL, NULL}
    };

    return sss_cmds;
}
