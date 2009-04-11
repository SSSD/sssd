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

#include <errno.h>
#include <talloc.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"
#include "responder/pam/pamsrv.h"

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

static void pam_reply(struct pam_auth_req *preq);
static void pam_reply_delay(struct tevent_context *ev, struct tevent_timer *te,
                            struct timeval tv, void *pvt)
{
    struct pam_auth_req *preq;

    DEBUG(4, ("pam_reply_delay get called.\n"));

    preq = talloc_get_type(pvt, struct pam_auth_req);

    pam_reply(preq);
}

static void pam_reply(struct pam_auth_req *preq)
{
    struct cli_ctx *cctx;
    uint8_t *body;
    size_t blen;
    int ret;
    int err = EOK;
    int32_t resp_c;
    int32_t resp_size;
    struct response_data *resp;
    int p;
    struct timeval tv;
    struct tevent_timer *te;
    struct pam_data *pd;

    pd = preq->pd;

    DEBUG(4, ("pam_reply get called.\n"));

    if ((pd->cmd == SSS_PAM_AUTHENTICATE) &&
        (preq->domain->cache_credentials == true) &&
        (pd->offline_auth == false)) {

        if (pd->pam_status == PAM_SUCCESS) {
            pd->offline_auth = true;
            preq->callback = pam_reply;
            ret = pam_cache_credentials(preq);
            if (ret == EOK) {
                return;
            }
            else {
                DEBUG(0, ("Failed to cache credentials"));
                /* this error is not fatal, continue */
            }
        }

        if (pd->pam_status == PAM_AUTHINFO_UNAVAIL) {
            /* do auth with offline credentials */
            pd->offline_auth = true;
            preq->callback = pam_reply;
            ret = pam_cache_auth(preq);
            if (ret == EOK) {
                return;
            }
            else {
                DEBUG(1, ("Failed to setup offline auth"));
                /* this error is not fatal, continue */
            }
        }
    }

    if (pd->response_delay > 0) {
        ret = gettimeofday(&tv, NULL);
        if (ret != EOK) {
            DEBUG(1, ("gettimeofday failed [%d][%s].\n",
                      errno, strerror(errno)));
            err = ret;
            goto done;
        }
        tv.tv_sec += pd->response_delay;
        tv.tv_usec = 0;
        pd->response_delay = 0;

        te = tevent_add_timer(cctx->ev, cctx, tv, pam_reply_delay, preq);
        if (te == NULL) {
            DEBUG(1, ("Failed to add event pam_reply_delay.\n"));
            err = ENOMEM;
            goto done;
        }

        return;
    }

    cctx = preq->cctx;

    ret = sss_packet_new(cctx->creq, 0, sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        err = ret;
        goto done;
    }

    if (pd->domain != NULL) {
        pam_add_response(pd, PAM_DOMAIN_NAME, strlen(pd->domain)+1,
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

    ret = sss_packet_grow(cctx->creq->out, sizeof(int32_t) + strlen(pd->domain)+1 +
                                           sizeof(int32_t) +
                                           resp_c * 2* sizeof(int32_t) +
                                           resp_size);
    if (ret != EOK) {
        err = ret;
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

static int pam_forwarder(struct cli_ctx *cctx, int pam_cmd)
{
    struct sss_domain_info *dom;
    uint8_t *body;
    size_t blen;
    int ret;
    struct pam_auth_req *preq;
    struct pam_data *pd;

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
        ((uint32_t *)(&body[blen - sizeof(uint32_t)]))[0] != END_OF_PAM_REQUEST) {
        DEBUG(1, ("Received data not terminated.\n"));
        talloc_free(preq);
        return EINVAL;
    }

    pd->cmd = pam_cmd;
    ret = pam_parse_in_data(cctx->rctx->names, pd, body, blen);
    if (ret != 0) {
        talloc_free(preq);
        return EINVAL;
    }

    if (pd->domain) {
        for (dom = cctx->rctx->domains; dom; dom = dom->next) {
            if (strcasecmp(dom->name, pd->domain) == 0) break;
        }
        if (!dom) {
            talloc_free(preq);
            return EINVAL;
        }
        preq->domain = dom;
    }
    else {
        DEBUG(4, ("Domain not provided, using default.\n"));
        preq->domain = cctx->rctx->domains;
        pd->domain = preq->domain->name;
    }

    if (!preq->domain->provider) {
        preq->callback = pam_reply;
        return LOCAL_pam_handler(preq);
    };

    preq->callback = pam_reply;
    ret = pam_dp_send_req(preq, PAM_DP_TIMEOUT);
    DEBUG(4, ("pam_dp_send_req returned %d\n", ret));

    return ret;
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

struct sss_cmd_table *register_sss_cmds(void) {
    static struct sss_cmd_table sss_cmds[] = {
        {SSS_GET_VERSION, sss_cmd_get_version},
        {SSS_PAM_AUTHENTICATE, pam_cmd_authenticate},
        {SSS_PAM_SETCRED, pam_cmd_setcred},
        {SSS_PAM_ACCT_MGMT, pam_cmd_acct_mgmt},
        {SSS_PAM_OPEN_SESSION, pam_cmd_open_session},
        {SSS_PAM_CLOSE_SESSION, pam_cmd_close_session},
        {SSS_PAM_CHAUTHTOK, pam_cmd_chauthtok},
        {SSS_CLI_NULL, NULL}
    };

    return sss_cmds;
}
