#include <errno.h>
#include <talloc.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "responder/pam/pam_LOCAL_domain.h"
#include "responder/common/responder_common.h"
#include "responder/common/responder_cmd.h"
#include "responder/common/responder_packet.h"
#include "responder/pam/pamsrv.h"

static int pam_parse_in_data(uint8_t *body, size_t blen, struct pam_data *pd) {
    int start;
    int end;
    int last=blen-1;
    char *delim;

    start = end = 0;
    while ( end < last && body[end++]!='\0');
    pd->user = (char *) &body[start];

    delim = strchr(pd->user, SSS_DOMAIN_DELIM);
    if (delim != NULL ) {
        *delim = '\0';
        pd->domain = delim+1;
    } else {
        pd->domain =  NULL;
    }

    start = end;
    while ( end < last && body[end++]!='\0');
    pd->service = (char *) &body[start];

    start = end;
    while ( end < last && body[end++]!='\0');
    pd->tty = (char *) &body[start];

    start = end;
    while ( end < last && body[end++]!='\0');
    pd->ruser = (char *) &body[start];

    start = end;
    while ( end < last && body[end++]!='\0');
    pd->rhost = (char *) &body[start];

    start = end;
    pd->authtok_type = (int) body[start];
    start += sizeof(uint32_t);
    pd->authtok_size = (int) body[start];
    start += sizeof(uint32_t);
    end =  start+pd->authtok_size;
    if ( pd->authtok_size == 0 ) {
        pd->authtok = NULL;
    } else {
        if ( end <= blen ) {
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
    end =  start+pd->newauthtok_size;
    if ( pd->newauthtok_size == 0 ) {
        pd->newauthtok = NULL;
    } else {
        if ( end <= blen ) {
            pd->newauthtok = (uint8_t *) &body[start];
        } else {
            DEBUG(1, ("Invalid newauthtok size: %d\n", pd->newauthtok_size));
            return EINVAL;
        }
    }

    DEBUG_PAM_DATA(4, pd);

    return EOK;
}

static void pam_reply(struct pam_data *pd);
static void pam_reply_delay(struct tevent_context *ev, struct tevent_timer *te,
                            struct timeval tv, void *pvt)
{
    struct pam_data *pd;
    DEBUG(4, ("pam_reply_delay get called.\n"));

    pd = talloc_get_type(pvt, struct pam_data);

    pam_reply(pd);
}

static void pam_reply(struct pam_data *pd)
{
    struct cli_ctx *cctx;
    struct sss_cmd_ctx *nctx;
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

    DEBUG(4, ("pam_reply get called.\n"));

    if (pd->response_delay > 0) {
        ret = gettimeofday(&tv, NULL);
        if (ret != EOK) {
            DEBUG(0, ("gettimeofday failed [%d][%s].\n",
                      errno, strerror(errno)));
            err = ret;
            goto done;
        }
        tv.tv_sec += pd->response_delay;
        tv.tv_usec = 0;
        pd->response_delay = 0;

        te = tevent_add_timer(cctx->ev, cctx, tv, pam_reply_delay, pd);
        if (te == NULL) {
            DEBUG(0, ("Failed to add event pam_reply_delay.\n"));
            err = ENOMEM;
            goto done;
        }

        return;
    }

    cctx = pd->cctx;
    nctx = talloc_zero(cctx, struct sss_cmd_ctx);
    if (!nctx) {
        err = ENOMEM;
        goto done;
    }
    nctx->cctx = cctx;
    nctx->check_expiration = true;

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
    talloc_free(pd);
    sss_cmd_done(nctx);
}

static int pam_forwarder(struct cli_ctx *cctx, int pam_cmd)
{
    uint8_t *body;
    size_t blen;
    int ret;
    struct pam_data *pd;

    pd = talloc(cctx, struct pam_data);
    if (pd == NULL) return ENOMEM;

    sss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen >= sizeof(uint32_t) &&
        ((uint32_t *)(&body[blen - sizeof(uint32_t)]))[0] != END_OF_PAM_REQUEST) {
        DEBUG(1, ("Received data not terminated.\n"));
        talloc_free(pd);
        return EINVAL;
    }

    pd->cmd = pam_cmd;
    pd->cctx = cctx;
    ret=pam_parse_in_data(body, blen, pd);
    if( ret != 0 ) {
        talloc_free(pd);
        return EINVAL;
    }
    pd->response_delay = 0;
    pd->resp_list = NULL;

    if (pd->domain == NULL) {
        if (cctx->nctx->default_domain != NULL) {
            pd->domain = cctx->nctx->default_domain;
        } else {
            pd->domain = talloc_strdup(pd, "LOCAL");
        }
        DEBUG(4, ("Using default domain [%s].\n", pd->domain));
    }

    if ( strncasecmp(pd->domain,"LOCAL",5) == 0 ) {
        return LOCAL_pam_handler(cctx, pam_reply, pd);
    };

    ret=pam_dp_send_req(cctx, pam_reply, PAM_DP_TIMEOUT, pd);
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
