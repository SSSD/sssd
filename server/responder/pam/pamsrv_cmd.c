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

static void pam_reply(struct cli_ctx *cctx, int pam_status, char *domain) {
    struct sss_cmd_ctx *nctx;
    int32_t ret_status = pam_status;
    uint8_t *body;
    size_t blen;
    int ret;
    int err = EOK;

    DEBUG(4, ("pam_reply get called.\n"));
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

    ret = sss_packet_grow(cctx->creq->out, sizeof(int) + strlen(domain)+1 );
    if (ret != EOK) {
        err = ret;
        goto done;
    }

    sss_packet_get_body(cctx->creq->out, &body, &blen);
    DEBUG(4, ("blen: %d\n", blen));
    memcpy(body, &ret_status, sizeof(int32_t));
    memcpy(body+sizeof(int32_t), domain, strlen(domain)+1);

done:
    sss_cmd_done(nctx);
}

static int pam_forwarder(struct cli_ctx *cctx, int pam_cmd)
{
    uint8_t *body;
    size_t blen;
    int ret;
    struct pam_data *pd;
    char *default_domain;

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
    ret=pam_parse_in_data(body, blen, pd);
    if( ret != 0 ) {
        talloc_free(pd);
        return EINVAL;
    }

    if (pd->domain == NULL) {
        ret = confdb_get_string(cctx->nctx->cdb, cctx, "config/domains",
                                "defaultDomain", "LOCAL", &default_domain);
        if (ret != EOK) {
            DEBUG(1, ("Failed to call confdb.\n"));
            talloc_free(pd);
            return ret;
        }
        pd->domain = default_domain;
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
