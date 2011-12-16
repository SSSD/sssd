/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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

#include <stdint.h>
#include <errno.h>
#include <talloc.h>

#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "responder/sudo/sudosrv_private.h"

static errno_t sudosrv_cmd_send_reply(struct sudo_cmd_ctx *cmd_ctx,
                                      uint8_t *response_body,
                                      size_t response_len)
{
    errno_t ret;
    uint8_t *packet_body = NULL;
    size_t packet_len = 0;
    struct cli_ctx *cli_ctx = cmd_ctx->cli_ctx;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ret = sss_packet_new(cli_ctx->creq, 0,
                         sss_packet_get_cmd(cli_ctx->creq->in),
                         &cli_ctx->creq->out);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unable to create a new packet [%d]; %s\n",
               ret, strerror(ret)));
        goto done;
    }

    ret = sss_packet_grow(cli_ctx->creq->out, response_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unable to create response: %s\n", strerror(ret)));
        goto done;
    }
    sss_packet_get_body(cli_ctx->creq->out, &packet_body, &packet_len);
    memcpy(packet_body, response_body, response_len);

    sss_packet_set_error(cli_ctx->creq->out, EOK);
    sss_cmd_done(cmd_ctx->cli_ctx, cmd_ctx);

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t sudosrv_cmd_send_error(TALLOC_CTX *mem_ctx,
                                      struct sudo_cmd_ctx *cmd_ctx,
                                      uint32_t error)
{
    uint8_t *response_body = NULL;
    size_t response_len = 0;
    int ret = EOK;

    ret = sudosrv_response_append_uint32(mem_ctx, error,
                                         &response_body, &response_len);
    if (ret != EOK) {
        return ret;
    }

    return sudosrv_cmd_send_reply(cmd_ctx, response_body, response_len);
}

errno_t sudosrv_cmd_done(struct sudo_dom_ctx *dctx, int ret)
{
    uint8_t *response_body = NULL;
    size_t response_len = 0;

    switch (ret) {
    case EOK:
        /* send result */
        ret = sudosrv_get_sudorules_build_response(dctx->cmd_ctx, SSS_SUDO_ERROR_OK,
                                                   dctx->res_count, dctx->res,
                                                   &response_body, &response_len);
        if (ret != EOK) {
            return EFAULT;
        }

        ret = sudosrv_cmd_send_reply(dctx->cmd_ctx, response_body, response_len);
        break;

    case EAGAIN:
        /* async processing, just return here */
        return EOK;

    case EFAULT:
        /* very bad error */
        return EFAULT;


    /* case ENOENT:
     * - means user not found
     * - send error ENOENT
     */

    default:
        /* send error */
        ret = sudosrv_cmd_send_error(dctx->cmd_ctx, dctx->cmd_ctx, ret);
        break;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Fatal error, killing connection!\n"));
        talloc_free(dctx->cmd_ctx->cli_ctx);
        return EFAULT;
    }

    return EOK;
}

static int sudosrv_cmd_get_sudorules(struct cli_ctx *cli_ctx)
{
    char *rawname = NULL;
    char *domname = NULL;
    uint8_t *query_body = NULL;
    size_t query_len = 0;
    int ret = EOK;
    struct sudo_cmd_ctx *cmd_ctx = NULL;
    struct sudo_dom_ctx *dctx = NULL;

    cmd_ctx = talloc_zero(cli_ctx, struct sudo_cmd_ctx);
    if (!cmd_ctx) {
        ret = ENOMEM;
        goto done;
    }
    cmd_ctx->cli_ctx = cli_ctx;

    dctx = talloc_zero(cmd_ctx, struct sudo_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmd_ctx = cmd_ctx;

    /* get query */
    sss_packet_get_body(cli_ctx->creq->in, &query_body, &query_len);
    if (query_len <= 0 || query_body == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Query is empty\n"));
        ret = EINVAL;
        goto done;
    }

    /* parse query */
    rawname = sudosrv_get_sudorules_parse_query(cmd_ctx,
                                                (const char*)query_body,
                                                 query_len);
    if (rawname == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unable to parse query: %s\n", strerror(ret)));
        goto done;
    }

    domname = NULL;
    ret = sss_parse_name(cmd_ctx, cli_ctx->rctx->names, rawname,
                         &domname, &cmd_ctx->username);
    if (ret != EOK) {
        DEBUG(2, ("Invalid name received [%s]\n", rawname));
        ret = ENOENT;
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, ("Requesting sudo rules for [%s] from [%s]\n",
          cmd_ctx->username, domname ? domname : "<ALL>"));

    if (domname) {
        dctx->domain = responder_get_domain(cli_ctx->rctx->domains, domname);
        if (!dctx->domain) {
            ret = ENOENT;
            goto done;
        }
    } else {
        /* this is a multidomain search */
        dctx->domain = cli_ctx->rctx->domains;
        cmd_ctx->check_next = true;
    }

    /* ok, find it ! */
    ret = sudosrv_get_sudorules(dctx);

done:
    return sudosrv_cmd_done(dctx, ret);
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version sudo_cli_protocol_version[] = {
        {0, NULL, NULL}
    };

    return sudo_cli_protocol_version;
}

struct sss_cmd_table *get_sudo_cmds(void) {
    static struct sss_cmd_table sudo_cmds[] = {
        {SSS_GET_VERSION, sss_cmd_get_version},
        {SSS_SUDO_GET_SUDORULES, sudosrv_cmd_get_sudorules},
        {SSS_CLI_NULL, NULL}
    };

    return sudo_cmds;
}
