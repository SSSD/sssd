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

#include "config.h"

#include <stdint.h>
#include <errno.h>
#include <talloc.h>

#include "util/util.h"
#include "util/util_creds.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "responder/sudo/sudosrv_private.h"
#include "db/sysdb_sudo.h"
#include "sss_client/sss_cli.h"
#include "responder/common/negcache.h"

static errno_t sudosrv_cmd_send_reply(struct sudo_cmd_ctx *cmd_ctx,
                                      uint8_t *response_body,
                                      size_t response_len)
{
    errno_t ret;
    uint8_t *packet_body = NULL;
    size_t packet_len = 0;
    struct cli_ctx *cli_ctx = cmd_ctx->cli_ctx;
    struct cli_protocol *pctx;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to create a new packet [%d]; %s\n",
               ret, strerror(ret));
        goto done;
    }

    ret = sss_packet_grow(pctx->creq->out, response_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to create response: %s\n", strerror(ret));
        goto done;
    }
    sss_packet_get_body(pctx->creq->out, &packet_body, &packet_len);
    memcpy(packet_body, response_body, response_len);

    sss_packet_set_error(pctx->creq->out, EOK);
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

    if (error == EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Everything is fine but we are "
              "returning error?\n");
        return EFAULT;
    }

    ret = sudosrv_build_response(mem_ctx, error, 0, NULL,
                                 &response_body, &response_len);
    if (ret != EOK) {
        return ret;
    }

    return sudosrv_cmd_send_reply(cmd_ctx, response_body, response_len);
}

errno_t sudosrv_cmd_reply(struct sudo_cmd_ctx *cmd_ctx, int ret)
{
    uint8_t *response_body = NULL;
    size_t response_len = 0;
    uint32_t num_rules = cmd_ctx->num_rules;
    struct sysdb_attrs **rules = cmd_ctx->rules;

    switch (ret) {
    case EOK:
        /*
         * Parent of cmd_ctx->rules is in-memory cache, we must not talloc_free it!
         */
        if (cmd_ctx->sudo_ctx->timed) {
            /* filter rules by time */

            DEBUG(SSSDBG_TRACE_FUNC, "Applying time restrictions on"
                                      "%u rules\n", cmd_ctx->num_rules);

            ret = sysdb_sudo_filter_rules_by_time(cmd_ctx, cmd_ctx->num_rules,
                                                  cmd_ctx->rules, 0,
                                                  &num_rules, &rules);
            if (ret != EOK) {
                return EFAULT;
            }

            DEBUG(SSSDBG_TRACE_FUNC, "Got %u rules after time filter\n",
                                      num_rules);
        }

        /* send result */
        ret = sudosrv_build_response(cmd_ctx, SSS_SUDO_ERROR_OK,
                                     num_rules, rules,
                                     &response_body, &response_len);
        if (ret != EOK) {
            return EFAULT;
        }

        ret = sudosrv_cmd_send_reply(cmd_ctx, response_body, response_len);
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
        ret = sudosrv_cmd_send_error(cmd_ctx, cmd_ctx, ret);
        break;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Fatal error, killing connection!\n");
        talloc_free(cmd_ctx->cli_ctx);
        return EFAULT;
    }

    return EOK;
}

static void sudosrv_cmd_done(struct tevent_req *req);

static int sudosrv_cmd(enum sss_sudo_type type, struct cli_ctx *cli_ctx)
{
    struct tevent_req *req = NULL;
    struct sudo_cmd_ctx *cmd_ctx = NULL;
    uint8_t *query_body = NULL;
    size_t query_len = 0;
    struct cli_protocol *pctx;
    uint32_t protocol;
    errno_t ret;

    /* create cmd_ctx */

    cmd_ctx = talloc_zero(cli_ctx, struct sudo_cmd_ctx);
    if (cmd_ctx == NULL) {
        /* kill the connection here as we have no context for reply */
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory?\n");
        return ENOMEM;
    }

    cmd_ctx->cli_ctx = cli_ctx;
    cmd_ctx->type = type;
    cmd_ctx->sudo_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct sudo_ctx);
    if (cmd_ctx->sudo_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "sudo_ctx not set, killing connection!\n");
        return EFAULT;
    }

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);
    protocol = pctx->cli_protocol_version->version;

    /* the only intended client - suid binary 'sudo' */
    if (cli_ctx->priv != 1) {
        DEBUG(SSSDBG_IMPORTANT_INFO, "Refusing to serve unprivileged client "
              "'%s' running under uid = %"SPRIuid"\n",
              cli_ctx->cmd_line, client_euid(cli_ctx->creds));
        ret = EFAULT;
        goto done;
    }

    /* if protocol is invalid return */
    switch (protocol) {
    case 0:
        DEBUG(SSSDBG_FATAL_FAILURE, "Protocol [%d] is not secure. "
              "SSSD does not allow to use this protocol.\n", protocol);
        ret = EFAULT;
        goto done;
        break;
    case SSS_SUDO_PROTOCOL_VERSION:
        DEBUG(SSSDBG_TRACE_INTERNAL, "Using protocol version [%d]\n",
                                      protocol);
        break;
    default:
        DEBUG(SSSDBG_FATAL_FAILURE, "Invalid protocol version [%d]!\n",
                                     protocol);
        ret = EFAULT;
        goto done;
    }

    /* parse query */
    sss_packet_get_body(pctx->creq->in, &query_body, &query_len);
    if (query_len <= 0 || query_body == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Query is empty\n");
        ret = EINVAL;
        goto done;
    }

    ret = sudosrv_parse_query(cmd_ctx, query_body, query_len,
                              &cmd_ctx->rawname, &cmd_ctx->uid);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse sudo query [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    req = sudosrv_get_rules_send(cmd_ctx, cli_ctx->ev, cmd_ctx->sudo_ctx,
                                 cmd_ctx->type, cmd_ctx->uid,
                                 cmd_ctx->rawname);
    if (req == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, sudosrv_cmd_done, cmd_ctx);

    ret = EAGAIN;

done:
    return sudosrv_cmd_reply(cmd_ctx, ret);
}

static void sudosrv_cmd_done(struct tevent_req *req)
{
    struct sudo_cmd_ctx *cmd_ctx;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(req, struct sudo_cmd_ctx);

    ret = sudosrv_get_rules_recv(cmd_ctx, req, &cmd_ctx->rules,
                                 &cmd_ctx->num_rules);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG((ret == ENOENT) ? SSSDBG_MINOR_FAILURE : SSSDBG_OP_FAILURE,
              "Unable to obtain cached rules [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    sudosrv_cmd_reply(cmd_ctx, ret);
}

static int sudosrv_cmd_get_sudorules(struct cli_ctx *cli_ctx)
{
    return sudosrv_cmd(SSS_SUDO_USER, cli_ctx);
}

static int sudosrv_cmd_get_defaults(struct cli_ctx *cli_ctx)
{
    return sudosrv_cmd(SSS_SUDO_DEFAULTS, cli_ctx);
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version sudo_cli_protocol_version[] = {
		{1, "2012-05-14", "require uid and domain"},
        {0, NULL, NULL}
    };

    return sudo_cli_protocol_version;
}

struct sss_cmd_table *get_sudo_cmds(void) {
    static struct sss_cmd_table sudo_cmds[] = {
        {SSS_GET_VERSION, sss_cmd_get_version},
        {SSS_SUDO_GET_SUDORULES, sudosrv_cmd_get_sudorules},
        {SSS_SUDO_GET_DEFAULTS, sudosrv_cmd_get_defaults},
        {SSS_CLI_NULL, NULL}
    };

    return sudo_cmds;
}
