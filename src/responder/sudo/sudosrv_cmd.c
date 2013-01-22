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
#include "db/sysdb_sudo.h"

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

    if (error == EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Everything is fine but we are "
              "returning error?\n"));
        return EFAULT;
    }

    ret = sudosrv_build_response(mem_ctx, error, 0, NULL,
                                 &response_body, &response_len);
    if (ret != EOK) {
        return ret;
    }

    return sudosrv_cmd_send_reply(cmd_ctx, response_body, response_len);
}

errno_t sudosrv_cmd_done(struct sudo_cmd_ctx *cmd_ctx, int ret)
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
            ret = sysdb_sudo_filter_rules_by_time(cmd_ctx, cmd_ctx->num_rules,
                                                  cmd_ctx->rules, 0,
                                                  &num_rules, &rules);
            if (ret != EOK) {
                return EFAULT;
            }
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("Fatal error, killing connection!\n"));
        talloc_free(cmd_ctx->cli_ctx);
        return EFAULT;
    }

    return EOK;
}

static void sudosrv_cmd_parse_query_done(struct tevent_req *req);

static int sudosrv_cmd(enum sss_sudo_type type, struct cli_ctx *cli_ctx)
{
    struct tevent_req *req = NULL;
    struct sudo_cmd_ctx *cmd_ctx = NULL;
    uint8_t *query_body = NULL;
    size_t query_len = 0;
    errno_t ret;

    /* create cmd_ctx */

    cmd_ctx = talloc_zero(cli_ctx, struct sudo_cmd_ctx);
    if (cmd_ctx == NULL) {
        /* kill the connection here as we have no context for reply */
        DEBUG(SSSDBG_FATAL_FAILURE, ("Out of memory?\n"));
        return ENOMEM;
    }

    cmd_ctx->domain = NULL;
    cmd_ctx->cli_ctx = cli_ctx;
    cmd_ctx->type = type;
    cmd_ctx->sudo_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct sudo_ctx);
    if (cmd_ctx->sudo_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("sudo_ctx not set, killing connection!\n"));
        return EFAULT;
    }

    /* if protocol is invalid return */
    if (cli_ctx->cli_protocol_version->version != 1) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("Invalid protocol! [%d]\n",
              cli_ctx->cli_protocol_version->version));
        ret = EFAULT;
        goto done;
    }

    /* parse query */

    sss_packet_get_body(cli_ctx->creq->in, &query_body, &query_len);
    if (query_len <= 0 || query_body == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Query is empty\n"));
        ret = EINVAL;
        goto done;
    }

    req = sudosrv_parse_query_send(cmd_ctx, cli_ctx->rctx,
                                   query_body, query_len);
    if (req == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, sudosrv_cmd_parse_query_done, cmd_ctx);

    ret = EAGAIN;

done:
    return sudosrv_cmd_done(cmd_ctx, ret);
}

static void sudosrv_cmd_parse_query_done(struct tevent_req *req)
{
    struct sudo_cmd_ctx *cmd_ctx = NULL;
    struct sudo_dom_ctx *dom_ctx = NULL;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(req, struct sudo_cmd_ctx);

    ret = sudosrv_parse_query_recv(cmd_ctx, req, &cmd_ctx->uid,
                                   &cmd_ctx->username, &cmd_ctx->domain);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid query [%d]: %s\n",
                                    ret, strerror(ret)));
        goto done;
    }

    cmd_ctx->check_next = cmd_ctx->domain == NULL;

    switch (cmd_ctx->type) {
        case SSS_SUDO_DEFAULTS:
            DEBUG(SSSDBG_FUNC_DATA, ("Requesting default options "
                  "for [%s] from [%s]\n", cmd_ctx->username,
                  cmd_ctx->domain ? cmd_ctx->domain->name : "<ALL>"));
            break;
        case SSS_SUDO_USER:
            DEBUG(SSSDBG_FUNC_DATA, ("Requesting rules "
                  "for [%s] from [%s]\n", cmd_ctx->username,
                  cmd_ctx->domain ? cmd_ctx->domain->name : "<ALL>"));
            break;
    }

    /* create domain ctx */

    dom_ctx = talloc_zero(cmd_ctx, struct sudo_dom_ctx);
    if (dom_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }
    dom_ctx->cmd_ctx = cmd_ctx;
    dom_ctx->domain = cmd_ctx->domain != NULL ? cmd_ctx->domain
                                              : cmd_ctx->cli_ctx->rctx->domains;

    ret = sudosrv_get_sudorules(dom_ctx);

done:
    sudosrv_cmd_done(cmd_ctx, ret);
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
