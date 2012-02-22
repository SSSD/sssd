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
    size_t num_rules = dctx->res_count;
    struct sysdb_attrs **rules = dctx->res;

    switch (ret) {
    case EOK:
        /*
         * Parent of dctx->res is in-memory cache, we must not talloc_free it!
         */
        if (!dctx->cmd_ctx->sudo_ctx->timed) {
            num_rules = dctx->res_count;
            rules = dctx->res;
        } else {
            /* filter rules by time */
            ret = sysdb_sudo_filter_rules_by_time(dctx, dctx->res_count,
                                                  dctx->res, 0,
                                                  &num_rules, &rules);
            if (ret != EOK) {
                return EFAULT;
            }
        }

        /* send result */
        ret = sudosrv_get_sudorules_build_response(dctx->cmd_ctx, SSS_SUDO_ERROR_OK,
                                                   num_rules, rules,
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
    cmd_ctx->type = SSS_DP_SUDO_USER;

    /* get responder ctx */
    cmd_ctx->sudo_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct sudo_ctx);
    if (!cmd_ctx->sudo_ctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("sudo_ctx not set\n"));
        ret = EFAULT;
        goto done;
    }

    /* create domain ctx */
    dctx = talloc_zero(cmd_ctx, struct sudo_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmd_ctx = cmd_ctx;
    dctx->orig_username = NULL;
    dctx->cased_username = NULL;

    /* get query */
    sss_packet_get_body(cli_ctx->creq->in, &query_body, &query_len);
    if (query_len <= 0 || query_body == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Query is empty\n"));
        ret = EINVAL;
        goto done;
    }

    /* If the body isn't valid UTF-8, fail */
    if (!sss_utf8_check(query_body, query_len - 1)) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Supplied data is not valid UTF-8 string\n"));
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

    /* try to find rules in in-memory cache */
    ret = sudosrv_cache_lookup(cmd_ctx->sudo_ctx->cache, dctx,
                               cmd_ctx->check_next, cmd_ctx->username,
                               &dctx->res_count, &dctx->res);
    if (ret == EOK) {
        /* cache hit */
        DEBUG(SSSDBG_FUNC_DATA, ("Returning rules for [%s@%s] "
              "from in-memory cache\n", cmd_ctx->username, dctx->domain->name));
    } else if (ret == ENOENT) {
        /* cache expired or missed */
        ret = sudosrv_get_sudorules(dctx);
    } /* else error */

done:
    return sudosrv_cmd_done(dctx, ret);
}

static int sudosrv_cmd_get_defaults(struct cli_ctx *cli_ctx)
{
    int ret = EOK;
    struct sudo_cmd_ctx *cmd_ctx = NULL;
    struct sudo_dom_ctx *dctx = NULL;

    cmd_ctx = talloc_zero(cli_ctx, struct sudo_cmd_ctx);
    if (!cmd_ctx) {
        ret = ENOMEM;
        goto done;
    }
    cmd_ctx->cli_ctx = cli_ctx;
    cmd_ctx->type = SSS_DP_SUDO_DEFAULTS;
    cmd_ctx->username = NULL;
    cmd_ctx->check_next = false;

    /* get responder ctx */
    cmd_ctx->sudo_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct sudo_ctx);
    if (!cmd_ctx->sudo_ctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("sudo_ctx not set\n"));
        ret = EFAULT;
        goto done;
    }

    /* create domain ctx */
    dctx = talloc_zero(cmd_ctx, struct sudo_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmd_ctx = cmd_ctx;
    dctx->orig_username = NULL;
    dctx->cased_username = NULL;

    DEBUG(SSSDBG_FUNC_DATA, ("Requesting cn=defaults\n"));

    /* sudo currently does not support domain selection
     * so find first available domain
     * TODO - support domain selection */
    dctx->domain = cli_ctx->rctx->domains;
    while (dctx->domain && dctx->domain->fqnames) {
        dctx->domain = dctx->domain->next;
    }
    if (!dctx->domain) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("No valid domain found\n"));
        ret = ENOENT;
        goto done;
    }

    /* try to find rules in in-memory cache */
    ret = sudosrv_cache_lookup(cmd_ctx->sudo_ctx->cache, dctx,
                               cmd_ctx->check_next, cmd_ctx->username,
                               &dctx->res_count, &dctx->res);
    if (ret == EOK) {
        /* cache hit */
        DEBUG(SSSDBG_FUNC_DATA, ("Returning defaults settings for [%s] "
                                 "from in-memory cache\n", dctx->domain->name));
    } else if (ret == ENOENT) {
        /* cache expired or missed */
        ret = sudosrv_get_rules(dctx);
    } /* else error */

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
        {SSS_SUDO_GET_DEFAULTS, sudosrv_cmd_get_defaults},
        {SSS_CLI_NULL, NULL}
    };

    return sudo_cmds;
}
