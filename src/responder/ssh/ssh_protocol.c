/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include <talloc.h>

#include "util/util.h"
#include "util/sss_ssh.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "responder/common/cache_req/cache_req.h"
#include "responder/ssh/ssh_private.h"

errno_t
ssh_protocol_done(struct cli_ctx *cli_ctx, errno_t error)
{
    struct cli_protocol *pctx;
    errno_t ret;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    switch (error) {
    case EOK:
        /* Create empty packet if none was provided. */
        if (pctx->creq->out == NULL) {
            ret = sss_packet_new(pctx->creq, 0,
                                 sss_packet_get_cmd(pctx->creq->in),
                                 &pctx->creq->out);
            if (ret != EOK) {
                goto done;
            }

            sss_packet_set_error(pctx->creq->out, EOK);
        }

        DEBUG(SSSDBG_TRACE_ALL, "Sending reply: success\n");
        ret = EOK;
        goto done;
    default:
        DEBUG(SSSDBG_TRACE_ALL, "Sending reply: error [%d]: %s\n",
              error, sss_strerror(error));
        ret = sss_cmd_send_error(cli_ctx, error);
        goto done;
    }

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send reply [%d]: %s!\n",
              ret, sss_strerror(ret));
        return ret;
    }

    sss_cmd_done(cli_ctx, NULL);
    return EOK;
}

void ssh_protocol_reply(struct cli_ctx *cli_ctx,
                        struct cache_req_result *result)
{
    struct cli_protocol *pctx;
    struct ssh_ctx *ssh_ctx;
    errno_t ret;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);
    ssh_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct ssh_ctx);

    ret = sss_packet_new(pctx->creq, 0, sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        goto done;
    }

    ret = ssh_protocol_build_reply(pctx->creq->out, ssh_ctx, result);
    if (ret != EOK) {
        goto done;
    }

    sss_packet_set_error(pctx->creq->out, EOK);

done:
    ssh_protocol_done(cli_ctx, ret);
}

static errno_t
ssh_protocol_parse_request(struct cli_ctx *cli_ctx,
                           const char *default_domain,
                           const char **_name,
                           const char **_alias,
                           const char **_domain)
{
    struct cli_protocol *pctx;
    const char *name = NULL;
    const char *alias = NULL;
    const char *domain = NULL;
    uint32_t flags;
    uint32_t name_len;
    uint32_t alias_len;
    uint32_t domain_len;
    size_t body_len;
    uint8_t *body;
    size_t c = 0;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &body_len);

    SAFEALIGN_COPY_UINT32_CHECK(&flags, body + c, body_len, &c);
    if (flags & ~(uint32_t)SSS_SSH_REQ_MASK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid flags received [0x%x]\n", flags);
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32_CHECK(&name_len, body + c, body_len, &c);
    if (name_len == 0 || name_len > body_len - c) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid name length\n");
        return EINVAL;
    }

    name = (const char *)(body + c);
    if (!sss_utf8_check((const uint8_t *)name, name_len-1) ||
            name[name_len - 1] != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Name is not valid UTF-8 string\n");
        return EINVAL;
    }
    c += name_len;

    if (flags & SSS_SSH_REQ_ALIAS) {
        SAFEALIGN_COPY_UINT32_CHECK(&alias_len, body + c, body_len, &c);
        if (alias_len == 0 || alias_len > body_len - c) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid alias length\n");
            return EINVAL;
        }

        alias = (const char *)(body+c);
        if (!sss_utf8_check((const uint8_t *)alias, alias_len - 1) ||
                alias[alias_len - 1] != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Alias is not valid UTF-8 string\n");
            return EINVAL;
        }
        c += alias_len;
    }

    if (flags & SSS_SSH_REQ_DOMAIN) {
        SAFEALIGN_COPY_UINT32_CHECK(&domain_len, body + c, body_len, &c);
        if (domain_len > 0) {
            if (domain_len > body_len - c) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Invalid domain length\n");
                return EINVAL;
            }

            domain = (const char *)(body + c);
            if (!sss_utf8_check((const uint8_t *)domain, domain_len - 1) ||
                    domain[domain_len - 1] != 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Domain is not valid UTF-8 string\n");
                return EINVAL;
            }
            c += domain_len;
        } else {
            domain = default_domain;
        }

        DEBUG(SSSDBG_TRACE_FUNC,
              "Requested domain [%s]\n", domain ? domain : "<ALL>");
    }

    if (_name != NULL) {
        *_name = name;
    }

    if (_alias != NULL) {
        *_alias = alias;
    }

    if (_domain != NULL) {
        *_domain = domain;
    }

    return EOK;
}

errno_t
ssh_protocol_parse_user(struct cli_ctx *cli_ctx,
                        const char *default_domain,
                        const char **_name,
                        const char **_domain)
{
    return ssh_protocol_parse_request(cli_ctx, default_domain,
                                      _name, NULL, _domain);
}

errno_t
ssh_protocol_parse_host(struct cli_ctx *cli_ctx,
                        const char **_name,
                        const char **_alias,
                        const char **_domain)
{
    return ssh_protocol_parse_request(cli_ctx, NULL, _name, _alias, _domain);
}
