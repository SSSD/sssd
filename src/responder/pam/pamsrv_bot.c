/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2026 Red Hat

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

#include <dhash.h>
#include <limits.h>
#include <talloc.h>
#include <tevent.h>
#include <string.h>

#include "util/util.h"
#include "util/sss_bot_parser.h"
#include "util/sss_ptr_hash.h"
#include "responder/common/responder_packet.h"
#include "responder/pam/pamsrv.h"
#include "responder/pam/pamsrv_bot.h"

#define PAM_BOT_METADATA_TIMEOUT 300

#define PAM_BOT_AGENT      "mcp-bot-agent:"
#define PAM_BOT_MODEL      "mcp-bot-model:"
#define PAM_BOT_TOOL       "mcp-bot-tool:"
#define PAM_BOT_REQUEST_ID "mcp-bot-request-id:"

struct pam_bot_metadata {
    char *agent;
    char *model;
    char *tool;
    char *request_id;
};

struct pam_bot_entry {
    char *name;
    struct pam_bot_metadata metadata;
    struct tevent_timer *timer;
};

static void pam_bot_entry_delete(hash_entry_t *item,
                                  hash_destroy_enum deltype,
                                  void *pvt)
{
    /* Also cancel the old entry's timer when replacing it. */
    talloc_free(item->value.ptr);
}

errno_t pam_bot_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct pam_bot_ctx **_ctx)
{
    struct pam_bot_ctx *ctx;

    ctx = talloc_zero(mem_ctx, struct pam_bot_ctx);
    if (ctx == NULL) {
        return ENOMEM;
    }

    ctx->ev = ev;
    ctx->table = sss_ptr_hash_create(ctx, pam_bot_entry_delete, NULL);
    if (ctx->table == NULL) {
        talloc_free(ctx);
        return ENOMEM;
    }

    *_ctx = ctx;
    return EOK;
}

/*
 * Metadata currently comes from authentication indicators. Keep their
 * interpretation separate from the cache so a custom container can replace
 * them without changing entry ownership or expiration.
 */
static errno_t pam_bot_parse_indicator(struct pam_bot_entry *entry,
                                       const uint8_t *indicator,
                                       size_t len)
{
    char **field;
    char *value;
    size_t prefix_len;

    if (len >= sizeof(PAM_BOT_AGENT) - 1
            && memcmp(indicator, PAM_BOT_AGENT,
                      sizeof(PAM_BOT_AGENT) - 1) == 0) {
        field = &entry->metadata.agent;
        prefix_len = sizeof(PAM_BOT_AGENT) - 1;
    } else if (len >= sizeof(PAM_BOT_MODEL) - 1
            && memcmp(indicator, PAM_BOT_MODEL,
                      sizeof(PAM_BOT_MODEL) - 1) == 0) {
        field = &entry->metadata.model;
        prefix_len = sizeof(PAM_BOT_MODEL) - 1;
    } else if (len >= sizeof(PAM_BOT_TOOL) - 1
            && memcmp(indicator, PAM_BOT_TOOL,
                      sizeof(PAM_BOT_TOOL) - 1) == 0) {
        field = &entry->metadata.tool;
        prefix_len = sizeof(PAM_BOT_TOOL) - 1;
    } else if (len >= sizeof(PAM_BOT_REQUEST_ID) - 1
            && memcmp(indicator, PAM_BOT_REQUEST_ID,
                      sizeof(PAM_BOT_REQUEST_ID) - 1) == 0) {
        field = &entry->metadata.request_id;
        prefix_len = sizeof(PAM_BOT_REQUEST_ID) - 1;
    } else {
        /* Other authentication indicators are not bot metadata. */
        return EOK;
    }

    if (memchr(indicator + prefix_len, '\0', len - prefix_len) != NULL) {
        return EINVAL;
    }

    value = talloc_strndup(entry, (const char *)indicator + prefix_len,
                          len - prefix_len);
    if (value == NULL) {
        return ENOMEM;
    }

    /* Preserve the PoC's last-value-wins behavior for duplicate fields. */
    talloc_free(*field);
    *field = value;
    return EOK;
}

static errno_t pam_bot_parse(TALLOC_CTX *mem_ctx,
                             const uint8_t *body,
                             size_t body_len,
                             struct pam_bot_entry **_entry)
{
    struct sss_bot_parser_data bot;
    struct pam_bot_entry *entry;
    const uint8_t *name_end;
    uint32_t indicator_len;
    size_t pos;
    errno_t ret;

    if (body == NULL || body_len == 0) {
        return EINVAL;
    }

    name_end = memchr(body, '\0', body_len);
    if (name_end == NULL) {
        return EINVAL;
    }

    ret = sss_bot_parse_const((const char *)body, &bot);
    if (ret != EOK) {
        return ret;
    }

    /* The plugin sends bot->name, without a realm or domain. */
    if (bot.name_len != bot.input_len) {
        return EINVAL;
    }

    entry = talloc_zero(mem_ctx, struct pam_bot_entry);
    if (entry == NULL) {
        return ENOMEM;
    }

    entry->name = talloc_strdup(entry, (const char *)body);
    if (entry->name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Body: [name\0][native uint32 length][indicator bytes]... */
    pos = (size_t)(name_end - body) + 1;
    while (pos < body_len) {
        if (body_len - pos < sizeof(uint32_t)) {
            ret = EINVAL;
            goto done;
        }

        SAFEALIGN_COPY_UINT32(&indicator_len, body + pos, &pos);
        if (indicator_len > body_len - pos) {
            ret = EINVAL;
            goto done;
        }

        ret = pam_bot_parse_indicator(entry, body + pos, indicator_len);
        if (ret != EOK) {
            goto done;
        }

        pos += indicator_len;
    }

    *_entry = entry;
    return EOK;

done:
    talloc_free(entry);
    return ret;
}

static void pam_bot_expire(struct tevent_context *ev,
                           struct tevent_timer *te,
                           struct timeval tv,
                           void *pvt)
{
    struct pam_bot_entry *entry;

    entry = talloc_get_type(pvt, struct pam_bot_entry);
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Removing expired bot metadata for [%s]\n", entry->name);

    /* sss_ptr_hash removes the mapping when the entry is freed. */
    talloc_free(entry);
}

/* Takes ownership of entry, freeing it on failure. */
static errno_t pam_bot_register(struct pam_bot_ctx *ctx,
                                struct pam_bot_entry *entry)
{
    struct timeval expires;
    errno_t ret;

    if (ctx == NULL) {
        ret = EIO;
        goto done;
    }

    /* Prepare the entry completely before replacing existing metadata. */
    expires = tevent_timeval_current_ofs(PAM_BOT_METADATA_TIMEOUT, 0);
    entry->timer = tevent_add_timer(ctx->ev, entry, expires,
                                    pam_bot_expire, entry);
    if (entry->timer == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_ptr_hash_add_or_override(ctx->table, entry->name, entry,
                                       struct pam_bot_entry);
    if (ret != EOK) {
        goto done;
    }

    talloc_steal(ctx->table, entry);
    DEBUG(SSSDBG_TRACE_FUNC, "Registered bot metadata for [%s]\n", entry->name);
    return EOK;

done:
    talloc_free(entry);
    return ret;
}

int pam_bot_cmd_register(struct cli_ctx *cctx)
{
    struct cli_protocol *protocol;
    struct pam_ctx *pctx;
    struct pam_bot_entry *entry;
    uint8_t *body;
    size_t body_len;
    errno_t ret;

    protocol = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);
    pctx = talloc_get_type(cctx->rctx->pvt_ctx, struct pam_ctx);

    sss_packet_get_body(protocol->creq->in, &body, &body_len);
    ret = pam_bot_parse(protocol->creq, body, body_len, &entry);
    if (ret != EOK) {
        goto done;
    }

    ret = pam_bot_register(pctx->bot_ctx, entry);

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to register bot metadata [%d]: %s\n",
              ret, sss_strerror(ret));
        ret = sss_cmd_send_error(cctx, ret);
    } else {
        ret = sss_cmd_send_empty(cctx);
    }

    if (ret != EOK) {
        return ret;
    }

    sss_cmd_done(cctx, NULL);
    return EOK;
}

static errno_t pam_bot_add_env(struct pam_data *pd,
                               TALLOC_CTX *tmp_ctx,
                               const char *name,
                               const char *value)
{
    char *env;
    size_t len;
    errno_t ret;

    if (value == NULL) {
        return EOK;
    }

    env = talloc_asprintf(tmp_ctx, "%s=%s", name, value);
    if (env == NULL) {
        return ENOMEM;
    }

    len = strlen(env) + 1;
    if (len > INT_MAX) {
        talloc_free(env);
        return EOVERFLOW;
    }

    ret = pam_add_response(pd, SSS_PAM_ENV_ITEM, len, (uint8_t *)env);
    talloc_free(env);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to add bot environment variable [%s] [%d]: %s\n",
              name, ret, sss_strerror(ret));
    }

    return ret;
}

/* Export bot account information through PAM for sss-confined-shell. */
errno_t pam_bot_export_env(struct pam_auth_req *preq,
                           struct pam_bot_ctx *ctx)
{
    TALLOC_CTX *tmp_ctx;
    struct pam_bot_entry *entry;
    const char *original_name;
    const char *shell;
    errno_t ret;

    if (preq->bot == NULL) {
        return EOK;
    }

    tmp_ctx = talloc_new(preq);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    original_name = sss_get_name_from_msg(preq->domain, preq->user_obj);
    shell = sss_resp_get_shell_override(preq->user_obj,
                                        preq->cctx->rctx, preq->domain);

    ret = pam_bot_add_env(preq->pd, tmp_ctx,
                          "SSS_BOT_NAME", preq->bot->input);
    if (ret != EOK) {
        goto done;
    }

    ret = pam_bot_add_env(preq->pd, tmp_ctx,
                          "SSS_BOT_ORIGINAL_USER", original_name);
    if (ret != EOK) {
        goto done;
    }

    ret = pam_bot_add_env(preq->pd, tmp_ctx,
                          "SSS_BOT_ORIGINAL_SHELL", shell);
    if (ret != EOK) {
        goto done;
    }

    entry = sss_ptr_hash_lookup(ctx->table, preq->bot->name,
                                struct pam_bot_entry);
    if (entry == NULL) {
        ret = EOK;
        goto done;
    }

    ret = pam_bot_add_env(preq->pd, tmp_ctx,
                          "SSS_BOT_AGENT", entry->metadata.agent);
    if (ret != EOK) {
        goto done;
    }

    ret = pam_bot_add_env(preq->pd, tmp_ctx,
                          "SSS_BOT_MODEL", entry->metadata.model);
    if (ret != EOK) {
        goto done;
    }

    ret = pam_bot_add_env(preq->pd, tmp_ctx,
                          "SSS_BOT_TOOL", entry->metadata.tool);
    if (ret != EOK) {
        goto done;
    }

    ret = pam_bot_add_env(preq->pd, tmp_ctx,
                          "SSS_BOT_REQUEST_ID", entry->metadata.request_id);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
