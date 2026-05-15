/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2012 Red Hat

    Autofs responder: commands

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

#include <talloc.h>

#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "responder/common/cache_req/cache_req.h"
#include "responder/autofs/autofs_private.h"
#include "db/sysdb.h"
#include "db/sysdb_autofs.h"
#include "confdb/confdb.h"
#include "sss_iface/sss_iface_async.h"
#include "util/sss_ptr_hash.h"

static int autofs_cmd_send_error(struct autofs_cmd_ctx *cmdctx, int err)
{
    return sss_cmd_send_error(cmdctx->cli_ctx, err);
}

static int
autofs_cmd_send_empty(struct autofs_cmd_ctx *cmdctx)
{
    return sss_cmd_send_empty(cmdctx->cli_ctx);
}

static int
autofs_cmd_done(struct autofs_cmd_ctx *cmdctx, int ret)
{
    switch (ret) {
    case EOK:
        /* all fine, just return here */
        break;

    case ENOENT:
        ret = autofs_cmd_send_empty(cmdctx);
        if (ret) {
            return EFAULT;
        }
        sss_cmd_done(cmdctx->cli_ctx, cmdctx);
        break;

    case EAGAIN:
        /* async processing, just return here */
        break;

    case EFAULT:
        /* very bad error */
        return EFAULT;

    default:
        ret = autofs_cmd_send_error(cmdctx, ret);
        if (ret) {
            return EFAULT;
        }
        sss_cmd_done(cmdctx->cli_ctx, cmdctx);
        break;
    }

    return EOK;
}

static errno_t
autofs_fill_entry(struct ldb_message *entry, struct sss_packet *packet, size_t *rp)
{
    errno_t ret;
    const char *key;
    size_t keylen;
    const char *value;
    size_t valuelen;
    uint8_t *body;
    size_t blen;
    size_t len;

    key = ldb_msg_find_attr_as_string(entry, SYSDB_AUTOFS_ENTRY_KEY, NULL);
    value = ldb_msg_find_attr_as_string(entry, SYSDB_AUTOFS_ENTRY_VALUE, NULL);
    if (!key || !value) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Incomplete entry\n");
        return EINVAL;
    }

    keylen = 1 + strlen(key);
    valuelen = 1 + strlen(value);
    len = sizeof(uint32_t) + sizeof(uint32_t) + keylen + sizeof(uint32_t) + valuelen;

    ret = sss_packet_grow(packet, len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot grow packet\n");
        return ret;
    }

    sss_packet_get_body(packet, &body, &blen);

    SAFEALIGN_SET_UINT32(&body[*rp], len, rp);
    SAFEALIGN_SET_UINT32(&body[*rp], keylen, rp);

    if (keylen == 1) {
        body[*rp] = '\0';
    } else {
        memcpy(&body[*rp], key, keylen);
    }
    *rp += keylen;

    SAFEALIGN_SET_UINT32(&body[*rp], valuelen, rp);
    if (valuelen == 1) {
        body[*rp] = '\0';
    } else {
        memcpy(&body[*rp], value, valuelen);
    }
    *rp += valuelen;

    return EOK;
}

void
autofs_orphan_maps(struct autofs_ctx *autofs_ctx)
{
    /* It will automatically decrease the refcount of enum_ctx through
     * delete callback. */
    sss_ptr_hash_delete_all(autofs_ctx->maps, false);
}

static void
autofs_enumctx_lifetime_timeout(struct tevent_context *ev,
                                struct tevent_timer *te,
                                struct timeval current_time,
                                void *pvt)
{
    struct autofs_enum_ctx *enum_ctx;

    enum_ctx = talloc_get_type(pvt, struct autofs_enum_ctx);

    /* Remove it from the table. It will automatically decrease the refcount. */
    sss_ptr_hash_delete(enum_ctx->table, enum_ctx->key, false);
}

static void
autofs_set_enumctx_lifetime(struct autofs_ctx *autofs_ctx,
                            struct autofs_enum_ctx *enum_ctx,
                            uint32_t lifetime)
{
    struct timeval tv;
    struct tevent_timer *te;

    tv = tevent_timeval_current_ofs(lifetime, 0);
    te = tevent_add_timer(autofs_ctx->rctx->ev, enum_ctx, tv,
                          autofs_enumctx_lifetime_timeout, enum_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not set up life timer for autofs maps. "
              "Entries may become stale.\n");
    }
}

static struct autofs_enum_ctx *
autofs_create_enumeration_context(TALLOC_CTX *mem_ctx,
                                  struct autofs_ctx *autofs_ctx,
                                  const char *mapname)
{
    struct autofs_enum_ctx *enum_ctx;
    errno_t ret;

    enum_ctx = talloc_zero(mem_ctx, struct autofs_enum_ctx);
    if (enum_ctx == NULL) {
        return NULL;
    }

    enum_ctx->ready = false;
    enum_ctx->table = autofs_ctx->maps;

    enum_ctx->key = talloc_strdup(enum_ctx, mapname);
    if (enum_ctx->key == NULL) {
        talloc_free(enum_ctx);
        return NULL;
    }

    ret = sss_ptr_hash_add(autofs_ctx->maps, mapname,
                           enum_ctx, struct autofs_enum_ctx);
    if (ret != EOK) {
        talloc_free(enum_ctx);
        return NULL;
    }

    return enum_ctx;
}

static void
autofs_orphan_master_map(struct autofs_ctx *autofs_ctx,
                         const char *mapname)
{
    struct sss_domain_info *dom;
    errno_t ret;

    if (strcmp(mapname, "auto.master") != 0) {
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Invalidating master map\n");

    /* Remove and invalidate all maps. */
    autofs_orphan_maps(autofs_ctx);

    DEBUG(SSSDBG_TRACE_FUNC, "Invalidating autofs maps\n");
    for (dom = autofs_ctx->rctx->domains;
         dom != NULL;
         dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        ret = sysdb_invalidate_autofs_maps(dom);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Unable to invalidate maps in "
                  "%s [%d]: %s\n", dom->name, ret, sss_strerror(ret));
        }
    }
}

struct autofs_setent_state {
    struct autofs_ctx *autofs_ctx;
    struct autofs_enum_ctx *enum_ctx;
};

static void autofs_setent_done(struct tevent_req *subreq);

static struct tevent_req *
autofs_setent_send(TALLOC_CTX *mem_ctx,
                   struct tevent_context *ev,
                   struct autofs_ctx *autofs_ctx,
                   const char *mapname)
{
    struct autofs_setent_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct autofs_setent_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->autofs_ctx = autofs_ctx;

    /* Lookup current results if available. */
    state->enum_ctx = sss_ptr_hash_lookup(autofs_ctx->maps, mapname,
                                          struct autofs_enum_ctx);
    if (state->enum_ctx != NULL) {
        if (state->enum_ctx->ready) {
            ret = EOK;
            goto done;
        }

        /* Map is still being created. We will watch the request. */
        ret = setent_add_ref(state, &state->enum_ctx->notify_list, req);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to watch enumeration request "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        ret = EAGAIN;
        goto done;
    }

    /* Map does not yet exist. Create the enumeration object and fetch data. */
    state->enum_ctx = autofs_create_enumeration_context(state, autofs_ctx, mapname);
    if (state->enum_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create enumeration context!\n");
        ret = ENOMEM;
        goto done;
    }

    subreq = cache_req_autofs_map_entries_send(mem_ctx, ev, autofs_ctx->rctx,
                                               autofs_ctx->rctx->ncache,
                                               0, NULL, mapname);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, autofs_setent_done, req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void autofs_setent_done(struct tevent_req *subreq)
{
    struct autofs_setent_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct autofs_setent_state);

    ret = cache_req_autofs_map_entries_recv(state, subreq, &result);
    talloc_zfree(subreq);

    switch (ret) {
    case EOK:
        state->enum_ctx->found = true;
        state->enum_ctx->result = talloc_steal(state->enum_ctx, result);
        autofs_set_enumctx_lifetime(state->autofs_ctx, state->enum_ctx,
                        state->enum_ctx->result->domain->autofsmap_timeout);
        break;
    case ENOENT:
        state->enum_ctx->found = false;
        state->enum_ctx->result = NULL;
        autofs_set_enumctx_lifetime(state->autofs_ctx, state->enum_ctx,
                                    state->autofs_ctx->neg_timeout);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unable to get map data [%d]: %s\n",
              ret, sss_strerror(ret));

        setent_notify(&state->enum_ctx->notify_list, ret);
        talloc_zfree(state->enum_ctx);
        tevent_req_error(req, ret);
        return;
    }

    state->enum_ctx->ready = true;

    /* Make the enumeration context disappear with maps table. */
    talloc_steal(state->autofs_ctx->maps, state->enum_ctx);

    setent_notify_done(&state->enum_ctx->notify_list);
    tevent_req_done(req);
    return;
}

static errno_t
autofs_setent_recv(TALLOC_CTX *mem_ctx,
                   struct tevent_req *req,
                   struct autofs_enum_ctx **_enum_ctx)
{
    struct autofs_setent_state *state;
    state = tevent_req_data(req, struct autofs_setent_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_enum_ctx = talloc_reference(mem_ctx, state->enum_ctx);

    return EOK;
}

static errno_t
autofs_read_setautomntent_input(struct cli_ctx *cli_ctx,
                                const char **_mapname)
{
    struct cli_protocol *pctx;
    uint8_t *body;
    size_t blen;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    /* if not terminated fail */
    if (body[blen - 1] != '\0') {
        return EINVAL;
    }

    /* If the body isn't valid UTF-8, fail */
    if (!sss_utf8_check(body, blen - 1)) {
        return EINVAL;
    }

    *_mapname = (const char *)body;

    return EOK;
}

static errno_t
autofs_write_setautomntent_output(struct cli_ctx *cli_ctx,
                                  struct cache_req_result *result)
{
    struct cli_protocol *pctx;
    uint8_t *body;
    size_t blen;
    errno_t ret;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    ret = sss_packet_new(pctx->creq, 0, sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    if (result == NULL || result->count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "Map was not found\n");
        return sss_cmd_empty_packet(pctx->creq->out);
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Map found\n");

    ret = sss_packet_grow(pctx->creq->out, 2 * sizeof(uint32_t));
    if (ret != EOK) {
        return ret;
    }

    sss_packet_get_body(pctx->creq->out, &body, &blen);

    /* Got some results */
    SAFEALIGN_SETMEM_UINT32(body, 1, NULL);

    /* Reserved padding */
    SAFEALIGN_SETMEM_UINT32(body + sizeof(uint32_t), 0, NULL);

    return EOK;
}

static void
sss_autofs_cmd_setautomntent_done(struct tevent_req *req);

static int
sss_autofs_cmd_setautomntent(struct cli_ctx *cli_ctx)
{
    struct autofs_cmd_ctx *cmd_ctx;
    struct autofs_ctx *autofs_ctx;
    struct tevent_req *req;
    errno_t ret;

    autofs_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct autofs_ctx);

    cmd_ctx = talloc_zero(cli_ctx, struct autofs_cmd_ctx);
    if (cmd_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create command context.\n");
        return ENOMEM;
    }

    cmd_ctx->cli_ctx = cli_ctx;
    cmd_ctx->autofs_ctx = autofs_ctx;

    ret = autofs_read_setautomntent_input(cli_ctx, &cmd_ctx->mapname);
    if (ret != EOK) {
        goto done;
    }

    autofs_orphan_master_map(autofs_ctx, cmd_ctx->mapname);

    DEBUG(SSSDBG_TRACE_FUNC, "Obtaining autofs map %s\n",
          cmd_ctx->mapname);

    req = cache_req_autofs_map_by_name_send(cli_ctx, cli_ctx->ev,
                                            autofs_ctx->rctx,
                                            autofs_ctx->rctx->ncache, 0, NULL,
                                            cmd_ctx->mapname);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cache_req_autofs_map_by_name_send failed\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, sss_autofs_cmd_setautomntent_done, cmd_ctx);

    ret = EOK;

done:
    return autofs_cmd_done(cmd_ctx, ret);
}

static void
sss_autofs_cmd_setautomntent_done(struct tevent_req *req)
{
    struct cache_req_result *result;
    struct autofs_cmd_ctx *cmd_ctx;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(req, struct autofs_cmd_ctx);

    ret = cache_req_autofs_map_by_name_recv(cmd_ctx, req, &result);
    talloc_zfree(req);
    if (ret != EOK) {
        autofs_cmd_done(cmd_ctx, ret);
        return;
    }

    ret = autofs_write_setautomntent_output(cmd_ctx->cli_ctx, result);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create reply packet "
              "[%d]: %s\n", ret, sss_strerror(ret));
        autofs_cmd_done(cmd_ctx, ret);
        return;
    }

    sss_cmd_done(cmd_ctx->cli_ctx, NULL);
}

static int
sss_autofs_cmd_endautomntent(struct cli_ctx *client)
{
    struct cli_protocol *pctx;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "endautomntent called\n");

    pctx = talloc_get_type(client->protocol_ctx, struct cli_protocol);

    /* create response packet */
    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);

    if (ret != EOK) {
        return ret;
    }

    sss_cmd_done(client, NULL);
    return EOK;
}

static errno_t
autofs_read_getautomntent_input(struct cli_ctx *cli_ctx,
                                const char **_mapname,
                                uint32_t *_cursor,
                                uint32_t *_max_entries)
{
    struct cli_protocol *pctx;
    const char *mapname;
    uint32_t namelen;
    uint8_t *body;
    size_t blen;
    size_t c = 0;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    SAFEALIGN_COPY_UINT32_CHECK(&namelen, body+c, blen, &c);
    if (namelen == 0 || namelen > blen - c) {
        return EINVAL;
    }

    mapname = (const char *)body + c;

    /* if not null-terminated fail */
    if (mapname[namelen] != '\0') {
        return EINVAL;
    }

    /* If the name isn't valid UTF-8, fail */
    if (!sss_utf8_check((const uint8_t *)mapname, namelen - 1)) {
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32_CHECK(_cursor, body + c + namelen + 1, blen, &c);
    SAFEALIGN_COPY_UINT32_CHECK(_max_entries, body + c + namelen + 1, blen, &c);
    *_mapname = mapname;

    return EOK;
}

static errno_t
autofs_write_getautomntent_output(struct cli_ctx *cli_ctx,
                                  struct autofs_enum_ctx *enum_ctx,
                                  uint32_t cursor,
                                  uint32_t max_entries)
{
    struct cli_protocol *pctx;
    struct ldb_message **entries;
    struct ldb_message *entry;
    size_t count;
    size_t num_entries;
    uint8_t *body;
    size_t blen;
    size_t rp;
    uint32_t i;
    uint32_t stop;
    uint32_t left;
    errno_t ret;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    count = enum_ctx->found ? enum_ctx->result->count - 1 : 0;
    entries = count > 0 ? enum_ctx->result->msgs + 1 : NULL;

    ret = sss_packet_new(pctx->creq, 0, sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    if (!enum_ctx->found || count == 0 || cursor >= count) {
        DEBUG(SSSDBG_TRACE_FUNC, "No entries was not found\n");
        return sss_cmd_empty_packet(pctx->creq->out);
    }

    /* allocate memory for number of entries in the packet */
    ret = sss_packet_grow(pctx->creq->out, sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot grow packet\n");
        return ret;
    }

    rp = sizeof(uint32_t);  /* We will first write the elements. */
    left = count - cursor;
    stop = max_entries < left ? max_entries : left;

    num_entries = 0;
    for (i = 0; i < stop; i++) {
        entry = entries[cursor];
        cursor++;

        ret = autofs_fill_entry(entry, pctx->creq->out, &rp);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot fill entry %d/%d, skipping\n", i, stop);
            continue;
        }
        num_entries++;
    }

    /* packet grows in fill_autofs_entry, body pointer may change,
     * thus we have to obtain it here */
    sss_packet_get_body(pctx->creq->out, &body, &blen);

    rp = 0;
    SAFEALIGN_SET_UINT32(&body[rp], num_entries, &rp);

    return EOK;
}

static void
sss_autofs_cmd_getautomntent_done(struct tevent_req *req);

static int
sss_autofs_cmd_getautomntent(struct cli_ctx *cli_ctx)
{
    struct autofs_cmd_ctx *cmd_ctx;
    struct autofs_ctx *autofs_ctx;
    struct tevent_req *req;
    errno_t ret;

    autofs_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct autofs_ctx);

    cmd_ctx = talloc_zero(cli_ctx, struct autofs_cmd_ctx);
    if (cmd_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create command context.\n");
        return ENOMEM;
    }

    cmd_ctx->cli_ctx = cli_ctx;
    cmd_ctx->autofs_ctx = autofs_ctx;

    ret = autofs_read_getautomntent_input(cli_ctx, &cmd_ctx->mapname,
                                          &cmd_ctx->cursor,
                                          &cmd_ctx->max_entries);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Obtaining enumeration context for %s\n",
          cmd_ctx->mapname);

    req = autofs_setent_send(cli_ctx, cli_ctx->ev, autofs_ctx, cmd_ctx->mapname);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "autofs_setent_send failed\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, sss_autofs_cmd_getautomntent_done, cmd_ctx);

    ret = EOK;

done:
    return autofs_cmd_done(cmd_ctx, ret);
}

static void
sss_autofs_cmd_getautomntent_done(struct tevent_req *req)
{
    struct autofs_enum_ctx *enum_ctx;
    struct autofs_cmd_ctx *cmd_ctx;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(req, struct autofs_cmd_ctx);

    ret = autofs_setent_recv(cmd_ctx, req, &enum_ctx);
    talloc_zfree(req);
    if (ret != EOK) {
        autofs_cmd_done(cmd_ctx, ret);
        return;
    }

    ret = autofs_write_getautomntent_output(cmd_ctx->cli_ctx, enum_ctx,
                                            cmd_ctx->cursor,
                                            cmd_ctx->max_entries);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create reply packet "
              "[%d]: %s\n", ret, sss_strerror(ret));
        autofs_cmd_done(cmd_ctx, ret);
        return;
    }

    sss_cmd_done(cmd_ctx->cli_ctx, NULL);
}

static errno_t
autofs_read_getautomntbyname_input(struct cli_ctx *cli_ctx,
                                   const char **_mapname,
                                   const char **_keyname)
{
    struct cli_protocol *pctx;
    const char *mapname;
    const char *keyname;
    uint32_t namelen;
    uint32_t keylen;
    uint8_t *body;
    size_t blen;
    size_t c = 0;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    /* Get map name. */
    SAFEALIGN_COPY_UINT32_CHECK(&namelen, body + c, blen, &c);
    if (namelen == 0 || namelen > blen - c) {
        return EINVAL;
    }

    mapname = (const  char *) body + c;

    /* if not null-terminated fail */
    if (mapname[namelen] != '\0') {
        return EINVAL;
    }

    /* If the name isn't valid UTF-8, fail */
    if (!sss_utf8_check((const uint8_t *)mapname, namelen - 1)) {
        return EINVAL;
    }

    c += namelen + 1;

    /* Get key name. */
    SAFEALIGN_COPY_UINT32_CHECK(&keylen, body + c, blen, &c);
    if (keylen == 0 || keylen > blen - c) {
        return EINVAL;
    }

    keyname = (const char *) body + c;

    /* if not null-terminated fail */
    if (keyname[keylen] != '\0') {
        return EINVAL;
    }

    /* If the key isn't valid UTF-8, fail */
    if (!sss_utf8_check((const uint8_t *)keyname, keylen - 1)) {
        return EINVAL;
    }

    *_mapname = mapname;
    *_keyname = keyname;

    return EOK;
}

static errno_t
autofs_write_getautomntbyname_output(struct cli_ctx *cli_ctx,
                                     struct cache_req_result *result,
                                     const char *keyname)
{
    struct cli_protocol *pctx;
    struct ldb_message *entry;
    const char *value;
    size_t value_len;
    size_t len;
    uint8_t *body;
    size_t blen;
    size_t rp;
    errno_t ret;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    if (result == NULL || result->count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "Key [%s] was not found\n", keyname);
        return sss_cmd_empty_packet(pctx->creq->out);
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Found key [%s]\n", keyname);
    entry = result->msgs[0];

    ret = sss_packet_new(pctx->creq, 0, sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    value = ldb_msg_find_attr_as_string(entry, SYSDB_AUTOFS_ENTRY_VALUE, NULL);
    if (value == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No entry value found in [%s]\n", keyname);
        return EINVAL;
    }

    value_len = 1 + strlen(value);
    len = sizeof(uint32_t) + sizeof(uint32_t) + value_len;

    ret = sss_packet_grow(pctx->creq->out, len);
    if (ret != EOK) {
        return ret;
    }

    sss_packet_get_body(pctx->creq->out, &body, &blen);

    rp = 0;
    SAFEALIGN_SET_UINT32(&body[rp], len, &rp);

    SAFEALIGN_SET_UINT32(&body[rp], value_len, &rp);
    if (value_len == 1) {
        body[rp] = '\0';
    } else {
        memcpy(&body[rp], value, value_len);
    }

    return EOK;
}

static void
sss_autofs_cmd_getautomntbyname_done(struct tevent_req *req);

static int
sss_autofs_cmd_getautomntbyname(struct cli_ctx *cli_ctx)
{
    struct autofs_cmd_ctx *cmd_ctx;
    struct autofs_ctx *autofs_ctx;
    struct tevent_req *req;
    errno_t ret;

    autofs_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct autofs_ctx);

    cmd_ctx = talloc_zero(cli_ctx, struct autofs_cmd_ctx);
    if (cmd_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create command context.\n");
        return ENOMEM;
    }

    cmd_ctx->cli_ctx = cli_ctx;
    cmd_ctx->autofs_ctx = autofs_ctx;

    ret = autofs_read_getautomntbyname_input(cli_ctx, &cmd_ctx->mapname,
                                             &cmd_ctx->keyname);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Obtaining autofs entry %s:%s\n",
          cmd_ctx->mapname, cmd_ctx->keyname);

    req = cache_req_autofs_entry_by_name_send(cli_ctx, cli_ctx->ev,
                                              autofs_ctx->rctx,
                                              autofs_ctx->rctx->ncache, 0, NULL,
                                              cmd_ctx->mapname,
                                              cmd_ctx->keyname);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cache_req_autofs_entry_by_name_send failed\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, sss_autofs_cmd_getautomntbyname_done, cmd_ctx);

    ret = EOK;

done:
    return autofs_cmd_done(cmd_ctx, ret);
}

static void
sss_autofs_cmd_getautomntbyname_done(struct tevent_req *req)
{
    struct cache_req_result *result;
    struct autofs_cmd_ctx *cmd_ctx;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(req, struct autofs_cmd_ctx);

    ret = cache_req_autofs_entry_by_name_recv(cmd_ctx, req, &result);
    talloc_zfree(req);
    if (ret != EOK) {
        autofs_cmd_done(cmd_ctx, ret);
        return;
    }

    ret = autofs_write_getautomntbyname_output(cmd_ctx->cli_ctx, result,
                                               cmd_ctx->keyname);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create reply packet "
              "[%d]: %s\n", ret, sss_strerror(ret));
        autofs_cmd_done(cmd_ctx, ret);
        return;
    }

    sss_cmd_done(cmd_ctx->cli_ctx, NULL);
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version autofs_cli_protocol_version[] = {
        { SSS_AUTOFS_PROTO_VERSION, NULL, NULL }
    };

    return autofs_cli_protocol_version;
}

struct sss_cmd_table *get_autofs_cmds(void)
{
    static struct sss_cmd_table autofs_cmds[] = {
        { SSS_GET_VERSION, sss_cmd_get_version },
        { SSS_AUTOFS_SETAUTOMNTENT, sss_autofs_cmd_setautomntent },
        { SSS_AUTOFS_GETAUTOMNTENT, sss_autofs_cmd_getautomntent },
        { SSS_AUTOFS_GETAUTOMNTBYNAME, sss_autofs_cmd_getautomntbyname },
        { SSS_AUTOFS_ENDAUTOMNTENT, sss_autofs_cmd_endautomntent },
        { SSS_CLI_NULL, NULL}
    };

    return autofs_cmds;
}

int autofs_connection_setup(struct cli_ctx *cctx)
{
    int ret;

    ret = sss_connection_setup(cctx);
    if (ret != EOK) return ret;

    return EOK;
}
