/*
   SSSD

   SSS Client Responder, command parser

   Copyright (C) Simo Sorce <ssorce@redhat.com> 2008

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
#include "db/sysdb.h"
#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"


int sss_cmd_send_error(struct cli_ctx *cctx, int err)
{
    struct cli_protocol *pctx;
    int ret;

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);
    if (!pctx) return EINVAL;

    /* create response packet */
    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create new packet: %d\n", ret);
        return ret;
    }

    sss_packet_set_error(pctx->creq->out, err);
    return EOK;
}

int sss_cmd_empty_packet(struct sss_packet *packet)
{
    uint8_t *body;
    size_t blen;
    int ret;

    ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
    if (ret != EOK) return ret;

    sss_packet_get_body(packet, &body, &blen);

    /* num results */
    SAFEALIGN_SETMEM_UINT32(body, 0, NULL);

    /* reserved */
    SAFEALIGN_SETMEM_UINT32(body + sizeof(uint32_t), 0, NULL);

    return EOK;
}

int sss_cmd_send_empty(struct cli_ctx *cctx)
{
    struct cli_protocol *pctx;
    int ret;

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);
    if (!pctx) return EINVAL;

    /* create response packet */
    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_cmd_empty_packet(pctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    sss_packet_set_error(pctx->creq->out, EOK);
    return EOK;
}

void sss_cmd_done(struct cli_ctx *cctx, void *freectx)
{
    /* now that the packet is in place, unlock queue
     * making the event writable */
    TEVENT_FD_WRITEABLE(cctx->cfde);

    /* free all request related data through the talloc hierarchy */
    talloc_free(freectx);
}

int sss_cmd_get_version(struct cli_ctx *cctx)
{
    struct cli_protocol *pctx;
    uint8_t *req_body;
    size_t req_blen;
    uint8_t *body;
    size_t blen;
    int ret;
    uint32_t client_version;
    uint32_t protocol_version;
    int i;
    static struct cli_protocol_version *cli_protocol_version = NULL;

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);
    if (!pctx) return EINVAL;

    pctx->cli_protocol_version = NULL;

    if (cli_protocol_version == NULL) {
        cli_protocol_version = register_cli_protocol_version();
    }

    if (cli_protocol_version != NULL) {
        pctx->cli_protocol_version = &cli_protocol_version[0];

        sss_packet_get_body(pctx->creq->in, &req_body, &req_blen);
        if (req_blen == sizeof(uint32_t)) {
            memcpy(&client_version, req_body, sizeof(uint32_t));
            DEBUG(SSSDBG_FUNC_DATA,
                  "Received client version [%d].\n", client_version);

            i=0;
            while(cli_protocol_version[i].version>0) {
                if (cli_protocol_version[i].version == client_version) {
                    pctx->cli_protocol_version = &cli_protocol_version[i];
                    break;
                }
                i++;
            }
        }
    }

    /* create response packet */
    ret = sss_packet_new(pctx->creq, sizeof(uint32_t),
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        return ret;
    }
    sss_packet_get_body(pctx->creq->out, &body, &blen);

    protocol_version = (pctx->cli_protocol_version != NULL)
                       ? pctx->cli_protocol_version->version : 0;

    SAFEALIGN_COPY_UINT32(body, &protocol_version, NULL);
    DEBUG(SSSDBG_FUNC_DATA, "Offered version [%d].\n", protocol_version);

    sss_cmd_done(cctx, NULL);
    return EOK;
}

int sss_cmd_execute(struct cli_ctx *cctx,
                    enum sss_cli_command cmd,
                    struct sss_cmd_table *sss_cmds)
{
    int i;

    for (i = 0; sss_cmds[i].cmd != SSS_CLI_NULL; i++) {
        if (cmd == sss_cmds[i].cmd) {
            return sss_cmds[i].fn(cctx);
        }
    }

    return EINVAL;
}
struct setent_req_list {
    struct setent_req_list *prev;
    struct setent_req_list *next;
    /* Need to modify the list from a talloc destructor */
    struct setent_req_list **head;

    struct tevent_req *req;
};

struct tevent_req *
setent_get_req(struct setent_req_list *sl)
{
    return sl->req;
}

int setent_remove_ref(TALLOC_CTX *ctx)
{
    struct setent_req_list *entry =
            talloc_get_type(ctx, struct setent_req_list);
    DLIST_REMOVE(*(entry->head), entry);
    return 0;
}

errno_t setent_add_ref(TALLOC_CTX *memctx,
                       struct setent_req_list **list,
                       struct tevent_req *req)
{
    struct setent_req_list *entry;

    entry = talloc_zero(memctx, struct setent_req_list);
    if (!entry) {
        return ENOMEM;
    }

    entry->req = req;
    DLIST_ADD_END(*list, entry, struct setent_req_list *);
    entry->head = list;

    talloc_set_destructor((TALLOC_CTX *)entry, setent_remove_ref);
    return EOK;
}

void setent_notify(struct setent_req_list **list, errno_t err)
{
    struct setent_req_list *reql;

    /* Notify the waiting clients */
    while ((reql = *list) != NULL) {
        /* Each tevent_req_done() call will free
         * the request, removing it from the list.
         */
        if (err == EOK) {
            tevent_req_done(reql->req);
        } else {
            tevent_req_error(reql->req, err);
        }

        if (reql == *list) {
            /* The consumer failed to free the
             * request. Log a bug and continue.
             */
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "BUG: a callback did not free its request. "
                   "May leak memory\n");
            /* Skip to the next since a memory leak is non-fatal */
            *list = (*list)->next;
        }
    }
}

void setent_notify_done(struct setent_req_list **list)
{
    return setent_notify(list, EOK);
}

/*
 * Return values:
 *  EOK     -   cache hit
 *  EAGAIN  -   cache hit, but schedule off band update
 *  ENOENT  -   cache miss
 */
errno_t
sss_cmd_check_cache(struct ldb_message *msg,
                    int cache_refresh_percent,
                    uint64_t cache_expire)
{
    uint64_t lastUpdate;
    uint64_t midpoint_refresh = 0;
    time_t now;

    now = time(NULL);
    lastUpdate = ldb_msg_find_attr_as_uint64(msg, SYSDB_LAST_UPDATE, 0);
    midpoint_refresh = 0;

    if(cache_refresh_percent) {
        midpoint_refresh = lastUpdate +
            (cache_expire - lastUpdate)*cache_refresh_percent/100.0;
        if (midpoint_refresh - lastUpdate < 10) {
            /* If the percentage results in an expiration
             * less than ten seconds after the lastUpdate time,
             * that's too often we will simply set it to 10s
             */
            midpoint_refresh = lastUpdate+10;
        }
    }

    if (cache_expire > now) {
        /* cache still valid */

        if (midpoint_refresh && midpoint_refresh < now) {
            /* We're past the cache refresh timeout
             * We'll return the value from the cache, but we'll also
             * queue the cache entry for update out-of-band.
             */
            return EAGAIN;
        } else {
            /* Cache is still valid. */
            return EOK;
        }
    }

    /* Cache needs to be updated */
    return ENOENT;
}
