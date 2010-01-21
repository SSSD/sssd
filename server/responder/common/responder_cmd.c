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
#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"


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
    uint8_t *req_body;
    size_t req_blen;
    uint8_t *body;
    size_t blen;
    int ret;
    uint32_t client_version;
    int i;
    static struct cli_protocol_version *cli_protocol_version = NULL;

    cctx->cli_protocol_version = NULL;

    if (cli_protocol_version == NULL) {
        cli_protocol_version = register_cli_protocol_version();
    }

    if (cli_protocol_version != NULL) {
        cctx->cli_protocol_version = &cli_protocol_version[0];

        sss_packet_get_body(cctx->creq->in, &req_body, &req_blen);
        if (req_blen == sizeof(uint32_t)) {
            memcpy(&client_version, req_body, sizeof(uint32_t));
            DEBUG(5, ("Received client version [%d].\n", client_version));

            i=0;
            while(cli_protocol_version[i].version>0) {
                if (cli_protocol_version[i].version == client_version) {
                    cctx->cli_protocol_version = &cli_protocol_version[i];
                    break;
                }
                i++;
            }
        }
    }

    /* create response packet */
    ret = sss_packet_new(cctx->creq, sizeof(uint32_t),
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }
    sss_packet_get_body(cctx->creq->out, &body, &blen);
    ((uint32_t *)body)[0] = cctx->cli_protocol_version!=NULL ?
                                cctx->cli_protocol_version->version : 0;
    DEBUG(5, ("Offered version [%d].\n", ((uint32_t *)body)[0]));

    sss_cmd_done(cctx, NULL);
    return EOK;
}

int sss_cmd_execute(struct cli_ctx *cctx, struct sss_cmd_table *sss_cmds)
{
    enum sss_cli_command cmd;
    int i;

    cmd = sss_packet_get_cmd(cctx->creq->in);

    for (i = 0; sss_cmds[i].cmd != SSS_CLI_NULL; i++) {
        if (cmd == sss_cmds[i].cmd) {
            return sss_cmds[i].fn(cctx);
        }
    }

    return EINVAL;
}
