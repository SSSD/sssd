/*
   SSSD

   NSS Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#include "util/util.h"
#include "nss/nsssrv.h"

struct nss_cmd_table {
    enum sss_nss_command cmd;
    int (*fn)(struct event_context *ev, struct cli_ctx *cctx);
};

static int nss_cmd_get_version(struct event_context *ev,
                               struct cli_ctx *cctx)
{
    uint8_t *body;
    size_t blen;
    int ret;

    /* create response packet */
    ret = nss_packet_new(cctx->creq, sizeof(uint32_t),
                         nss_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != RES_SUCCESS) {
        return ret;
    }
    nss_get_body(cctx->creq->out, &body, &blen);
    ((uint32_t *)body)[0] = SSS_NSS_VERSION;

    /* now that the packet is in place, unlock queue
     * making the event writable */
    EVENT_FD_WRITEABLE(cctx->cfde);

    return RES_SUCCESS;
}

static int nss_cmd_getpwnam(struct event_context *ev,
                            struct cli_ctx *cctx)
{
    uint8_t *body;
    size_t blen;
    int ret;
    const char *name;

    /* get user name to query */
    nss_get_body(cctx->creq->in, &body, &blen);
    name = (const char *)body;
    /* if not terminated fail */
    if (name[blen -1] != '\0') {
        return RES_INVALID_DATA;
    }

    /* TODO: async search data and return */

    /* fake data for now */

    /* create response packet */
    ret = nss_packet_new(cctx->creq, 4+4+(8+8+4+2+4+10+10),
                         nss_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != RES_SUCCESS) {
        return ret;
    }
    nss_get_body(cctx->creq->out, &body, &blen);

    ((uint32_t *)body)[0] = 1; /* 1 result */
    ((uint32_t *)body)[1] = 0; /* reserved */
    ((uint64_t *)body)[1] = 1234; /* first result uid */
    ((uint64_t *)body)[2] = 1234; /* first result gid */

    name = "foo\0x\0foo\0/home/foo\0/bin/bash\0";
    memcpy(&body[24], name, (8+8+4+2+4+10+10));

    /* now that the packet is in place, unlock queue
     * making the event writable */
    EVENT_FD_WRITEABLE(cctx->cfde);

    return RES_SUCCESS;
}

struct nss_cmd_table nss_cmds[] = {
    {SSS_NSS_GET_VERSION, nss_cmd_get_version},
    {SSS_NSS_GETPWNAM, nss_cmd_getpwnam},
    {SSS_NSS_NULL, NULL}
};

int nss_cmd_execute(struct event_context *ev, struct cli_ctx *cctx)
{
    enum sss_nss_command cmd;
    int i;

    cmd = nss_get_cmd(cctx->creq->in);

    for (i = 0; nss_cmds[i].cmd != SSS_NSS_NULL; i++) {
        if (cmd == nss_cmds[i].cmd) {
            return nss_cmds[i].fn(ev, cctx);
        }
    }

    return RES_INVALID_DATA;
}
