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

#include "ldb.h"
#include "ldb_errors.h"
#include "util/util.h"
#include "nss/nsssrv.h"
#include "nss/nsssrv_ldb.h"

struct nss_cmd_ctx {
    struct cli_ctx *cctx;
};

struct nss_cmd_table {
    enum sss_nss_command cmd;
    int (*fn)(struct cli_ctx *cctx);
};

static int nss_cmd_get_version(struct cli_ctx *cctx)
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

static int fill_pwent(struct nss_packet *packet,
                      struct ldb_message **msgs,
                      int count)
{
    struct ldb_message *msg;
    uint8_t *body;
    const char *name;
    const char *fullname;
    const char *homedir;
    const char *shell;
    uint64_t uid;
    uint64_t gid;
    size_t rsize, rp, blen;
    size_t s1, s2, s3, s4;
    int i, ret, num = 0;

    /* first 2 fieldss (len and reserved), filled up later */
    ret = nss_packet_grow(packet, 2*sizeof(uint32_t));
    rp = 2*sizeof(uint32_t);

    for (i = 0; i < count; i++) {
        msg = msgs[i];

        name = ldb_msg_find_attr_as_string(msg, NSS_PW_NAME, NULL);
        fullname = ldb_msg_find_attr_as_string(msg, NSS_PW_FULLNAME, NULL);
        homedir = ldb_msg_find_attr_as_string(msg, NSS_PW_HOMEDIR, NULL);
        shell = ldb_msg_find_attr_as_string(msg, NSS_PW_SHELL, NULL);
        uid = ldb_msg_find_attr_as_uint64(msg, NSS_PW_UIDNUM, 0);
        gid = ldb_msg_find_attr_as_uint64(msg, NSS_PW_GIDNUM, 0);

        if (!name || !fullname || !homedir || !shell || !uid || !gid) {
            DEBUG(1, ("Incomplede user object for %s! Skipping\n",
                      name?name:"<NULL>"));
            continue;
        }

        s1 = strlen(name) + 1;
        s2 = strlen(fullname) + 1;
        s3 = strlen(homedir) + 1;
        s4 = strlen(shell) + 1;
        rsize = 2*sizeof(uint64_t) +s1 + 2 + s2 + s3 +s4;

        ret = nss_packet_grow(packet, rsize);
        if (ret != RES_SUCCESS) {
            num = 0;
            goto done;
        }
        nss_get_body(packet, &body, &blen);

        ((uint64_t *)(&body[rp]))[0] = uid;
        ((uint64_t *)(&body[rp]))[1] = gid;
        rp += 2*sizeof(uint64_t);
        memcpy(&body[rp], name, s1);
        rp += s1;
        memcpy(&body[rp], "x", 2);
        rp += 2;
        memcpy(&body[rp], fullname, s2);
        rp += s2;
        memcpy(&body[rp], homedir, s3);
        rp += s3;
        memcpy(&body[rp], shell, s4);
        rp += s4;

        num++;
    }

done:
    nss_get_body(packet, &body, &blen);
    ((uint32_t *)body)[0] = num; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

    return RES_SUCCESS;
}

static int nss_cmd_getpwnam_callback(void *ptr, int status,
                                     struct ldb_result *res)
{
    struct nss_cmd_ctx *nctx = talloc_get_type(ptr, struct nss_cmd_ctx);
    struct cli_ctx *cctx = nctx->cctx;
    uint8_t *body;
    size_t blen;
    int ret;

    if (res->count != 1) {
        if (res->count > 1) {
            DEBUG(1, ("getpwnam call returned more than oine result !?!\n"));
        }
        if (res->count == 0) {
            DEBUG(2, ("No results for getpwnam call"));
        }
        ret = nss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                             nss_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != RES_SUCCESS) {
            return ret;
        }
        nss_get_body(cctx->creq->out, &body, &blen);
        ((uint32_t *)body)[0] = 0; /* 0 results */
        ((uint32_t *)body)[1] = 0; /* reserved */
        goto done;
    }

    /* create response packet */
    ret = nss_packet_new(cctx->creq, 0,
                         nss_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != RES_SUCCESS) {
        return ret;
    }

    ret = fill_pwent(cctx->creq->out, res->msgs, res->count);

done:
    /* now that the packet is in place, unlock queue
     * making the event writable */
    EVENT_FD_WRITEABLE(cctx->cfde);

    /* free all request related data through the talloc hierarchy */
    talloc_free(nctx);

    return ret;
}

static int nss_cmd_getpwnam(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
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

    nctx = talloc(cctx, struct nss_cmd_ctx);
    if (!nctx) {
        return RES_NOMEM;
    }
    nctx->cctx = cctx;

    ret = nss_ldb_getpwnam(nctx, cctx->ev, cctx->ldb, name,
                           nss_cmd_getpwnam_callback, nctx);

    return ret;
}

struct nss_cmd_table nss_cmds[] = {
    {SSS_NSS_GET_VERSION, nss_cmd_get_version},
    {SSS_NSS_GETPWNAM, nss_cmd_getpwnam},
    {SSS_NSS_NULL, NULL}
};

int nss_cmd_execute(struct cli_ctx *cctx)
{
    enum sss_nss_command cmd;
    int i;

    cmd = nss_get_cmd(cctx->creq->in);

    for (i = 0; nss_cmds[i].cmd != SSS_NSS_NULL; i++) {
        if (cmd == nss_cmds[i].cmd) {
            return nss_cmds[i].fn(cctx);
        }
    }

    return RES_INVALID_DATA;
}
