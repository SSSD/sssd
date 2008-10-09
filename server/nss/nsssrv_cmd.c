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

struct getent_ctx {
    struct ldb_result *pwds;
    struct ldb_result *grps;
    int pwd_cur;
    int grp_cur;
};

struct nss_cmd_table {
    enum sss_nss_command cmd;
    int (*fn)(struct cli_ctx *cctx);
};

static void nss_cmd_done(struct nss_cmd_ctx *nctx)
{
    /* now that the packet is in place, unlock queue
     * making the event writable */
    EVENT_FD_WRITEABLE(nctx->cctx->cfde);

    /* free all request related data through the talloc hierarchy */
    talloc_free(nctx);
}

static int nss_cmd_get_version(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    uint8_t *body;
    size_t blen;
    int ret;

    nctx = talloc(cctx, struct nss_cmd_ctx);
    if (!nctx) {
        return ENOMEM;
    }
    nctx->cctx = cctx;

    /* create response packet */
    ret = nss_packet_new(cctx->creq, sizeof(uint32_t),
                         nss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }
    nss_packet_get_body(cctx->creq->out, &body, &blen);
    ((uint32_t *)body)[0] = SSS_NSS_VERSION;

    nss_cmd_done(nctx);
    return EOK;
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
            DEBUG(1, ("Incomplede user object for %s[%llu]! Skipping\n",
                      name?name:"<NULL>", (unsigned long long int)uid));
            continue;
        }

        s1 = strlen(name) + 1;
        s2 = strlen(fullname) + 1;
        s3 = strlen(homedir) + 1;
        s4 = strlen(shell) + 1;
        rsize = 2*sizeof(uint64_t) +s1 + 2 + s2 + s3 +s4;

        ret = nss_packet_grow(packet, rsize);
        if (ret != EOK) {
            num = 0;
            goto done;
        }
        nss_packet_get_body(packet, &body, &blen);

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
    nss_packet_get_body(packet, &body, &blen);
    ((uint32_t *)body)[0] = num; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

    return EOK;
}

static int nss_cmd_getpw_callback(void *ptr, int status,
                                  struct ldb_result *res)
{
    struct nss_cmd_ctx *nctx = talloc_get_type(ptr, struct nss_cmd_ctx);
    struct cli_ctx *cctx = nctx->cctx;
    uint8_t *body;
    size_t blen;
    int ret;

    /* create response packet */
    ret = nss_packet_new(cctx->creq, 0,
                         nss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    if (status != LDB_SUCCESS) {
        nss_packet_set_error(cctx->creq->out, status);
        goto done;
    }

    if (res->count != 1) {
        if (res->count > 1) {
            DEBUG(1, ("getpwnam call returned more than oine result !?!\n"));
        }
        if (res->count == 0) {
            DEBUG(2, ("No results for getpwnam call"));
        }
        ret = nss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                             nss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            return ret;
        }
        nss_packet_get_body(cctx->creq->out, &body, &blen);
        ((uint32_t *)body)[0] = 0; /* 0 results */
        ((uint32_t *)body)[1] = 0; /* reserved */
        goto done;
    }

    ret = fill_pwent(cctx->creq->out, res->msgs, res->count);
    nss_packet_set_error(cctx->creq->out, ret);

done:
    nss_cmd_done(nctx);
    return EOK;
}

static int nss_cmd_getpwnam(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    uint8_t *body;
    size_t blen;
    int ret;
    const char *name;

    /* get user name to query */
    nss_packet_get_body(cctx->creq->in, &body, &blen);
    name = (const char *)body;
    /* if not terminated fail */
    if (name[blen -1] != '\0') {
        return EINVAL;
    }

    nctx = talloc(cctx, struct nss_cmd_ctx);
    if (!nctx) {
        return ENOMEM;
    }
    nctx->cctx = cctx;

    ret = nss_ldb_getpwnam(nctx, cctx->ev, cctx->ldb, name,
                           nss_cmd_getpw_callback, nctx);

    return ret;
}

static int nss_cmd_getpwuid(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    uint8_t *body;
    size_t blen;
    int ret;
    uint64_t uid;

    /* get uid to query */
    nss_packet_get_body(cctx->creq->in, &body, &blen);

    if (blen != sizeof(uint64_t)) {
        return EINVAL;
    }

    uid = *((uint64_t *)body);

    nctx = talloc(cctx, struct nss_cmd_ctx);
    if (!nctx) {
        return ENOMEM;
    }
    nctx->cctx = cctx;

    ret = nss_ldb_getpwuid(nctx, cctx->ev, cctx->ldb, uid,
                           nss_cmd_getpw_callback, nctx);

    return ret;
}

/* to keep it simple at this stage we are retrieving the
 * full enumeration again for each request for each process
 * and we also block on setpwent() for the full time needed
 * to retrieve the data. And endpwent() frees all the data.
 * Next steps are:
 * - use and nsssrv wide cache with data already structured
 *   so that it can be immediately returned (see nscd way)
 * - use mutexes so that setpwent() can return immediately
 *   even if the data is still being fetched
 * - make getpwent() wait on the mutex
 */
static int nss_cmd_setpwent_callback(void *ptr, int status,
                                     struct ldb_result *res)
{
    struct nss_cmd_ctx *nctx = talloc_get_type(ptr, struct nss_cmd_ctx);
    struct cli_ctx *cctx = nctx->cctx;
    struct getent_ctx *gctx = cctx->gctx;
    int ret;

    /* create response packet */
    ret = nss_packet_new(cctx->creq, 0,
                         nss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    if (status != LDB_SUCCESS) {
        nss_packet_set_error(cctx->creq->out, status);
        goto done;
    }

    gctx->pwds = talloc_steal(gctx, res);

done:
    nss_cmd_done(nctx);
    return EOK;
}

static int nss_cmd_setpwent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    struct getent_ctx *gctx;
    int ret;

    nctx = talloc(cctx, struct nss_cmd_ctx);
    if (!nctx) {
        return ENOMEM;
    }
    nctx->cctx = cctx;

    if (cctx->gctx == NULL) {
        gctx = talloc_zero(cctx, struct getent_ctx);
        if (!gctx) {
            talloc_free(nctx);
            return ENOMEM;
        }
        cctx->gctx = gctx;
    }
    if (cctx->gctx->pwds) {
        talloc_free(cctx->gctx->pwds);
        cctx->gctx->pwds = NULL;
        cctx->gctx->pwd_cur = 0;
    }

    ret = nss_ldb_enumpwent(nctx, cctx->ev, cctx->ldb,
                            nss_cmd_setpwent_callback, nctx);

    return ret;
}

static int nss_cmd_retpwent(struct cli_ctx *cctx, int num)
{
    struct getent_ctx *gctx = cctx->gctx;
    int n, ret;

    n = gctx->pwds->count - gctx->pwd_cur;
    if (n > num) n = num;

    ret = fill_pwent(cctx->creq->out, &(gctx->pwds->msgs[gctx->pwd_cur]), n);
    gctx->pwd_cur += n;

    return ret;
}

/* used only if a process calls getpwent() without first calling setpwent()
 * in this case we basically trigger an implicit setpwent() */
static int nss_cmd_getpwent_callback(void *ptr, int status,
                                     struct ldb_result *res)
{
    struct nss_cmd_ctx *nctx = talloc_get_type(ptr, struct nss_cmd_ctx);
    struct cli_ctx *cctx = nctx->cctx;
    struct getent_ctx *gctx = cctx->gctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    int ret;

    /* get max num of entries to return in one call */
    nss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }
    num = *((uint32_t *)body);

    /* create response packet */
    ret = nss_packet_new(cctx->creq, 0,
                         nss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    if (status != LDB_SUCCESS) {
        nss_packet_set_error(cctx->creq->out, status);
        goto done;
    }

    gctx->pwds = talloc_steal(gctx, res);

    ret = nss_cmd_retpwent(cctx, num);
    nss_packet_set_error(cctx->creq->out, ret);

done:
    nss_cmd_done(nctx);
    return EOK;
}

static int nss_cmd_getpwent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    struct getent_ctx *gctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    int ret;

    /* get max num of entries to return in one call */
    nss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }
    num = *((uint32_t *)body);

    nctx = talloc(cctx, struct nss_cmd_ctx);
    if (!nctx) {
        return ENOMEM;
    }
    nctx->cctx = cctx;

    /* see if we need to trigger an implicit setpwent() */
    if (cctx->gctx == NULL || cctx->gctx->pwds == NULL) {
        if (cctx->gctx == NULL) {
            gctx = talloc_zero(cctx, struct getent_ctx);
            if (!gctx) {
                talloc_free(nctx);
                return ENOMEM;
            }
            cctx->gctx = gctx;
        }
        if (cctx->gctx->pwds == NULL) {
            ret = nss_ldb_enumpwent(nctx, cctx->ev, cctx->ldb,
                                    nss_cmd_getpwent_callback, nctx);
            return ret;
        }
    }

    /* create response packet */
    ret = nss_packet_new(cctx->creq, 0,
                         nss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    ret = nss_cmd_retpwent(cctx, num);
    nss_packet_set_error(cctx->creq->out, ret);
    nss_cmd_done(nctx);
    return EOK;
}

static int nss_cmd_endpwent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    int ret;

    nctx = talloc(cctx, struct nss_cmd_ctx);
    if (!nctx) {
        return ENOMEM;
    }
    nctx->cctx = cctx;

    /* create response packet */
    ret = nss_packet_new(cctx->creq, 0,
                         nss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);

    if (cctx->gctx == NULL) goto done;
    if (cctx->gctx->pwds == NULL) goto done;

    /* free results and reset */
    talloc_free(cctx->gctx->pwds);
    cctx->gctx->pwds = NULL;
    cctx->gctx->pwd_cur = 0;

done:
    nss_cmd_done(nctx);
    return EOK;
}

struct nss_cmd_table nss_cmds[] = {
    {SSS_NSS_GET_VERSION, nss_cmd_get_version},
    {SSS_NSS_GETPWNAM, nss_cmd_getpwnam},
    {SSS_NSS_GETPWUID, nss_cmd_getpwuid},
    {SSS_NSS_SETPWENT, nss_cmd_setpwent},
    {SSS_NSS_GETPWENT, nss_cmd_getpwent},
    {SSS_NSS_ENDPWENT, nss_cmd_endpwent},
    {SSS_NSS_NULL, NULL}
};

int nss_cmd_execute(struct cli_ctx *cctx)
{
    enum sss_nss_command cmd;
    int i;

    cmd = nss_packet_get_cmd(cctx->creq->in);

    for (i = 0; nss_cmds[i].cmd != SSS_NSS_NULL; i++) {
        if (cmd == nss_cmds[i].cmd) {
            return nss_cmds[i].fn(cctx);
        }
    }

    return EINVAL;
}
