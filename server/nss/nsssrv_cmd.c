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
#include "util/btreemap.h"
#include "nss/nsssrv.h"
#include "db/sysdb.h"
#include <time.h>

struct nss_cmd_ctx {
    struct cli_ctx *cctx;
    const char *domain;
    const char *name;
    uid_t id;
    bool check_expiration;
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

static int nss_cmd_send_error(struct nss_cmd_ctx *nctx, int err)
{
    struct cli_ctx *cctx = nctx->cctx;
    int ret;

    /* create response packet */
    ret = nss_packet_new(cctx->creq, 0,
                         nss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    nss_packet_set_error(cctx->creq->out, err);

    nss_cmd_done(nctx);
    return EOK;
}

#define NSS_CMD_FATAL_ERROR(cctx) do { \
    DEBUG(1,("Fatal error, killing connection!")); \
    talloc_free(cctx); \
    return; \
} while(0)

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

/****************************************************************************
 * PASSWD db related functions
 ***************************************************************************/

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
    int i, ret, num;

    /* first 2 fields (len and reserved), filled up later */
    ret = nss_packet_grow(packet, 2*sizeof(uint32_t));
    rp = 2*sizeof(uint32_t);

    num = 0;
    for (i = 0; i < count; i++) {
        msg = msgs[i];

        name = ldb_msg_find_attr_as_string(msg, SYSDB_PW_NAME, NULL);
        fullname = ldb_msg_find_attr_as_string(msg, SYSDB_PW_FULLNAME, NULL);
        homedir = ldb_msg_find_attr_as_string(msg, SYSDB_PW_HOMEDIR, NULL);
        shell = ldb_msg_find_attr_as_string(msg, SYSDB_PW_SHELL, NULL);
        uid = ldb_msg_find_attr_as_uint64(msg, SYSDB_PW_UIDNUM, 0);
        gid = ldb_msg_find_attr_as_uint64(msg, SYSDB_PW_GIDNUM, 0);

        if (!name || !fullname || !homedir || !shell || !uid || !gid) {
            DEBUG(1, ("Incomplete user object for %s[%llu]! Skipping\n",
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

static void nss_cmd_getpwnam_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr);
static void nss_cmd_getpwuid_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr);

static void nss_cmd_getpw_callback(void *ptr, int status,
                                   struct ldb_result *res)
{
    struct nss_cmd_ctx *nctx = talloc_get_type(ptr, struct nss_cmd_ctx);
    struct cli_ctx *cctx = nctx->cctx;
    nss_dp_callback_t callback_fn;
    int timeout;
    uint64_t lastUpdate;
    uint8_t *body;
    size_t blen;
    int ret;

    if (status != LDB_SUCCESS) {
        ret = nss_cmd_send_error(nctx, status);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        return;
    }

    if (nctx->name) {
        callback_fn = &nss_cmd_getpwnam_callback;
    } else {
        callback_fn = &nss_cmd_getpwuid_callback;
    }

    if (res->count == 0 && nctx->check_expiration) {

        /* dont loop forever :-) */
        nctx->check_expiration = false;
        timeout = SSS_NSS_SOCKET_TIMEOUT/2;

        ret = nss_dp_send_acct_req(cctx->nctx, nctx, callback_fn, nctx,
                                   timeout, "*", NSS_DP_USER,
                                   nctx->name, nctx->id);
        if (ret != EOK) {
            DEBUG(3, ("Failed to dispatch request: %d(%s)",
                      ret, strerror(ret)));
            ret = nss_cmd_send_error(nctx, ret);
        }
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }

        return;
    }

    if (res->count != 1) {
        if (res->count > 1) {
            DEBUG(1, ("getpwnam call returned more than one result !?!\n"));
        }
        if (res->count == 0) {
            DEBUG(2, ("No results for getpwnam call\n"));
        }
        ret = nss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                             nss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        nss_packet_get_body(cctx->creq->out, &body, &blen);
        ((uint32_t *)body)[0] = 0; /* 0 results */
        ((uint32_t *)body)[1] = 0; /* reserved */
        goto done;
    }

    if (nctx->check_expiration) {
        timeout = nctx->cctx->nctx->cache_timeout;

        lastUpdate = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_LAST_UPDATE, 0);
        if (lastUpdate + timeout < time(NULL)) {

            /* dont loop forever :-) */
            nctx->check_expiration = false;
            timeout = SSS_NSS_SOCKET_TIMEOUT/2;

            ret = nss_dp_send_acct_req(cctx->nctx, nctx, callback_fn, nctx,
                                       timeout, "*", NSS_DP_USER,
                                       nctx->name, nctx->id);
            if (ret != EOK) {
                DEBUG(3, ("Failed to dispatch request: %d(%s)",
                          ret, strerror(ret)));
                ret = nss_cmd_send_error(nctx, ret);
            }
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }

            return;
        }
    }

    /* create response packet */
    ret = nss_packet_new(cctx->creq, 0,
                         nss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        NSS_CMD_FATAL_ERROR(cctx);
    }

    ret = fill_pwent(cctx->creq->out, res->msgs, res->count);
    nss_packet_set_error(cctx->creq->out, ret);

done:
    nss_cmd_done(nctx);
}

static int nss_parse_name(TALLOC_CTX *memctx,
                          const char *fullname,
                          struct btreemap *domain_map,
                          const char **domain, const char **name) {
    char *delim;
    struct btreemap *node;
    int ret;

    if ((delim = strchr(fullname, NSS_DOMAIN_DELIM)) != NULL) {

        /* Check for registered domain */
        ret = btreemap_search_key(domain_map, (void *)(delim+1), &node);
        if (ret != BTREEMAP_FOUND) {
            /* No such domain was registered. Return EINVAL.
             * TODO: alternative approach?
             * Alternatively, we could simply fail down to
             * below, treating the entire construct as the
             * full name if the domain is unspecified.
             */
            return EINVAL;
        }

        *name = talloc_strndup(memctx, fullname, delim-fullname);
        *domain = talloc_strdup(memctx, delim+1);
    }
    else {
        *name = talloc_strdup(memctx, fullname);
        *domain = NULL;
    }

    return EOK;
}

static void nss_cmd_getpwnam_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_cmd_ctx *nctx = talloc_get_type(ptr, struct nss_cmd_ctx);
    struct cli_ctx *cctx = nctx->cctx;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = sysdb_getpwnam(nctx, cctx->ev, cctx->nctx->sysdb,
                         nctx->domain, nctx->name,
                         nss_cmd_getpw_callback, nctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(nctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
    }
}

static int nss_cmd_getpwnam(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    uint8_t *body;
    size_t blen;
    int ret;

    nctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!nctx) {
        return ENOMEM;
    }
    nctx->cctx = cctx;
    nctx->check_expiration = true;

    /* get user name to query */
    nss_packet_get_body(cctx->creq->in, &body, &blen);
    /* if not terminated fail */
    if (body[blen -1] != '\0') {
        talloc_free(nctx);
        return EINVAL;
    }

    ret = nss_parse_name(nctx, (const char *)body,
                         cctx->nctx->domain_map,
                         &nctx->domain, &nctx->name);
    if (ret != EOK) {
        DEBUG(1, ("Invalid name received\n"));
        talloc_free(nctx);
        return ret;
    }
    DEBUG(4, ("Requesting info for [%s] from [%s]\n",
              nctx->name, nctx->domain?nctx->domain:"all domains"));

    ret = sysdb_getpwnam(nctx, cctx->ev, cctx->nctx->sysdb,
                         nctx->domain, nctx->name,
                         nss_cmd_getpw_callback, nctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(nctx, ret);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

static void nss_cmd_getpwuid_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_cmd_ctx *nctx = talloc_get_type(ptr, struct nss_cmd_ctx);
    struct cli_ctx *cctx = nctx->cctx;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = sysdb_getpwuid(nctx, cctx->ev, cctx->nctx->sysdb,
                         nctx->domain, nctx->id,
                         nss_cmd_getpw_callback, nctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(nctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
    }
}

static int nss_cmd_getpwuid(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    uint8_t *body;
    size_t blen;
    int ret;

    nctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!nctx) {
        return ENOMEM;
    }
    nctx->cctx = cctx;
    nctx->check_expiration = true;

    /* get uid to query */
    nss_packet_get_body(cctx->creq->in, &body, &blen);

    if (blen != sizeof(uint64_t)) {
        return EINVAL;
    }

    nctx->id = (uid_t)*((uint64_t *)body);

    /* FIXME: Just ask all backends for now, until we check for ranges */
    nctx->domain = NULL;

    DEBUG(4, ("Requesting info for [%lu]@[%s]\n", nctx->id, nctx->domain));

    ret = sysdb_getpwuid(nctx, cctx->ev, cctx->nctx->sysdb,
                         nctx->domain, nctx->id,
                         nss_cmd_getpw_callback, nctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(nctx, ret);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
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
static void nss_cmd_setpwent_callback(void *ptr, int status,
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
        NSS_CMD_FATAL_ERROR(cctx);
    }

    if (status != LDB_SUCCESS) {
        nss_packet_set_error(cctx->creq->out, status);
        goto done;
    }

    gctx->pwds = talloc_steal(gctx, res);

done:
    nss_cmd_done(nctx);
}

static int nss_cmd_setpwent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    struct getent_ctx *gctx;
    int ret;

    DEBUG(4, ("Requesting info for all accounts\n"));

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

    ret = sysdb_enumpwent(nctx, cctx->ev, cctx->nctx->sysdb,
                          nss_cmd_setpwent_callback, nctx);

    return ret;
}

static int nss_cmd_retpwent(struct cli_ctx *cctx, int num)
{
    struct getent_ctx *gctx = cctx->gctx;
    int n, ret;

    n = gctx->pwds->count - gctx->pwd_cur;
    if (n > num) n = num;

    ret = fill_pwent(cctx->creq->out,
                     &(gctx->pwds->msgs[gctx->pwd_cur]), n);
    gctx->pwd_cur += n;

    return ret;
}

/* used only if a process calls getpwent() without first calling setpwent()
 * in this case we basically trigger an implicit setpwent() */
static void nss_cmd_getpwent_callback(void *ptr, int status,
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
        NSS_CMD_FATAL_ERROR(cctx);
    }
    num = *((uint32_t *)body);

    /* create response packet */
    ret = nss_packet_new(cctx->creq, 0,
                         nss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        NSS_CMD_FATAL_ERROR(cctx);
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
}

static int nss_cmd_getpwent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    struct getent_ctx *gctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    int ret;

    DEBUG(4, ("Requesting info for all accounts\n"));

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
            ret = sysdb_enumpwent(nctx, cctx->ev, cctx->nctx->sysdb,
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

    DEBUG(4, ("Terminating request info for all accounts\n"));

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

/****************************************************************************
 * GROUP db related functions
 ***************************************************************************/

static int fill_grent(struct nss_packet *packet,
                      struct ldb_message **msgs,
                      int count)
{
    struct ldb_message *msg;
    uint8_t *body;
    const char *name;
    uint64_t gid;
    size_t rsize, rp, blen, mnump;
    int i, ret, num, memnum;
    bool get_group = true;

    /* first 2 fields (len and reserved), filled up later */
    ret = nss_packet_grow(packet, 2*sizeof(uint32_t));
    rp = 2*sizeof(uint32_t);

    num = 0;
    mnump = 0;
    for (i = 0; i < count; i++) {
        msg = msgs[i];

        if (get_group) {
            /* find group name/gid */
            name = ldb_msg_find_attr_as_string(msg, SYSDB_GR_NAME, NULL);
            gid = ldb_msg_find_attr_as_uint64(msg, SYSDB_GR_GIDNUM, 0);
            if (!name || !gid) {
                DEBUG(1, ("Incomplete group object for %s[%llu]! Aborting\n",
                          name?name:"<NULL>", (unsigned long long int)gid));
                num = 0;
                goto done;
            }

            /* fill in gid and name and set pointer for number of members */
            rsize = sizeof(uint64_t) + sizeof(uint32_t) + strlen(name)+1 +2;
            ret = nss_packet_grow(packet, rsize);
            nss_packet_get_body(packet, &body, &blen);
            rp = blen - rsize;
            ((uint64_t *)(&body[rp]))[0] = gid;
            rp += sizeof(uint64_t);
            ((uint32_t *)(&body[rp]))[0] = 0; /* init members num to 0 */
            mnump = rp; /* keep around pointer to set members num later */
            rp += sizeof(uint32_t);
            memcpy(&body[rp], name, strlen(name)+1);
            body[blen-2] = 'x'; /* group passwd field */
            body[blen-1] = '\0';

            get_group = false;
            memnum = 0;
            num++;
            continue;
        }

        name = ldb_msg_find_attr_as_string(msg, SYSDB_PW_NAME, NULL);

        if (!name) {
            /* last member of previous group found, or error.
             * set next element to be a group, and eventually
             * fail there if here start bogus entries */
            get_group = true;
            i--;
            nss_packet_get_body(packet, &body, &blen);
            ((uint32_t *)(&body[mnump]))[0] = memnum; /* num members */
            continue;
        }

        rsize = strlen(name) + 1;

        ret = nss_packet_grow(packet, rsize);
        if (ret != EOK) {
            num = 0;
            goto done;
        }
        nss_packet_get_body(packet, &body, &blen);
        rp = blen - rsize;
        memcpy(&body[rp], name, rsize);

        memnum++;
    }

    /* fill in the last group member count */
    if (mnump != 0) {
        nss_packet_get_body(packet, &body, &blen);
        ((uint32_t *)(&body[mnump]))[0] = memnum; /* num members */
    }

done:
    nss_packet_get_body(packet, &body, &blen);
    ((uint32_t *)body)[0] = num; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

    return EOK;
}

static void nss_cmd_getgr_callback(void *ptr, int status,
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
        NSS_CMD_FATAL_ERROR(cctx);
    }

    if (status != LDB_SUCCESS) {
        nss_packet_set_error(cctx->creq->out, status);
        goto done;
    }

    if (res->count == 0) {
        DEBUG(2, ("No results for getpwnam call"));

        ret = nss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                             nss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        nss_packet_get_body(cctx->creq->out, &body, &blen);
        ((uint32_t *)body)[0] = 0; /* 0 results */
        ((uint32_t *)body)[1] = 0; /* reserved */
        goto done;
    }

    ret = fill_grent(cctx->creq->out, res->msgs, res->count);
    nss_packet_set_error(cctx->creq->out, ret);

done:
    nss_cmd_done(nctx);
}

static int nss_cmd_getgrnam(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    uint8_t *body;
    size_t blen;
    int ret;

    nctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!nctx) {
        return ENOMEM;
    }
    nctx->cctx = cctx;
    nctx->check_expiration = true;

    /* get group name to query */
    nss_packet_get_body(cctx->creq->in, &body, &blen);
    nctx->name = (const char *)body;
    /* if not terminated fail */
    if (nctx->name[blen -1] != '\0') {
        return EINVAL;
    }

    /* FIXME: Just ask all backends for now, until Steve provides for name
     * parsing code */
    nctx->domain = NULL;

    DEBUG(4, ("Requesting info for [%s]@[%s]\n", nctx->name, nctx->domain));

    ret = sysdb_getgrnam(nctx, cctx->ev, cctx->nctx->sysdb,
                         nctx->domain, nctx->name,
                         nss_cmd_getgr_callback, nctx);

    return ret;
}

static int nss_cmd_getgrgid(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    uint8_t *body;
    size_t blen;
    int ret;

    nctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!nctx) {
        return ENOMEM;
    }
    nctx->cctx = cctx;
    nctx->check_expiration = true;

    /* get gid to query */
    nss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen != sizeof(uint64_t)) {
        return EINVAL;
    }
    nctx->id = (uid_t)*((uint64_t *)body);

    /* FIXME: Just ask all backends for now, until we check for ranges */
    nctx->domain = NULL;

    DEBUG(4, ("Requesting info for [%lu]@[%s]\n", nctx->id, nctx->domain));

    ret = sysdb_getgrgid(nctx, cctx->ev, cctx->nctx->sysdb,
                         nctx->domain, nctx->id,
                         nss_cmd_getgr_callback, nctx);

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
static void nss_cmd_setgrent_callback(void *ptr, int status,
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
        NSS_CMD_FATAL_ERROR(cctx);
    }

    if (status != LDB_SUCCESS) {
        nss_packet_set_error(cctx->creq->out, status);
        goto done;
    }

    gctx->grps = talloc_steal(gctx, res);

done:
    nss_cmd_done(nctx);
}

static int nss_cmd_setgrent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    struct getent_ctx *gctx;
    int ret;

    DEBUG(4, ("Requesting info for all groups\n"));

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
    if (cctx->gctx->grps) {
        talloc_free(cctx->gctx->grps);
        cctx->gctx->grps = NULL;
        cctx->gctx->grp_cur = 0;
    }

    ret = sysdb_enumgrent(nctx, cctx->ev, cctx->nctx->sysdb,
                          nss_cmd_setgrent_callback, nctx);

    return ret;
}

static int nss_cmd_retgrent(struct cli_ctx *cctx, int num)
{
    struct getent_ctx *gctx = cctx->gctx;
    int n, ret;

    n = gctx->grps->count - gctx->grp_cur;
    if (n > num) n = num;

    ret = fill_grent(cctx->creq->out,
                     &(gctx->grps->msgs[gctx->grp_cur]), n);
    gctx->grp_cur += n;

    return ret;
}

/* used only if a process calls getpwent() without first calling setpwent()
 * in this case we basically trigger an implicit setpwent() */
static void nss_cmd_getgrent_callback(void *ptr, int status,
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
        ret = nss_cmd_send_error(nctx, EIO);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
    }
    num = *((uint32_t *)body);

    /* create response packet */
    ret = nss_packet_new(cctx->creq, 0,
                         nss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        NSS_CMD_FATAL_ERROR(cctx);
    }

    if (status != LDB_SUCCESS) {
        nss_packet_set_error(cctx->creq->out, status);
        goto done;
    }

    gctx->grps = talloc_steal(gctx, res);

    ret = nss_cmd_retgrent(cctx, num);
    nss_packet_set_error(cctx->creq->out, ret);

done:
    nss_cmd_done(nctx);
}

static int nss_cmd_getgrent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    struct getent_ctx *gctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    int ret;

    DEBUG(4, ("Requesting info for all groups\n"));

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
    if (cctx->gctx == NULL || cctx->gctx->grps == NULL) {
        if (cctx->gctx == NULL) {
            gctx = talloc_zero(cctx, struct getent_ctx);
            if (!gctx) {
                talloc_free(nctx);
                return ENOMEM;
            }
            cctx->gctx = gctx;
        }
        if (cctx->gctx->grps == NULL) {
            ret = sysdb_enumgrent(nctx, cctx->ev, cctx->nctx->sysdb,
                                  nss_cmd_getgrent_callback, nctx);
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

    ret = nss_cmd_retgrent(cctx, num);
    nss_packet_set_error(cctx->creq->out, ret);
    nss_cmd_done(nctx);
    return EOK;
}

static int nss_cmd_endgrent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    int ret;

    DEBUG(4, ("Terminating request info for all groups\n"));

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
    if (cctx->gctx->grps == NULL) goto done;

    /* free results and reset */
    talloc_free(cctx->gctx->grps);
    cctx->gctx->grps = NULL;
    cctx->gctx->grp_cur = 0;

done:
    nss_cmd_done(nctx);
    return EOK;
}

static void nss_cmd_initgr_callback(void *ptr, int status,
                                   struct ldb_result *res)
{
    struct nss_cmd_ctx *nctx = talloc_get_type(ptr, struct nss_cmd_ctx);
    struct cli_ctx *cctx = nctx->cctx;
    uint8_t *body;
    size_t blen;
    uint64_t gid;
    uint32_t num;
    int ret, i;

    /* create response packet */
    ret = nss_packet_new(cctx->creq, 0,
                         nss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        NSS_CMD_FATAL_ERROR(cctx);
    }

    if (status != LDB_SUCCESS) {
        nss_packet_set_error(cctx->creq->out, status);
        goto done;
    }

    num = res->count;
    /* the first 64 bit uint is really 2 32 units used to hold the number of
     * results */
    ret = nss_packet_grow(cctx->creq->out, (1 + num) * sizeof(uint64_t));
    if (ret != EOK) {
        nss_packet_set_error(cctx->creq->out, ret);
        goto done;
    }
    nss_packet_get_body(cctx->creq->out, &body, &blen);

    for (i = 0; i < num; i++) {
        gid = ldb_msg_find_attr_as_uint64(res->msgs[i], SYSDB_GR_GIDNUM, 0);
        if (!gid) {
            DEBUG(1, ("Incomplete group object for initgroups! Aborting\n"));
            nss_packet_set_error(cctx->creq->out, EIO);
            num = 0;
            goto done;
        }
        ((uint64_t *)body)[i+1] = gid;
    }

    ((uint32_t *)body)[0] = num; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

done:
    nss_cmd_done(nctx);
}

static int nss_cmd_initgroups(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *nctx;
    uint8_t *body;
    size_t blen;
    int ret;

    nctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!nctx) {
        return ENOMEM;
    }
    nctx->cctx = cctx;
    nctx->check_expiration = true;

    /* get user name to query */
    nss_packet_get_body(cctx->creq->in, &body, &blen);
    nctx->name = (const char *)body;
    /* if not terminated fail */
    if (nctx->name[blen -1] != '\0') {
        return EINVAL;
    }

    /* FIXME: Just ask all backends for now, until Steve provides for name
     * parsing code */
    nctx->domain = NULL;

    DEBUG(4, ("Requesting info for [%s]@[%s]\n", nctx->name, nctx->domain));


    ret = sysdb_initgroups(nctx, cctx->ev, cctx->nctx->sysdb,
                           nctx->domain, nctx->name,
                           nss_cmd_initgr_callback, nctx);

    return ret;
}

struct nss_cmd_table nss_cmds[] = {
    {SSS_NSS_GET_VERSION, nss_cmd_get_version},
    {SSS_NSS_GETPWNAM, nss_cmd_getpwnam},
    {SSS_NSS_GETPWUID, nss_cmd_getpwuid},
    {SSS_NSS_SETPWENT, nss_cmd_setpwent},
    {SSS_NSS_GETPWENT, nss_cmd_getpwent},
    {SSS_NSS_ENDPWENT, nss_cmd_endpwent},
    {SSS_NSS_GETGRNAM, nss_cmd_getgrnam},
    {SSS_NSS_GETGRGID, nss_cmd_getgrgid},
    {SSS_NSS_SETGRENT, nss_cmd_setgrent},
    {SSS_NSS_GETGRENT, nss_cmd_getgrent},
    {SSS_NSS_ENDGRENT, nss_cmd_endgrent},
    {SSS_NSS_INITGR, nss_cmd_initgroups},
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

