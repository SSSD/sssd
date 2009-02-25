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
#include "responder/common/responder_packet.h"
#include "responder/nss/nsssrv.h"
#include "db/sysdb.h"
#include <time.h>

struct nss_cmd_ctx {
    struct cli_ctx *cctx;
    const char *name;
    uid_t id;

    bool immediate;
    bool done;
    int nr;
};

struct getent_ctx {
    struct ldb_result *pwds;
    struct ldb_result *grps;
    int pwd_cur;
    int grp_cur;
};

struct nss_dom_ctx {
    struct nss_cmd_ctx *cmdctx;
    const char *domain;
    bool check_provider;
    bool legacy;
};

struct nss_cmd_table {
    enum sss_cli_command cmd;
    int (*fn)(struct cli_ctx *cctx);
};

static void nss_cmd_done(struct nss_cmd_ctx *cmdctx)
{
    /* now that the packet is in place, unlock queue
     * making the event writable */
    TEVENT_FD_WRITEABLE(cmdctx->cctx->cfde);

    /* free all request related data through the talloc hierarchy */
    talloc_free(cmdctx);
}

static int nss_cmd_send_error(struct nss_cmd_ctx *cmdctx, int err)
{
    struct cli_ctx *cctx = cmdctx->cctx;
    int ret;

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    sss_packet_set_error(cctx->creq->out, err);
    return EOK;
}

#define NSS_CMD_FATAL_ERROR(cctx) do { \
    DEBUG(1,("Fatal error, killing connection!")); \
    talloc_free(cctx); \
    return; \
} while(0)

static int nss_parse_name(struct nss_dom_ctx *dctx, const char *fullname)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct nss_ctx *nctx = cmdctx->cctx->nctx;
    struct nss_domain_info *info;
    struct btreemap *domain_map;
    char *delim;
    char *domain;

    domain_map = nctx->domain_map;

    if ((delim = strchr(fullname, NSS_DOMAIN_DELIM)) != NULL) {
        domain = delim+1;
    } else {
        domain = nctx->default_domain;
    }

    /* Check for registered domain */
    info = btreemap_get_value(domain_map, (void *)domain);
    if (!info) {
        /* No such domain was registered. Return EINVAL.
         * TODO: alternative approach?
         * Alternatively, we could simply fail down to
         * below, treating the entire construct as the
         * full name if the domain is unspecified.
         */
        return EINVAL;
    }

    dctx->check_provider = info->has_provider;
    dctx->legacy = info->legacy;

    dctx->domain = talloc_strdup(dctx, domain);
    if (!dctx->domain) return ENOMEM;

    if (delim) {
        cmdctx->name = talloc_strndup(cmdctx, fullname, delim-fullname);
    } else {
        cmdctx->name = talloc_strdup(cmdctx, fullname);
    }
    if (!cmdctx->name) return ENOMEM;

    return EOK;
}

static int nss_cmd_get_version(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    uint8_t *body;
    size_t blen;
    int ret;

    cmdctx = talloc(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    /* create response packet */
    ret = sss_packet_new(cctx->creq, sizeof(uint32_t),
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }
    sss_packet_get_body(cctx->creq->out, &body, &blen);
    ((uint32_t *)body)[0] = SSS_PROTOCOL_VERSION;

    nss_cmd_done(cmdctx);
    return EOK;
}

/****************************************************************************
 * PASSWD db related functions
 ***************************************************************************/

static int fill_pwent(struct sss_packet *packet,
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
    ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
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

        ret = sss_packet_grow(packet, rsize);
        if (ret != EOK) {
            num = 0;
            goto done;
        }
        sss_packet_get_body(packet, &body, &blen);

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
    sss_packet_get_body(packet, &body, &blen);
    ((uint32_t *)body)[0] = num; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

    return EOK;
}

static void nss_cmd_getpwnam_dp_callback(uint16_t err_maj, uint32_t err_min,
                                        const char *err_msg, void *ptr);

static void nss_cmd_getpwnam_callback(void *ptr, int status,
                                   struct ldb_result *res)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int timeout;
    uint64_t lastUpdate;
    uint8_t *body;
    size_t blen;
    bool call_provider = false;
    int ret;

    if (status != LDB_SUCCESS) {
        ret = nss_cmd_send_error(cmdctx, status);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        goto done;
    }

    if (dctx->check_provider) {
        switch (res->count) {
        case 0:
            call_provider = true;
            break;

        case 1:
            timeout = cmdctx->cctx->nctx->cache_timeout;

            lastUpdate = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                     SYSDB_LAST_UPDATE, 0);
            if (lastUpdate + timeout < time(NULL)) {
                call_provider = true;
            }
            break;

        default:
            DEBUG(1, ("getpwnam call returned more than one result !?!\n"));
            ret = nss_cmd_send_error(cmdctx, ret);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
            goto done;
        }
    }

    if (call_provider) {

        /* dont loop forever :-) */
        dctx->check_provider = false;
        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                   nss_cmd_getpwnam_dp_callback, dctx,
                                   timeout, dctx->domain, NSS_DP_USER,
                                   cmdctx->name, 0);
        if (ret != EOK) {
            DEBUG(3, ("Failed to dispatch request: %d(%s)\n",
                      ret, strerror(ret)));
            ret = nss_cmd_send_error(cmdctx, ret);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
            goto done;
        }
        return;
    }

    switch (res->count) {
    case 0:

        DEBUG(2, ("No results for getpwnam call\n"));

        ret = sss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_packet_get_body(cctx->creq->out, &body, &blen);
        ((uint32_t *)body)[0] = 0; /* 0 results */
        ((uint32_t *)body)[1] = 0; /* reserved */
        break;

    case 1:
        /* create response packet */
        ret = sss_packet_new(cctx->creq, 0,
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        ret = fill_pwent(cctx->creq->out, res->msgs, res->count);
        sss_packet_set_error(cctx->creq->out, ret);

        break;

    default:
        DEBUG(1, ("getpwnam call returned more than one result !?!\n"));
        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
    }

done:
    nss_cmd_done(cmdctx);
}

static void nss_cmd_getpwnam_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = sysdb_getpwnam(cmdctx, cctx->ev, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->name,
                         dctx->legacy,
                         nss_cmd_getpwnam_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        nss_cmd_done(cmdctx);
    }
}

static int nss_cmd_getpwnam(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    uint8_t *body;
    size_t blen;
    int ret;

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) return ENOMEM;
    dctx->cmdctx = cmdctx;

    /* get user name to query */
    sss_packet_get_body(cctx->creq->in, &body, &blen);
    /* if not terminated fail */
    if (body[blen -1] != '\0') {
        talloc_free(cmdctx);
        return EINVAL;
    }

    ret = nss_parse_name(dctx, (const char *)body);
    if (ret != EOK) {
        DEBUG(1, ("Invalid name received\n"));
        talloc_free(cmdctx);
        return ret;
    }
    DEBUG(4, ("Requesting info for [%s] from [%s]\n",
              cmdctx->name, dctx->domain));

    ret = sysdb_getpwnam(cmdctx, cctx->ev, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->name,
                         dctx->legacy,
                         nss_cmd_getpwnam_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret == EOK) {
            nss_cmd_done(cmdctx);
        }
        return ret;
    }

    return EOK;
}

static void nss_cmd_getpwuid_dp_callback(uint16_t err_maj, uint32_t err_min,
                                        const char *err_msg, void *ptr);

static void nss_cmd_getpwuid_callback(void *ptr, int status,
                                      struct ldb_result *res)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int timeout;
    uint64_t lastUpdate;
    uint8_t *body;
    size_t blen;
    bool call_provider = false;
    int ret;

    /* one less to go */
    cmdctx->nr--;

    /* check if another callback already replied */
    if (cmdctx->done) {
        /* now check if this is the last callback */
        if (cmdctx->nr == 0) {
            /* ok we are really done with this request */
            goto done;
        }
    }

    if (status != LDB_SUCCESS) {
        ret = nss_cmd_send_error(cmdctx, status);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        goto done;
    }

    if (dctx->check_provider) {
        switch (res->count) {
        case 0:
            call_provider = true;
            break;

        case 1:
            timeout = cmdctx->cctx->nctx->cache_timeout;

            lastUpdate = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                     SYSDB_LAST_UPDATE, 0);
            if (lastUpdate + timeout < time(NULL)) {
                call_provider = true;
            }
            break;

        default:
            DEBUG(1, ("getpwuid call returned more than one result !?!\n"));
            ret = nss_cmd_send_error(cmdctx, ret);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
            goto done;
        }
    }

    if (call_provider) {

        /* yet one more call to go */
        cmdctx->nr++;

        /* dont loop forever :-) */
        dctx->check_provider = false;
        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                   nss_cmd_getpwuid_dp_callback, dctx,
                                   timeout, dctx->domain, NSS_DP_USER,
                                   NULL, cmdctx->id);
        if (ret != EOK) {
            DEBUG(3, ("Failed to dispatch request: %d(%s)\n",
                      ret, strerror(ret)));
            ret = nss_cmd_send_error(cmdctx, ret);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
            goto done;
        }
        return;
    }

    switch (res->count) {
    case 0:
        if (cmdctx->nr != 0) {
            /* nothing to do */
            return;
        }

        DEBUG(2, ("No results for getpwuid call\n"));

        ret = sss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_packet_get_body(cctx->creq->out, &body, &blen);
        ((uint32_t *)body)[0] = 0; /* 0 results */
        ((uint32_t *)body)[1] = 0; /* reserved */
        break;

    case 1:
        /* create response packet */
        ret = sss_packet_new(cctx->creq, 0,
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }

        ret = fill_pwent(cctx->creq->out, res->msgs, res->count);
        sss_packet_set_error(cctx->creq->out, ret);

        break;

    default:
        DEBUG(1, ("getpwnam call returned more than one result !?!\n"));
        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
    }

done:
    if (cmdctx->nr != 0) {
        cmdctx->done = true; /* signal that we are done */
        return;
    }
    nss_cmd_done(cmdctx);
}

static void nss_cmd_getpwuid_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = sysdb_getpwuid(cmdctx, cctx->ev, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->id,
                         dctx->legacy,
                         nss_cmd_getpwuid_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        if (cmdctx->nr != 0) {
            cmdctx->done = true; /* signal that we are done */
            return;
        }
        nss_cmd_done(cmdctx);
    }
}

static int nss_cmd_getpwuid(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct nss_domain_info *info;
    const char **domains;
    uint8_t *body;
    size_t blen;
    int i, num, ret;

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    /* get uid to query */
    sss_packet_get_body(cctx->creq->in, &body, &blen);

    if (blen != sizeof(uint64_t)) {
        return EINVAL;
    }

    cmdctx->id = (uid_t)*((uint64_t *)body);

    /* FIXME: Just ask all backends for now, until we check for ranges */
    dctx = NULL;
    domains = NULL;
    num = 0;
    /* get domains list */
    btreemap_get_keys(cmdctx, cctx->nctx->domain_map,
                      (const void ***)&domains, &num);

    cmdctx->nr = num;

    for (i = 0; i < num; i++) {
        info = btreemap_get_value(cctx->nctx->domain_map, domains[i]);

        dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
        if (!dctx) return ENOMEM;

        dctx->cmdctx = cmdctx;
        dctx->domain = talloc_strdup(dctx, domains[i]);
        if (!dctx->domain) return ENOMEM;
        dctx->check_provider = info->has_provider;
        dctx->legacy = info->legacy;


        DEBUG(4, ("Requesting info for [%lu@%s]\n",
                  cmdctx->id, dctx->domain));

        ret = sysdb_getpwuid(cmdctx, cctx->ev, cctx->nctx->sysdb,
                             dctx->domain, cmdctx->id,
                             dctx->legacy,
                             nss_cmd_getpwuid_callback, dctx);
        if (ret != EOK) {
            DEBUG(1, ("Failed to make request to our cache!\n"));
            /* shutdown ? */

            ret = nss_cmd_send_error(cmdctx, ret);
            if (ret == EOK) {
                nss_cmd_done(cmdctx);
            }
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
 * - use an nsssrv wide cache with data already structured
 *   so that it can be immediately returned (see nscd way)
 * - use mutexes so that setpwent() can return immediately
 *   even if the data is still being fetched
 * - make getpwent() wait on the mutex
 */
static void nss_cmd_getpwent_callback(void *ptr, int status,
                                      struct ldb_result *res);

static void nss_cmd_setpwent_callback(void *ptr, int status,
                                        struct ldb_result *res)
{
    struct nss_cmd_ctx *cmdctx = talloc_get_type(ptr, struct nss_cmd_ctx);
    struct cli_ctx *cctx = cmdctx->cctx;
    struct getent_ctx *gctx = cctx->gctx;
    struct ldb_result *store = gctx->pwds;
    int i, j, c, ret;

    cmdctx->nr--;

    if (cmdctx->done) {
        /* do not reply until all domain searches are done */
        if (cmdctx->nr != 0) return;
        else goto done;
    }

    if (status != LDB_SUCCESS) {
        /* create response packet */
        ret = sss_packet_new(cctx->creq, 0,
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_packet_set_error(cctx->creq->out, status);
        cmdctx->done = true;
        return;
    }

    if (store) {
            c = store->count + res->count;
            store->msgs = talloc_realloc(store, store->msgs,
                                         struct ldb_message *, c);
            if (!store->msgs) NSS_CMD_FATAL_ERROR(cctx);

            for (i = store->count, j = 0; i < c; i++, j++) {
                store->msgs[i] = talloc_steal(store->msgs, res->msgs[j]);
                if (!store->msgs[i]) NSS_CMD_FATAL_ERROR(cctx);
            }
            store->count = c;
            talloc_free(res);
    } else {
        gctx->pwds = talloc_steal(gctx, res);
    }

    /* do not reply until all domain searches are done */
    if (cmdctx->nr) return;

    if (cmdctx->immediate) {
        /* this was a getpwent call w/o setpwent,
         * return immediately one result */
        nss_cmd_getpwent_callback(ptr, status, res);

        return;
    }

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        NSS_CMD_FATAL_ERROR(cctx);
    }

done:
    nss_cmd_done(cmdctx);
}

static void nss_cmd_setpw_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = sysdb_enumpwent(cmdctx, cctx->ev, cctx->nctx->sysdb,
                          dctx->domain, dctx->legacy,
                          nss_cmd_setpwent_callback, cmdctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        nss_cmd_done(cmdctx);
    }
}

static int nss_cmd_setpwent_ext(struct cli_ctx *cctx, bool immediate)
{
    struct nss_domain_info *info;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct getent_ctx *gctx;
    const char **domains;
    int timeout;
    int i, ret, num;

    DEBUG(4, ("Requesting info for all users\n"));

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    if (cctx->gctx == NULL) {
        gctx = talloc_zero(cctx, struct getent_ctx);
        if (!gctx) {
            talloc_free(cmdctx);
            return ENOMEM;
        }
        cctx->gctx = gctx;
    }
    if (cctx->gctx->pwds) {
        talloc_free(cctx->gctx->pwds);
        cctx->gctx->pwds = NULL;
        cctx->gctx->pwd_cur = 0;
    }

    cmdctx->immediate = immediate;

    domains = NULL;
    num = 0;
    /* get domains list */
    btreemap_get_keys(cmdctx, cctx->nctx->domain_map,
                      (const void ***)&domains, &num);

    /* check if enumeration is enabled in any domain */
    for (i = 0; i < num; i++) {
        info = btreemap_get_value(cctx->nctx->domain_map, domains[i]);

        if ((info->enumerate & NSS_ENUM_USERS) == 0) {
            continue;
        }

        /* TODO: enabled, check if we have a recent cached enumeration */

        /* ok no cache, go and ask the backend to enumerate */
        dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
        if (!dctx) return ENOMEM;

        dctx->cmdctx = cmdctx;
        dctx->domain = talloc_strdup(dctx, domains[i]);
        if (!dctx->domain) return ENOMEM;
        dctx->check_provider = info->has_provider;
        dctx->legacy = info->legacy;

        if (dctx->check_provider) {
            timeout = SSS_CLI_SOCKET_TIMEOUT/(i+2);
            ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                       nss_cmd_setpw_dp_callback, dctx,
                                       timeout, domains[i], NSS_DP_USER,
                                       NULL, 0);
        } else {
            ret = sysdb_enumpwent(dctx, cctx->ev, cctx->nctx->sysdb,
                                  dctx->domain, dctx->legacy,
                                  nss_cmd_setpwent_callback, cmdctx);
        }
        if (ret != EOK) {
            /* FIXME: shutdown ? */
            DEBUG(1, ("Failed to send enumeration request for domain [%s]!\n",
                      domains[i]));
            continue;
        }

        /* number of replies to wait for before setpwent is done */
        cmdctx->nr++;
    }

    if (cmdctx->nr == 0) {
        /* create response packet */
        ret = sss_packet_new(cctx->creq, 0,
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            return ret;
        }

        sss_packet_set_error(cctx->creq->out, ret);
        nss_cmd_done(cmdctx);
        return EOK;
    }

    return ret;
}

static int nss_cmd_setpwent(struct cli_ctx *cctx)
{
    return nss_cmd_setpwent_ext(cctx, false);
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
 */
static void nss_cmd_getpwent_callback(void *ptr, int status,
                                      struct ldb_result *res)
{
    struct nss_cmd_ctx *cmdctx = talloc_get_type(ptr, struct nss_cmd_ctx);
    struct cli_ctx *cctx = cmdctx->cctx;
    struct getent_ctx *gctx = cctx->gctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    int ret;

    /* get max num of entries to return in one call */
    sss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen != sizeof(uint32_t)) {
        NSS_CMD_FATAL_ERROR(cctx);
    }
    num = *((uint32_t *)body);

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        NSS_CMD_FATAL_ERROR(cctx);
    }

    if (status != LDB_SUCCESS) {
        sss_packet_set_error(cctx->creq->out, status);
        goto done;
    }

    gctx->pwds = talloc_steal(gctx, res);

    ret = nss_cmd_retpwent(cctx, num);
    sss_packet_set_error(cctx->creq->out, ret);

done:
    nss_cmd_done(cmdctx);
}

static int nss_cmd_getpwent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct getent_ctx *gctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    int ret;

    DEBUG(4, ("Requesting info for all accounts\n"));

    /* get max num of entries to return in one call */
    sss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }
    num = *((uint32_t *)body);

    /* see if we need to trigger an implicit setpwent() */
    if (cctx->gctx == NULL || cctx->gctx->pwds == NULL) {
        if (cctx->gctx == NULL) {
            gctx = talloc_zero(cctx, struct getent_ctx);
            if (!gctx) {
                return ENOMEM;
            }
            cctx->gctx = gctx;
        }
        if (cctx->gctx->pwds == NULL) {
            ret = nss_cmd_setpwent_ext(cctx, true);
            return ret;
        }
    }

    cmdctx = talloc(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    ret = nss_cmd_retpwent(cctx, num);
    sss_packet_set_error(cctx->creq->out, ret);
    nss_cmd_done(cmdctx);
    return EOK;
}

static int nss_cmd_endpwent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    int ret;

    DEBUG(4, ("Terminating request info for all accounts\n"));

    cmdctx = talloc(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);

    if (cctx->gctx == NULL) goto done;
    if (cctx->gctx->pwds == NULL) goto done;

    /* free results and reset */
    talloc_free(cctx->gctx->pwds);
    cctx->gctx->pwds = NULL;
    cctx->gctx->pwd_cur = 0;

done:
    nss_cmd_done(cmdctx);
    return EOK;
}

/****************************************************************************
 * GROUP db related functions
 ***************************************************************************/

static int fill_grent(struct sss_packet *packet,
                      struct ldb_message **msgs,
                      int count)
{
    struct ldb_message_element *el;
    struct ldb_message *msg;
    uint8_t *body;
    const char *name;
    uint64_t gid;
    size_t rsize, rp, blen, mnump;
    int i, j, ret, num, memnum;
    bool get_group = true;
    bool memnum_set = false;

    /* first 2 fields (len and reserved), filled up later */
    ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
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
            ret = sss_packet_grow(packet, rsize);
            sss_packet_get_body(packet, &body, &blen);
            rp = blen - rsize;
            ((uint64_t *)(&body[rp]))[0] = gid;
            rp += sizeof(uint64_t);
            ((uint32_t *)(&body[rp]))[0] = 0; /* init members num to 0 */
            mnump = rp; /* keep around members num pointer to set later */
            rp += sizeof(uint32_t);
            memcpy(&body[rp], name, strlen(name)+1);
            body[blen-2] = 'x'; /* group passwd field */
            body[blen-1] = '\0';

            memnum_set = false;
            memnum = 0;
            num++;

            /* legacy style group, members are in SYSDB_LEGACY_MEMBER */
            el = ldb_msg_find_element(msg, SYSDB_LEGACY_MEMBER);
            if (el) {
                /* legacy */
                memnum = el->num_values;

                for (j = 0; j < memnum; j++) {
                    rsize = el->values[j].length + 1;
                    ret = sss_packet_grow(packet, rsize);
                    if (ret != EOK) {
                        num = 0;
                        goto done;
                    }

                    sss_packet_get_body(packet, &body, &blen);
                    rp = blen - rsize;
                    memcpy(&body[rp], el->values[j].data, el->values[j].length);
                    body[blen-1] = '\0';
                }

                sss_packet_get_body(packet, &body, &blen);
                ((uint32_t *)(&body[mnump]))[0] = memnum; /* num members */
                memnum_set = true;

            }  else {
                get_group = false;
            }

            continue;
        }

        name = ldb_msg_find_attr_as_string(msg, SYSDB_PW_NAME, NULL);

        if (!name) {
            /* last member of previous group found, or error.
             * set next element to be a group, and eventually
             * fail there if here start bogus entries */
            get_group = true;
            i--;
            sss_packet_get_body(packet, &body, &blen);
            ((uint32_t *)(&body[mnump]))[0] = memnum; /* num members */
            memnum_set = true;
            continue;
        }

        rsize = strlen(name) + 1;

        ret = sss_packet_grow(packet, rsize);
        if (ret != EOK) {
            num = 0;
            goto done;
        }
        sss_packet_get_body(packet, &body, &blen);
        rp = blen - rsize;
        memcpy(&body[rp], name, rsize);

        memnum++;
    }

    if (!memnum_set) {
        /* fill in the last group member count */
        if (mnump != 0) {
            sss_packet_get_body(packet, &body, &blen);
            ((uint32_t *)(&body[mnump]))[0] = memnum; /* num members */
        }
    }

done:
    sss_packet_get_body(packet, &body, &blen);
    ((uint32_t *)body)[0] = num; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

    return EOK;
}

static void nss_cmd_getgrnam_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr);

static void nss_cmd_getgrnam_callback(void *ptr, int status,
                                   struct ldb_result *res)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int timeout;
    uint64_t lastUpdate;
    uint8_t *body;
    size_t blen;
    bool call_provider = false;
    int ret;

    if (status != LDB_SUCCESS) {
        ret = nss_cmd_send_error(cmdctx, status);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        nss_cmd_done(cmdctx);
        return;
    }

    if (dctx->check_provider) {
        switch (res->count) {
        case 0:
            call_provider = true;
            break;

        default:
            timeout = cmdctx->cctx->nctx->cache_timeout;

            lastUpdate = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                     SYSDB_LAST_UPDATE, 0);
            if (lastUpdate + timeout < time(NULL)) {
                call_provider = true;
            }
        }
    }

    if (call_provider) {

        /* dont loop forever :-) */
        dctx->check_provider = false;
        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                   nss_cmd_getgrnam_dp_callback, dctx,
                                   timeout, dctx->domain, NSS_DP_GROUP,
                                   cmdctx->name, 0);
        if (ret != EOK) {
            DEBUG(3, ("Failed to dispatch request: %d(%s)\n",
                      ret, strerror(ret)));
            ret = nss_cmd_send_error(cmdctx, ret);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
            goto done;
        }

        return;
    }

    switch (res->count) {
    case 0:

        DEBUG(2, ("No results for getgrnam call\n"));

        ret = sss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_packet_get_body(cctx->creq->out, &body, &blen);
        ((uint32_t *)body)[0] = 0; /* 0 results */
        ((uint32_t *)body)[1] = 0; /* reserved */
        break;

    default:

        DEBUG(6, ("Returning info for group [%s]\n", cmdctx->name));

        /* create response packet */
        ret = sss_packet_new(cctx->creq, 0,
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }

        ret = fill_grent(cctx->creq->out, res->msgs, res->count);
        sss_packet_set_error(cctx->creq->out, ret);
    }

done:
    nss_cmd_done(cmdctx);
}

static void nss_cmd_getgrnam_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = sysdb_getgrnam(cmdctx, cctx->ev, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->name,
                         dctx->legacy,
                         nss_cmd_getgrnam_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        nss_cmd_done(cmdctx);
    }
}

static int nss_cmd_getgrnam(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    uint8_t *body;
    size_t blen;
    int ret;

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) return ENOMEM;
    dctx->cmdctx = cmdctx;

    /* get user name to query */
    sss_packet_get_body(cctx->creq->in, &body, &blen);
    /* if not terminated fail */
    if (body[blen -1] != '\0') {
        talloc_free(cmdctx);
        return EINVAL;
    }

    ret = nss_parse_name(dctx, (const char *)body);
    if (ret != EOK) {
        DEBUG(1, ("Invalid name received\n"));
        talloc_free(cmdctx);
        return ret;
    }
    DEBUG(4, ("Requesting info for [%s] from [%s]\n",
              cmdctx->name, dctx->domain));

    ret = sysdb_getgrnam(cmdctx, cctx->ev, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->name,
                         dctx->legacy,
                         nss_cmd_getgrnam_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret == EOK) {
            nss_cmd_done(cmdctx);
        }
        return ret;
    }

    return EOK;
}

static void nss_cmd_getgrgid_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr);

static void nss_cmd_getgrgid_callback(void *ptr, int status,
                                      struct ldb_result *res)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int timeout;
    uint64_t lastUpdate;
    uint8_t *body;
    size_t blen;
    bool call_provider = false;
    int ret;

    /* one less to go */
    cmdctx->nr--;

    /* check if another callback already replied */
    if (cmdctx->done) {
        /* now check if this is the last callback */
        if (cmdctx->nr == 0) {
            /* ok we are really done with this request */
            goto done;
        }
    }

    if (status != LDB_SUCCESS) {
        ret = nss_cmd_send_error(cmdctx, status);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        goto done;
    }

    if (dctx->check_provider) {
        switch (res->count) {
        case 0:
            call_provider = true;
            break;

        default:
            timeout = cmdctx->cctx->nctx->cache_timeout;

            lastUpdate = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                     SYSDB_LAST_UPDATE, 0);
            if (lastUpdate + timeout < time(NULL)) {
                call_provider = true;
            }
        }
    }

    if (call_provider) {

        /* yet one more call to go */
        cmdctx->nr++;

        /* dont loop forever :-) */
        dctx->check_provider = false;
        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                   nss_cmd_getgrgid_dp_callback, dctx,
                                   timeout, dctx->domain, NSS_DP_GROUP,
                                   NULL, cmdctx->id);
        if (ret != EOK) {
            DEBUG(3, ("Failed to dispatch request: %d(%s)\n",
                      ret, strerror(ret)));
            ret = nss_cmd_send_error(cmdctx, ret);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
            goto done;
        }
        return;
    }

    switch (res->count) {
    case 0:
        if (cmdctx->nr != 0) {
            /* nothing to do */
            return;
        }

        DEBUG(2, ("No results for getgrgid call\n"));

        ret = sss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_packet_get_body(cctx->creq->out, &body, &blen);
        ((uint32_t *)body)[0] = 0; /* 0 results */
        ((uint32_t *)body)[1] = 0; /* reserved */
        break;

    default:

        DEBUG(6, ("Returning info for group [%u]\n", (unsigned)cmdctx->id));

        /* create response packet */
        ret = sss_packet_new(cctx->creq, 0,
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }

        ret = fill_grent(cctx->creq->out, res->msgs, res->count);
        sss_packet_set_error(cctx->creq->out, ret);
    }

done:
    if (cmdctx->nr != 0) {
        cmdctx->done = true; /* signal that we are done */
        return;
    }
    nss_cmd_done(cmdctx);
}

static void nss_cmd_getgrgid_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = sysdb_getgrgid(cmdctx, cctx->ev, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->id,
                         dctx->legacy,
                         nss_cmd_getgrgid_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        nss_cmd_done(cmdctx);
    }
}

static int nss_cmd_getgrgid(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct nss_domain_info *info;
    const char **domains;
    uint8_t *body;
    size_t blen;
    int i, num, ret;

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    /* get uid to query */
    sss_packet_get_body(cctx->creq->in, &body, &blen);

    if (blen != sizeof(uint64_t)) {
        return EINVAL;
    }

    cmdctx->id = (gid_t)*((uint64_t *)body);

    /* FIXME: Just ask all backends for now, until we check for ranges */
    dctx = NULL;
    domains = NULL;
    num = 0;
    /* get domains list */
    btreemap_get_keys(cmdctx, cctx->nctx->domain_map,
                      (const void ***)&domains, &num);

    cmdctx->nr = num;

    for (i = 0; i < num; i++) {
        info = btreemap_get_value(cctx->nctx->domain_map, domains[i]);

        dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
        if (!dctx) return ENOMEM;

        dctx->cmdctx = cmdctx;
        dctx->domain = talloc_strdup(dctx, domains[i]);
        if (!dctx->domain) return ENOMEM;
        dctx->check_provider = info->has_provider;
        dctx->legacy = info->legacy;

        DEBUG(4, ("Requesting info for [%lu@%s]\n",
                  cmdctx->id, dctx->domain));

        ret = sysdb_getgrgid(cmdctx, cctx->ev, cctx->nctx->sysdb,
                             dctx->domain, cmdctx->id,
                             dctx->legacy,
                             nss_cmd_getgrgid_callback, dctx);
        if (ret != EOK) {
            DEBUG(1, ("Failed to make request to our cache!\n"));
            /* shutdown ? */

            ret = nss_cmd_send_error(cmdctx, ret);
            if (ret == EOK) {
                nss_cmd_done(cmdctx);
            }
            return ret;
        }
    }

    return EOK;
}

/* to keep it simple at this stage we are retrieving the
 * full enumeration again for each request for each process
 * and we also block on setgrent() for the full time needed
 * to retrieve the data. And endgrent() frees all the data.
 * Next steps are:
 * - use and nsssrv wide cache with data already structured
 *   so that it can be immediately returned (see nscd way)
 * - use mutexes so that setgrent() can return immediately
 *   even if the data is still being fetched
 * - make getgrent() wait on the mutex
 */
static void nss_cmd_getgrent_callback(void *ptr, int status,
                                      struct ldb_result *res);

static void nss_cmd_setgrent_callback(void *ptr, int status,
                                     struct ldb_result *res)
{
    struct nss_cmd_ctx *cmdctx = talloc_get_type(ptr, struct nss_cmd_ctx);
    struct cli_ctx *cctx = cmdctx->cctx;
    struct getent_ctx *gctx = cctx->gctx;
    struct ldb_result *store = gctx->grps;
    int i, j, c, ret;

    cmdctx->nr--;

    if (cmdctx->done) {
        /* do not reply until all domain searches are done */
        if (cmdctx->nr != 0) return;
        else goto done;
    }

    if (status != LDB_SUCCESS) {
        /* create response packet */
        ret = sss_packet_new(cctx->creq, 0,
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_packet_set_error(cctx->creq->out, status);
        cmdctx->done = true;
        return;
    }

    if (store) {
            c = store->count + res->count;
            store->msgs = talloc_realloc(store, store->msgs,
                                         struct ldb_message *, c);
            if (!store->msgs) NSS_CMD_FATAL_ERROR(cctx);

            for (i = store->count, j = 0; i < c; i++, j++) {
                store->msgs[i] = talloc_steal(store->msgs, res->msgs[j]);
                if (!store->msgs[i]) NSS_CMD_FATAL_ERROR(cctx);
            }
            store->count = c;
            talloc_free(res);
    } else {
        gctx->grps = talloc_steal(gctx, res);
    }

    /* do not reply until all domain searches are done */
    if (cmdctx->nr) return;

    if (cmdctx->immediate) {
        /* this was a getgrent call w/o setgrent,
         * return immediately one result */
        nss_cmd_getgrent_callback(ptr, status, res);
        return;
    }

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        NSS_CMD_FATAL_ERROR(cctx);
    }

done:
    nss_cmd_done(cmdctx);
}

static void nss_cmd_setgr_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = sysdb_enumgrent(dctx, cctx->ev, cctx->nctx->sysdb,
                          dctx->domain, dctx->legacy,
                          nss_cmd_setgrent_callback, cmdctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        nss_cmd_done(cmdctx);
    }
}

static int nss_cmd_setgrent_ext(struct cli_ctx *cctx, bool immediate)
{
    struct nss_domain_info *info;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct getent_ctx *gctx;
    const char **domains;
    int timeout;
    int i, ret, num;

    DEBUG(4, ("Requesting info for all groups\n"));

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    if (cctx->gctx == NULL) {
        gctx = talloc_zero(cctx, struct getent_ctx);
        if (!gctx) {
            talloc_free(cmdctx);
            return ENOMEM;
        }
        cctx->gctx = gctx;
    }
    if (cctx->gctx->grps) {
        talloc_free(cctx->gctx->grps);
        cctx->gctx->grps = NULL;
        cctx->gctx->grp_cur = 0;
    }

    cmdctx->immediate = immediate;

    domains = NULL;
    num = 0;
    /* get domains list */
    btreemap_get_keys(cmdctx, cctx->nctx->domain_map,
                      (const void ***)&domains, &num);

    /* check if enumeration is enabled in any domain */
    for (i = 0; i < num; i++) {
        info = btreemap_get_value(cctx->nctx->domain_map, domains[i]);

        if ((info->enumerate & NSS_ENUM_GROUPS) == 0) {
            continue;
        }

        /* TODO: enabled, check if we have a recent cached enumeration */

        /* ok no cache, go and ask the backend to enumerate */
        dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
        if (!dctx) return ENOMEM;

        dctx->cmdctx = cmdctx;
        dctx->domain = talloc_strdup(dctx, domains[i]);
        if (!dctx->domain) return ENOMEM;
        dctx->check_provider = info->has_provider;
        dctx->legacy = info->legacy;

        if (dctx->check_provider) {
            timeout = SSS_CLI_SOCKET_TIMEOUT/(i+2);
            ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                       nss_cmd_setgr_dp_callback, dctx,
                                       timeout, domains[i], NSS_DP_GROUP,
                                       NULL, 0);
        } else {
            ret = sysdb_enumgrent(dctx, cctx->ev, cctx->nctx->sysdb,
                                  dctx->domain, dctx->legacy,
                                  nss_cmd_setgrent_callback, cmdctx);
        }
        if (ret != EOK) {
            /* FIXME: shutdown ? */
            DEBUG(1, ("Failed to send enumeration request for domain [%s]!\n",
                      domains[i]));
            continue;
        }

        cmdctx->nr++;
    }

    if (cmdctx->nr == 0) {
        /* create response packet */
        ret = sss_packet_new(cctx->creq, 0,
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            return ret;
        }

        sss_packet_set_error(cctx->creq->out, ret);
        nss_cmd_done(cmdctx);
        return EOK;
    }

    return ret;
}

static int nss_cmd_setgrent(struct cli_ctx *cctx)
{
    return nss_cmd_setgrent_ext(cctx, false);
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
    struct nss_cmd_ctx *cmdctx = talloc_get_type(ptr, struct nss_cmd_ctx);
    struct cli_ctx *cctx = cmdctx->cctx;
    struct getent_ctx *gctx = cctx->gctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    int ret;

    /* get max num of entries to return in one call */
    sss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen != sizeof(uint32_t)) {
        ret = nss_cmd_send_error(cmdctx, EIO);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        nss_cmd_done(cmdctx);
    }
    num = *((uint32_t *)body);

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        NSS_CMD_FATAL_ERROR(cctx);
    }

    if (status != LDB_SUCCESS) {
        sss_packet_set_error(cctx->creq->out, status);
        goto done;
    }

    gctx->grps = talloc_steal(gctx, res);

    ret = nss_cmd_retgrent(cctx, num);
    sss_packet_set_error(cctx->creq->out, ret);

done:
    nss_cmd_done(cmdctx);
}

static int nss_cmd_getgrent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct getent_ctx *gctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    int ret;

    DEBUG(4, ("Requesting info for all groups\n"));

    /* get max num of entries to return in one call */
    sss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }
    num = *((uint32_t *)body);

    /* see if we need to trigger an implicit setpwent() */
    if (cctx->gctx == NULL || cctx->gctx->grps == NULL) {
        if (cctx->gctx == NULL) {
            gctx = talloc_zero(cctx, struct getent_ctx);
            if (!gctx) {
                return ENOMEM;
            }
            cctx->gctx = gctx;
        }
        if (cctx->gctx->grps == NULL) {
            ret = nss_cmd_setgrent_ext(cctx, true);
            return ret;
        }
    }

    cmdctx = talloc(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    ret = nss_cmd_retgrent(cctx, num);
    sss_packet_set_error(cctx->creq->out, ret);
    nss_cmd_done(cmdctx);
    return EOK;
}

static int nss_cmd_endgrent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    int ret;

    DEBUG(4, ("Terminating request info for all groups\n"));

    cmdctx = talloc(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);

    if (cctx->gctx == NULL) goto done;
    if (cctx->gctx->grps == NULL) goto done;

    /* free results and reset */
    talloc_free(cctx->gctx->grps);
    cctx->gctx->grps = NULL;
    cctx->gctx->grp_cur = 0;

done:
    nss_cmd_done(cmdctx);
    return EOK;
}

static void nss_cmd_initgr_callback(void *ptr, int status,
                                   struct ldb_result *res)
{
    struct nss_cmd_ctx *cmdctx = talloc_get_type(ptr, struct nss_cmd_ctx);
    struct cli_ctx *cctx = cmdctx->cctx;
    uint8_t *body;
    size_t blen;
    uint64_t gid;
    uint32_t num;
    int ret, i;

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        NSS_CMD_FATAL_ERROR(cctx);
    }

    if (status != LDB_SUCCESS) {
        sss_packet_set_error(cctx->creq->out, status);
        goto done;
    }

    num = res->count;
    /* the first 64 bit uint is really 2 32 units used to hold the number of
     * results */
    ret = sss_packet_grow(cctx->creq->out, (1 + num) * sizeof(uint64_t));
    if (ret != EOK) {
        sss_packet_set_error(cctx->creq->out, ret);
        goto done;
    }
    sss_packet_get_body(cctx->creq->out, &body, &blen);

    for (i = 0; i < num; i++) {
        gid = ldb_msg_find_attr_as_uint64(res->msgs[i], SYSDB_GR_GIDNUM, 0);
        if (!gid) {
            DEBUG(1, ("Incomplete group object for initgroups! Aborting\n"));
            sss_packet_set_error(cctx->creq->out, EIO);
            num = 0;
            goto done;
        }
        ((uint64_t *)body)[i+1] = gid;
    }

    ((uint32_t *)body)[0] = num; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

done:
    nss_cmd_done(cmdctx);
}

static void nss_cmd_getinitgr_callback(uint16_t err_maj, uint32_t err_min,
                                       const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = sysdb_initgroups(cmdctx, cctx->ev, cctx->nctx->sysdb,
                           dctx->domain, cmdctx->name,
                           dctx->legacy,
                           nss_cmd_initgr_callback, cmdctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        nss_cmd_done(cmdctx);
    }
}

static void nss_cmd_getinit_callback(void *ptr, int status,
                                     struct ldb_result *res);

static void nss_cmd_getinitnam_callback(uint16_t err_maj, uint32_t err_min,
                                        const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = sysdb_getpwnam(cmdctx, cctx->ev, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->name,
                         dctx->legacy,
                         nss_cmd_getinit_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        nss_cmd_done(cmdctx);
    }
}

static void nss_cmd_getinit_callback(void *ptr, int status,
                                     struct ldb_result *res)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int timeout;
    uint64_t lastUpdate;
    uint8_t *body;
    size_t blen;
    bool call_provider = false;
    int ret;

    if (status != LDB_SUCCESS) {
        ret = nss_cmd_send_error(cmdctx, status);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        goto done;
    }

    if (dctx->check_provider) {
        switch (res->count) {
        case 0:
            call_provider = true;
            break;

        default:
            timeout = cmdctx->cctx->nctx->cache_timeout;

            lastUpdate = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                     SYSDB_LAST_UPDATE, 0);
            if (lastUpdate + timeout < time(NULL)) {
                call_provider = true;
            }
        }
    }

    if (call_provider) {

        /* dont loop forever :-) */
        dctx->check_provider = false;
        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                   nss_cmd_getinitnam_callback, dctx,
                                   timeout, dctx->domain, NSS_DP_USER,
                                   cmdctx->name, 0);
        if (ret != EOK) {
            DEBUG(3, ("Failed to dispatch request: %d(%s)\n",
                      ret, strerror(ret)));
            ret = nss_cmd_send_error(cmdctx, ret);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
            goto done;
        }

        return;
    }

    switch (res->count) {
    case 0:

        DEBUG(2, ("No results for initgroups call\n"));

        ret = sss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_packet_get_body(cctx->creq->out, &body, &blen);
        ((uint32_t *)body)[0] = 0; /* 0 results */
        ((uint32_t *)body)[1] = 0; /* reserved */
        break;

    case 1:

        timeout = SSS_CLI_SOCKET_TIMEOUT/2;
        ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                   nss_cmd_getinitgr_callback, dctx,
                                   timeout, dctx->domain, NSS_DP_INITGROUPS,
                                   cmdctx->name, 0);
        if (ret != EOK) {
            DEBUG(3, ("Failed to dispatch request: %d(%s)\n",
                      ret, strerror(ret)));
            ret = nss_cmd_send_error(cmdctx, ret);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
            goto done;
        }

        return;

    default:
        DEBUG(1, ("getpwnam call returned more than one result !?!\n"));
        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
    }

done:
    nss_cmd_done(cmdctx);
}

/* for now, if we are online, try to always query the backend */
static int nss_cmd_initgroups(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    uint8_t *body;
    size_t blen;
    int ret;

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) return ENOMEM;
    dctx->cmdctx = cmdctx;

    /* get user name to query */
    sss_packet_get_body(cctx->creq->in, &body, &blen);
    cmdctx->name = (const char *)body;
    /* if not terminated fail */
    if (cmdctx->name[blen -1] != '\0') {
        return EINVAL;
    }

    ret = nss_parse_name(dctx, (const char *)body);
    if (ret != EOK) {
        DEBUG(1, ("Invalid name received\n"));
        talloc_free(cmdctx);
        return ret;
    }
    DEBUG(4, ("Requesting info for [%s] from [%s]\n",
              cmdctx->name, dctx->domain));

    ret = sysdb_getpwnam(cmdctx, cctx->ev, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->name,
                         dctx->legacy,
                         nss_cmd_getinit_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret == EOK) {
            nss_cmd_done(cmdctx);
        }
        return ret;
    }

    return EOK;
}

struct nss_cmd_table sss_cmds[] = {};
struct nss_cmd_table nss_cmds[] = {
    {SSS_GET_VERSION, nss_cmd_get_version},
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
    {SSS_CLI_NULL, NULL}
};

int nss_cmd_execute(struct cli_ctx *cctx)
{
    enum sss_cli_command cmd;
    int i;

    cmd = sss_packet_get_cmd(cctx->creq->in);

    for (i = 0; nss_cmds[i].cmd != SSS_CLI_NULL; i++) {
        if (cmd == nss_cmds[i].cmd) {
            return nss_cmds[i].fn(cctx);
        }
    }

    return EINVAL;
}

