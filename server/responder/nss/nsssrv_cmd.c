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
#include "responder/nss/nsssrv_nc.h"
#include "db/sysdb.h"
#include <time.h>
#include "confdb/confdb.h"

struct nss_cmd_ctx {
    struct cli_ctx *cctx;
    const char *name;
    uint32_t id;

    bool immediate;
    bool done;
    int nr;
};

struct dom_ctx {
    const char *domain;
    struct ldb_result *res;
    int cur;
};

struct getent_ctx {
    struct dom_ctx *doms;
    int num;
    int cur;
};

struct nss_dom_ctx {
    struct nss_cmd_ctx *cmdctx;
    struct sss_domain_info *domain;
    bool add_domain;
    bool check_provider;

    /* cache results */
    struct ldb_result *res;
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

static bool nss_add_domain(struct sss_domain_info *info)
{
    /* FIXME: we want to actually retrieve this bool from some conf */
    return (strcasecmp(info->name, "LOCAL") != 0);
}

static int nss_parse_name(struct nss_dom_ctx *dctx, const char *fullname)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct nss_ctx *nctx = cmdctx->cctx->nctx;
    struct sss_domain_info *info;
    struct btreemap *domain_map;
    char *delim;
    char *domain;

    /* TODO: add list of names to filter to configuration */
    if (strcmp(fullname, "root") == 0) return ECANCELED;

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

    dctx->domain = info;
    dctx->add_domain = nss_add_domain(info);
    dctx->check_provider = strcasecmp(domain, "LOCAL");

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
                      bool add_domain,
                      const char *domain,
                      struct ldb_message **msgs,
                      int count)
{
    struct ldb_message *msg;
    uint8_t *body;
    const char *name;
    const char *gecos;
    const char *homedir;
    const char *shell;
    uint32_t uid;
    uint32_t gid;
    size_t rsize, rp, blen;
    size_t s1, s2, s3, s4;
    size_t dom_len = 0;
    int i, ret, num;

    if (add_domain) dom_len = strlen(domain) +1;

    /* first 2 fields (len and reserved), filled up later */
    ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
    rp = 2*sizeof(uint32_t);

    num = 0;
    for (i = 0; i < count; i++) {
        msg = msgs[i];

        name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        gecos = ldb_msg_find_attr_as_string(msg, SYSDB_GECOS, NULL);
        homedir = ldb_msg_find_attr_as_string(msg, SYSDB_HOMEDIR, NULL);
        shell = ldb_msg_find_attr_as_string(msg, SYSDB_SHELL, NULL);
        uid = ldb_msg_find_attr_as_uint64(msg, SYSDB_UIDNUM, 0);
        gid = ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);

        if (!name || !uid || !gid) {
            DEBUG(1, ("Incomplete user object for %s[%llu]! Skipping\n",
                      name?name:"<NULL>", (unsigned long long int)uid));
            continue;
        }
        if (!gecos) gecos = "";
        if (!homedir) homedir = "/";
        if (!shell) shell = "";

        s1 = strlen(name) + 1;
        s2 = strlen(gecos) + 1;
        s3 = strlen(homedir) + 1;
        s4 = strlen(shell) + 1;
        rsize = 2*sizeof(uint32_t) +s1 + 2 + s2 + s3 +s4;
        if (add_domain) rsize += dom_len;

        ret = sss_packet_grow(packet, rsize);
        if (ret != EOK) {
            num = 0;
            goto done;
        }
        sss_packet_get_body(packet, &body, &blen);

        ((uint32_t *)(&body[rp]))[0] = uid;
        ((uint32_t *)(&body[rp]))[1] = gid;
        rp += 2*sizeof(uint32_t);
        memcpy(&body[rp], name, s1);
        rp += s1;
        if (add_domain) {
            body[rp-1] = NSS_DOMAIN_DELIM;
            memcpy(&body[rp], domain, dom_len);
            rp += dom_len;
        }
        memcpy(&body[rp], "x", 2);
        rp += 2;
        memcpy(&body[rp], gecos, s2);
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
    bool neghit = false;
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

    if (call_provider && res->count == 0) {
        /* check negative cache before potentially expensive remote call */
        ret = nss_ncache_check_user(cctx->nctx->ncache,
                                    cctx->nctx->neg_timeout,
                                    dctx->domain->name, cmdctx->name);
        switch (ret) {
        case EEXIST:
            DEBUG(2, ("Negative cache hit for getpwnam call\n"));
            res->count = 0;
            call_provider = false;
            neghit = true;
            break;
        case ENOENT:
            break;
        default:
            DEBUG(4,("Error processing ncache request: %d [%s]\n",
                     ret, strerror(ret)));
        }
        ret = EOK;
    }

    if (call_provider) {

        /* dont loop forever :-) */
        dctx->check_provider = false;
        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        /* keep around current data in case backend is offline */
        if (res->count) {
            dctx->res = talloc_steal(dctx, res);
        }

        ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                   nss_cmd_getpwnam_dp_callback, dctx,
                                   timeout, dctx->domain->name, NSS_DP_USER,
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

        /* set negative cache only if not result of cache check */
        if (!neghit) {
            ret = nss_ncache_set_user(cctx->nctx->ncache,
                                      dctx->domain->name, cmdctx->name);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
        }

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
        ret = fill_pwent(cctx->creq->out,
                         dctx->add_domain,
                         dctx->domain->name,
                         res->msgs, res->count);
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

        if (!dctx->res) {
            /* return 0 results */
            dctx->res = talloc_zero(dctx, struct ldb_result);
            if (!dctx->res) {
                ret = ENOMEM;
                goto done;
            }
        }

        nss_cmd_getpwnam_callback(dctx, LDB_SUCCESS, dctx->res);
        return;
    }

    ret = sysdb_getpwnam(cmdctx, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->name,
                         nss_cmd_getpwnam_callback, dctx);

done:
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache! (%d [%s])\n",
                  ret, strerror(ret)));

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
    const char *rawname;
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
    rawname = (const char *)body;

    ret = nss_parse_name(dctx, rawname);
    if (ret != EOK) {
        DEBUG(2, ("Invalid name received [%s]\n", rawname));
        goto done;
    }
    DEBUG(4, ("Requesting info for [%s] from [%s]\n",
              cmdctx->name, dctx->domain->name));

    ret = sysdb_getpwnam(cmdctx, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->name,
                         nss_cmd_getpwnam_callback, dctx);

    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));
    }

done:
    if (ret != EOK) {
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
    bool neghit = false;
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

    if (call_provider && res->count == 0) {
        /* check negative cache before potentially expensive remote call */
        ret = nss_ncache_check_uid(cctx->nctx->ncache,
                                   cctx->nctx->neg_timeout,
                                   cmdctx->id);
        switch (ret) {
        case EEXIST:
            DEBUG(2, ("Negative cache hit for getpwuid call\n"));
            res->count = 0;
            call_provider = false;
            neghit = true;
            break;
        case ENOENT:
            break;
        default:
            DEBUG(4,("Error processing ncache request: %d [%s]\n",
                     ret, strerror(ret)));
        }
        ret = EOK;
    }

    if (call_provider) {

        /* yet one more call to go */
        cmdctx->nr++;

        /* dont loop forever :-) */
        dctx->check_provider = false;
        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        /* keep around current data in case backend is offline */
        if (res->count) {
            dctx->res = talloc_steal(dctx, res);
        }

        ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                   nss_cmd_getpwuid_dp_callback, dctx,
                                   timeout, dctx->domain->name, NSS_DP_USER,
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

        /* set negative cache only if not result of cache check */
        if (!neghit) {
            ret = nss_ncache_set_uid(cctx->nctx->ncache, cmdctx->id);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
        }

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

        ret = fill_pwent(cctx->creq->out,
                         dctx->add_domain,
                         dctx->domain->name,
                         res->msgs, res->count);
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

        if (!dctx->res) {
            /* return 0 results */
            dctx->res = talloc_zero(dctx, struct ldb_result);
            if (!dctx->res) {
                ret = ENOMEM;
                goto done;
            }
        }

        nss_cmd_getpwuid_callback(dctx, LDB_SUCCESS, dctx->res);
        return;
    }

    ret = sysdb_getpwuid(cmdctx, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->id,
                         nss_cmd_getpwuid_callback, dctx);

done:
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
    struct sss_domain_info *info;
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

    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }

    cmdctx->id = *((uint32_t *)body);

    /* FIXME: Just ask all backends for now, until we check for ranges */
    dctx = NULL;
    domains = NULL;
    num = 0;
    /* get domains list */
    ret = btreemap_get_keys(cmdctx, cctx->nctx->domain_map,
                            (const void ***)&domains, &num);
    if (ret != EOK)
        return ret;

    cmdctx->nr = num;

    for (i = 0; i < num; i++) {
        info = btreemap_get_value(cctx->nctx->domain_map, domains[i]);

        dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
        if (!dctx) return ENOMEM;

        dctx->cmdctx = cmdctx;
        dctx->domain = info;
        dctx->add_domain = nss_add_domain(info);
        dctx->check_provider = strcasecmp(domains[i], "LOCAL");

        DEBUG(4, ("Requesting info for [%lu@%s]\n",
                  cmdctx->id, dctx->domain->name));

        ret = sysdb_getpwuid(cmdctx, cctx->nctx->sysdb,
                             dctx->domain, cmdctx->id,
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
static int nss_cmd_getpwent_immediate(struct nss_cmd_ctx *cmdctx);

static void nss_cmd_setpwent_callback(void *ptr, int status,
                                      struct ldb_result *res)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct getent_ctx *pctx = cctx->pctx;
    int ret;

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

    pctx->doms = talloc_realloc(pctx, pctx->doms, struct dom_ctx, pctx->num +1);
    if (!pctx->doms) NSS_CMD_FATAL_ERROR(cctx);

    if (dctx->add_domain) {
        pctx->doms[pctx->num].domain = dctx->domain->name;
    } else {
        pctx->doms[pctx->num].domain = NULL;
    }
    pctx->doms[pctx->num].res = talloc_steal(pctx->doms, res);
    pctx->doms[pctx->num].cur = 0;

    pctx->num++;

    /* do not reply until all domain searches are done */
    if (cmdctx->nr) return;

    /* set cache mark */
    cctx->nctx->last_user_enum = time(NULL);

    if (cmdctx->immediate) {
        /* this was a getpwent call w/o setpwent,
         * return immediately one result */
        ret = nss_cmd_getpwent_immediate(cmdctx);
        if (ret != EOK) NSS_CMD_FATAL_ERROR(cctx);
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

    ret = sysdb_enumpwent(cmdctx, cctx->nctx->sysdb,
                          dctx->domain, NULL,
                          nss_cmd_setpwent_callback, dctx);
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
    struct sss_domain_info *info;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct getent_ctx *pctx;
    const char **domains;
    time_t now = time(NULL);
    bool cached = false;
    int timeout;
    int i, ret, num;

    DEBUG(4, ("Requesting info for all users\n"));

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    talloc_free(cctx->pctx);
    cctx->pctx = talloc_zero(cctx, struct getent_ctx);
    if (!cctx->pctx) {
        talloc_free(cmdctx);
        return ENOMEM;
    }
    pctx = cctx->pctx;

    cmdctx->immediate = immediate;

    domains = NULL;
    num = 0;
    /* get domains list */
    ret = btreemap_get_keys(cmdctx, cctx->nctx->domain_map,
                      (const void ***)&domains, &num);
    if (ret != EOK) {
        return ret;
    }

    /* do not query backends if we have a recent enumeration */
    if (cctx->nctx->enum_cache_timeout) {
        if (cctx->nctx->last_user_enum +
            cctx->nctx->enum_cache_timeout > now) {
            cached = true;
        }
    }

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
        dctx->domain = info;
        dctx->add_domain = nss_add_domain(info);

        if (cached) {
            dctx->check_provider = false;
        } else {
            dctx->check_provider = strcasecmp(domains[i], "LOCAL");
        }

        if (dctx->check_provider) {
            timeout = SSS_CLI_SOCKET_TIMEOUT/(i+2);
            ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                       nss_cmd_setpw_dp_callback, dctx,
                                       timeout, domains[i], NSS_DP_USER,
                                       NULL, 0);
        } else {
            ret = sysdb_enumpwent(dctx, cctx->nctx->sysdb,
                                  dctx->domain, NULL,
                                  nss_cmd_setpwent_callback, dctx);
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
    struct getent_ctx *pctx = cctx->pctx;
    struct ldb_message **msgs = NULL;
    struct dom_ctx *pdom;
    const char *dom = NULL;
    bool add = false;
    int n = 0;

    if (pctx->cur >= pctx->num) goto done;

    pdom = &pctx->doms[pctx->cur];

    n = pdom->res->count - pdom->cur;
    if (n == 0 && (pctx->cur+1 < pctx->num)) {
        pctx->cur++;
        pdom = &pctx->doms[pctx->cur];
        n = pdom->res->count - pdom->cur;
    }

    if (!n) goto done;

    if (n > num) n = num;

    msgs = &(pdom->res->msgs[pdom->cur]);
    pdom->cur += n;

    add = (pdom->domain != NULL);
    dom = pdom->domain;

done:
    return fill_pwent(cctx->creq->out, add, dom, msgs, n);
}

/* used only if a process calls getpwent() without first calling setpwent()
 */
static int nss_cmd_getpwent_immediate(struct nss_cmd_ctx *cmdctx)
{
    struct cli_ctx *cctx = cmdctx->cctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    int ret;

    /* get max num of entries to return in one call */
    sss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }
    num = *((uint32_t *)body);

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

static int nss_cmd_getpwent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;

    DEBUG(4, ("Requesting info for all accounts\n"));

    /* see if we need to trigger an implicit setpwent() */
    if (cctx->gctx == NULL) {
        cctx->gctx = talloc_zero(cctx, struct getent_ctx);
        if (!cctx->gctx) return ENOMEM;

        return nss_cmd_setpwent_ext(cctx, true);
    }

    cmdctx = talloc(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    return nss_cmd_getpwent_immediate(cmdctx);
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

    if (cctx->pctx == NULL) goto done;

    /* free results and reset */
    talloc_free(cctx->pctx);
    cctx->pctx = NULL;

done:
    nss_cmd_done(cmdctx);
    return EOK;
}

/****************************************************************************
 * GROUP db related functions
 ***************************************************************************/

static int fill_grent(struct sss_packet *packet,
                      bool add_domain,
                      const char *domain,
                      struct ldb_message **msgs,
                      int count)
{
    struct ldb_message_element *el;
    struct ldb_message *msg;
    uint8_t *body;
    const char *name;
    uint32_t gid;
    size_t rsize, rp, blen, mnump;
    int i, j, ret, num, memnum;
    bool get_members;
    size_t dom_len = 0;
    size_t name_len;

    if (add_domain) dom_len = strlen(domain) +1;

    /* first 2 fields (len and reserved), filled up later */
    ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
    rp = 2*sizeof(uint32_t);

    num = 0;
    mnump = 0;
    get_members = false;
    for (i = 0; i < count; i++) {
        msg = msgs[i];

        /* new group */
        if (ldb_msg_check_string_attribute(msg, "objectClass",
                                                SYSDB_GROUP_CLASS)) {
            if (get_members) {
                /* this marks the end of a previous group */
                sss_packet_get_body(packet, &body, &blen);
                ((uint32_t *)(&body[mnump]))[0] = memnum; /* num members */
                get_members = false;
            }

            /* find group name/gid */
            name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
            gid = ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);
            if (!name || !gid) {
                DEBUG(1, ("Incomplete group object for %s[%llu]! Aborting\n",
                          name?name:"<NULL>", (unsigned long long int)gid));
                num = 0;
                goto done;
            }

            /* fill in gid and name and set pointer for number of members */
            name_len = strlen(name)+1;
            rsize = 2 * sizeof(uint32_t) + name_len +2;
            if (add_domain) rsize += dom_len;

            ret = sss_packet_grow(packet, rsize);
            sss_packet_get_body(packet, &body, &blen);

            /*  0-3: 64bit number gid */
            rp = blen - rsize;
            ((uint32_t *)(&body[rp]))[0] = gid;
            rp += sizeof(uint32_t);

            /*  4-7: 32bit unsigned number of members */
            ((uint32_t *)(&body[rp]))[0] = 0; /* init members num to 0 */
            mnump = rp; /* keep around members num pointer to set later */
            rp += sizeof(uint32_t);

            /*  8-X: sequence of strings (name, passwd, mem..) */
            memcpy(&body[rp], name, name_len);
            rp += name_len;
            if (add_domain) {
                body[rp-1] = NSS_DOMAIN_DELIM;
                memcpy(&body[rp], domain, dom_len);
                rp += dom_len;
            }
            body[rp] = 'x'; /* group passwd field */
            body[rp+1] = '\0';

            memnum = 0;
            num++;

            /* legacy style group, members are in SYSDB_LEGACY_MEMBER */
            el = ldb_msg_find_element(msg, SYSDB_LEGACY_MEMBER);
            if (el) {
                /* legacy */
                memnum = el->num_values;

                for (j = 0; j < memnum; j++) {
                    rsize = el->values[j].length + 1;
                    if (add_domain) {
                        name_len = rsize;
                        rsize += dom_len;
                    }
                    ret = sss_packet_grow(packet, rsize);
                    if (ret != EOK) {
                        num = 0;
                        goto done;
                    }

                    sss_packet_get_body(packet, &body, &blen);
                    rp = blen - rsize;
                    memcpy(&body[rp], el->values[j].data, el->values[j].length);
                    if (add_domain) {
                        rp += name_len;
                        body[rp-1] = NSS_DOMAIN_DELIM;
                        memcpy(&body[rp], domain, dom_len);
                    }
                    body[blen-1] = '\0';
                }

                sss_packet_get_body(packet, &body, &blen);
                ((uint32_t *)(&body[mnump]))[0] = memnum; /* num members */

            }  else {
                get_members = true;
            }

            continue;
        }

        if (!get_members) {
            DEBUG(1, ("Wrong object found on stack! Aborting\n"));
            num = 0;
            goto done;
        }

        /* member */
        if (ldb_msg_check_string_attribute(msg, "objectClass",
                                                SYSDB_USER_CLASS)) {

            name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
            if (!name) {
                DEBUG(1, ("Incomplete user object! Aborting\n"));
                num = 0;
                goto done;
            }

            rsize = strlen(name) + 1;
            if (add_domain) {
                name_len = rsize;
                rsize += dom_len;
            }

            ret = sss_packet_grow(packet, rsize);
            if (ret != EOK) {
                num = 0;
                goto done;
            }
            sss_packet_get_body(packet, &body, &blen);
            rp = blen - rsize;
            memcpy(&body[rp], name, rsize);
            if (add_domain) {
                body[rp-1] = NSS_DOMAIN_DELIM;
                memcpy(&body[rp], domain, dom_len);
                rp += dom_len;
            }

            memnum++;

            continue;
        }

        DEBUG(1, ("Wrong object found on stack! Aborting\n"));
        num = 0;
        goto done;
    }

    if (mnump) {
        /* fill in the last group member count */
        sss_packet_get_body(packet, &body, &blen);
        ((uint32_t *)(&body[mnump]))[0] = memnum; /* num members */
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
    bool neghit = false;
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

    if (call_provider && res->count == 0) {
        /* check negative cache before potentially expensive remote call */
        ret = nss_ncache_check_group(cctx->nctx->ncache,
                                     cctx->nctx->neg_timeout,
                                     dctx->domain->name, cmdctx->name);
        switch (ret) {
        case EEXIST:
            DEBUG(2, ("Negative cache hit for getgrnam call\n"));
            res->count = 0;
            call_provider = false;
            neghit = true;
            break;
        case ENOENT:
            break;
        default:
            DEBUG(4,("Error processing ncache request: %d [%s]\n",
                     ret, strerror(ret)));
        }
        ret = EOK;
    }

    if (call_provider) {

        /* dont loop forever :-) */
        dctx->check_provider = false;
        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        /* keep around current data in case backend is offline */
        if (res->count) {
            dctx->res = talloc_steal(dctx, res);
        }

        ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                   nss_cmd_getgrnam_dp_callback, dctx,
                                   timeout, dctx->domain->name, NSS_DP_GROUP,
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

        /* set negative cache only if not result of cache check */
        if (!neghit) {
            ret = nss_ncache_set_group(cctx->nctx->ncache,
                                       dctx->domain->name, cmdctx->name);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
        }

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

        ret = fill_grent(cctx->creq->out,
                         dctx->add_domain,
                         dctx->domain->name,
                         res->msgs, res->count);
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

        if (!dctx->res) {
            /* return 0 results */
            dctx->res = talloc_zero(dctx, struct ldb_result);
            if (!dctx->res) {
                ret = ENOMEM;
                goto done;
            }
        }

        nss_cmd_getgrnam_callback(dctx, LDB_SUCCESS, dctx->res);
        return;
    }

    ret = sysdb_getgrnam(cmdctx, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->name,
                         nss_cmd_getgrnam_callback, dctx);

done:
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
    const char *rawname;
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
    rawname = (const char *)body;

    ret = nss_parse_name(dctx, rawname);
    if (ret != EOK) {
        DEBUG(2, ("Invalid name received [%s]\n", rawname));
        goto done;
    }
    DEBUG(4, ("Requesting info for [%s] from [%s]\n",
              cmdctx->name, dctx->domain->name));

    ret = sysdb_getgrnam(cmdctx, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->name,
                         nss_cmd_getgrnam_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));
    }

done:
    if (ret != EOK) {
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
    bool neghit = false;
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

    if (call_provider && res->count == 0) {
        /* check negative cache before potentially expensive remote call */
        ret = nss_ncache_check_gid(cctx->nctx->ncache,
                                   cctx->nctx->neg_timeout,
                                   cmdctx->id);
        switch (ret) {
        case EEXIST:
            DEBUG(2, ("Negative cache hit for getgrgid call\n"));
            res->count = 0;
            call_provider = false;
            neghit = true;
            break;
        case ENOENT:
            break;
        default:
            DEBUG(4,("Error processing ncache request: %d [%s]\n",
                     ret, strerror(ret)));
        }
        ret = EOK;
    }

    if (call_provider) {

        /* yet one more call to go */
        cmdctx->nr++;

        /* dont loop forever :-) */
        dctx->check_provider = false;
        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        /* keep around current data in case backend is offline */
        if (res->count) {
            dctx->res = talloc_steal(dctx, res);
        }

        ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                   nss_cmd_getgrgid_dp_callback, dctx,
                                   timeout, dctx->domain->name, NSS_DP_GROUP,
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

        /* set negative cache only if not result of cache check */
        if (!neghit) {
            ret = nss_ncache_set_gid(cctx->nctx->ncache, cmdctx->id);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
        }

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

        ret = fill_grent(cctx->creq->out,
                         dctx->add_domain,
                         dctx->domain->name,
                         res->msgs, res->count);
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

        if (!dctx->res) {
            /* return 0 results */
            dctx->res = talloc_zero(dctx, struct ldb_result);
            if (!dctx->res) {
                ret = ENOMEM;
                goto done;
            }
        }

        nss_cmd_getgrgid_callback(dctx, LDB_SUCCESS, dctx->res);
        return;
    }

    ret = sysdb_getgrgid(cmdctx, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->id,
                         nss_cmd_getgrgid_callback, dctx);

done:
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
    struct sss_domain_info *info;
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

    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }

    cmdctx->id = *((uint32_t *)body);

    /* FIXME: Just ask all backends for now, until we check for ranges */
    dctx = NULL;
    domains = NULL;
    num = 0;
    /* get domains list */
    ret = btreemap_get_keys(cmdctx, cctx->nctx->domain_map,
                            (const void ***)&domains, &num);
    if (ret != EOK) {
        return ret;
    }

    cmdctx->nr = num;

    for (i = 0; i < num; i++) {
        info = btreemap_get_value(cctx->nctx->domain_map, domains[i]);

        dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
        if (!dctx) return ENOMEM;

        dctx->cmdctx = cmdctx;
        dctx->domain = info;
        dctx->add_domain = nss_add_domain(info);
        dctx->check_provider = strcasecmp(domains[i], "LOCAL");

        DEBUG(4, ("Requesting info for [%lu@%s]\n",
                  cmdctx->id, dctx->domain->name));

        ret = sysdb_getgrgid(cmdctx, cctx->nctx->sysdb,
                             dctx->domain, cmdctx->id,
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

static int nss_cmd_getgrent_immediate(struct nss_cmd_ctx *cmdctx);

static void nss_cmd_setgrent_callback(void *ptr, int status,
                                     struct ldb_result *res)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct getent_ctx *gctx = cctx->gctx;
    int ret;

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

    gctx->doms = talloc_realloc(gctx, gctx->doms, struct dom_ctx, gctx->num +1);
    if (!gctx->doms) NSS_CMD_FATAL_ERROR(cctx);

    if (dctx->add_domain) {
        gctx->doms[gctx->num].domain = dctx->domain->name;
    } else {
        gctx->doms[gctx->num].domain = NULL;
    }
    gctx->doms[gctx->num].res = talloc_steal(gctx->doms, res);
    gctx->doms[gctx->num].cur = 0;

    gctx->num++;

    /* do not reply until all domain searches are done */
    if (cmdctx->nr) return;

    /* set cache mark */
    cctx->nctx->last_group_enum = time(NULL);

    if (cmdctx->immediate) {
        /* this was a getgrent call w/o setgrent,
         * return immediately one result */
        ret = nss_cmd_getgrent_immediate(cmdctx);
        if (ret != EOK) NSS_CMD_FATAL_ERROR(cctx);
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

    ret = sysdb_enumgrent(dctx, cctx->nctx->sysdb,
                          dctx->domain,
                          nss_cmd_setgrent_callback, dctx);
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
    struct sss_domain_info *info;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct getent_ctx *gctx;
    const char **domains;
    time_t now = time(NULL);
    bool cached = false;
    int timeout;
    int i, ret, num;

    DEBUG(4, ("Requesting info for all groups\n"));

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    talloc_free(cctx->gctx);
    cctx->gctx = talloc_zero(cctx, struct getent_ctx);
    if (!cctx->gctx) {
        talloc_free(cmdctx);
        return ENOMEM;
    }
    gctx = cctx->gctx;

    cmdctx->immediate = immediate;

    domains = NULL;
    num = 0;
    /* get domains list */
    ret = btreemap_get_keys(cmdctx, cctx->nctx->domain_map,
                            (const void ***)&domains, &num);
    if(ret != EOK) {
        return ret;
    }

    /* do not query backends if we have a recent enumeration */
    if (cctx->nctx->enum_cache_timeout) {
        if (cctx->nctx->last_group_enum +
            cctx->nctx->enum_cache_timeout > now) {
            cached = true;
        }
    }

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
        dctx->domain = info;
        dctx->add_domain = nss_add_domain(info);

        if (cached) {
            dctx->check_provider = false;
        } else {
            dctx->check_provider = strcasecmp(domains[i], "LOCAL");
        }

        if (dctx->check_provider) {
            timeout = SSS_CLI_SOCKET_TIMEOUT/(i+2);
            ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                       nss_cmd_setgr_dp_callback, dctx,
                                       timeout, domains[i], NSS_DP_GROUP,
                                       NULL, 0);
        } else {
            ret = sysdb_enumgrent(dctx, cctx->nctx->sysdb,
                                  dctx->domain,
                                  nss_cmd_setgrent_callback, dctx);
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
    struct ldb_message **msgs = NULL;
    struct dom_ctx *gdom;
    const char *dom = NULL;
    bool add = false;
    int n = 0;

    if (gctx->cur >= gctx->num) goto done;

    gdom = &gctx->doms[gctx->cur];

    n = gdom->res->count - gdom->cur;
    if (n == 0 && (gctx->cur+1 < gctx->num)) {
        gctx->cur++;
        gdom = &gctx->doms[gctx->cur];
        n = gdom->res->count - gdom->cur;
    }

    if (!n) goto done;

    if (n > num) n = num;

    msgs = &(gdom->res->msgs[gdom->cur]);
    gdom->cur += n;

    add = (gdom->domain != NULL);
    dom = gdom->domain;

done:
    return fill_grent(cctx->creq->out, add, dom, msgs, n);
}

/* used only if a process calls getpwent() without first calling setpwent()
 */
static int nss_cmd_getgrent_immediate(struct nss_cmd_ctx *cmdctx)
{
    struct cli_ctx *cctx = cmdctx->cctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    int ret;

    /* get max num of entries to return in one call */
    sss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }
    num = *((uint32_t *)body);

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

static int nss_cmd_getgrent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;

    DEBUG(4, ("Requesting info for all groups\n"));

    /* see if we need to trigger an implicit setpwent() */
    if (cctx->gctx == NULL) {
        cctx->gctx = talloc_zero(cctx, struct getent_ctx);
        if (!cctx->gctx) return ENOMEM;

        return nss_cmd_setgrent_ext(cctx, true);
    }

    cmdctx = talloc(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    return nss_cmd_getgrent_immediate(cmdctx);
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

    /* free results and reset */
    talloc_free(cctx->gctx);
    cctx->gctx = NULL;

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
    uint32_t gid;
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
    ret = sss_packet_grow(cctx->creq->out, (2 + num) * sizeof(uint32_t));
    if (ret != EOK) {
        sss_packet_set_error(cctx->creq->out, ret);
        goto done;
    }
    sss_packet_get_body(cctx->creq->out, &body, &blen);

    for (i = 0; i < num; i++) {
        gid = ldb_msg_find_attr_as_uint64(res->msgs[i], SYSDB_GIDNUM, 0);
        if (!gid) {
            DEBUG(1, ("Incomplete group object for initgroups! Aborting\n"));
            sss_packet_set_error(cctx->creq->out, EIO);
            num = 0;
            goto done;
        }
        ((uint32_t *)body)[2+i] = gid;
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

    ret = sysdb_initgroups(cmdctx, cctx->nctx->sysdb,
                           dctx->domain, cmdctx->name,
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

        if (!dctx->res) {
            /* return 0 results */
            dctx->res = talloc_zero(dctx, struct ldb_result);
            if (!dctx->res) {
                ret = ENOMEM;
                goto done;
            }
        }

        nss_cmd_getinit_callback(dctx, LDB_SUCCESS, dctx->res);
        return;
    }

    ret = sysdb_getpwnam(cmdctx, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->name,
                         nss_cmd_getinit_callback, dctx);

done:
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
    bool neghit = false;
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

    if (call_provider && res->count == 0) {
        /* check negative cache before potentially expensive remote call */
        ret = nss_ncache_check_user(cctx->nctx->ncache,
                                   cctx->nctx->neg_timeout,
                                   dctx->domain->name, cmdctx->name);
        switch (ret) {
        case EEXIST:
            DEBUG(2, ("Negative cache hit for initgr call\n"));
            res->count = 0;
            call_provider = false;
            neghit = false;
            break;
        case ENOENT:
            break;
        default:
            DEBUG(4,("Error processing ncache request: %d [%s]\n",
                     ret, strerror(ret)));
        }
        ret = EOK;
    }

    if (call_provider) {

        /* dont loop forever :-) */
        dctx->check_provider = false;
        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        /* keep around current data in case backend is offline */
        if (res->count) {
            dctx->res = talloc_steal(dctx, res);
        }

        ret = nss_dp_send_acct_req(cctx->nctx, cmdctx,
                                   nss_cmd_getinitnam_callback, dctx,
                                   timeout, dctx->domain->name, NSS_DP_USER,
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

        /* set negative cache only if not result of cache check */
        if (!neghit) {
            ret = nss_ncache_set_user(cctx->nctx->ncache,
                                      dctx->domain->name, cmdctx->name);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
        }

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
                                   timeout, dctx->domain->name,
                                   NSS_DP_INITGROUPS,
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
    const char *rawname;
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
        return EINVAL;
    }
    rawname = (const char *)body;

    ret = nss_parse_name(dctx, rawname);
    if (ret != EOK) {
        DEBUG(2, ("Invalid name received [%s]\n", rawname));
        goto done;
    }
    DEBUG(4, ("Requesting info for [%s] from [%s]\n",
              cmdctx->name, dctx->domain->name));

    ret = sysdb_getpwnam(cmdctx, cctx->nctx->sysdb,
                         dctx->domain, cmdctx->name,
                         nss_cmd_getinit_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));
    }

done:
    if (ret != EOK) {
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

