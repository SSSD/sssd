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
#include "responder/nss/nsssrv.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include <time.h>

struct nss_cmd_ctx {
    struct cli_ctx *cctx;
    char *name;
    uint32_t id;

    bool immediate;
    bool check_next;
    bool enum_cached;
};

struct dom_ctx {
    struct sss_domain_info *domain;
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

    bool check_provider;

    /* cache results */
    struct ldb_result *res;
};

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

#define NSS_CMD_FATAL_ERROR_CODE(cctx, ret) do { \
    DEBUG(1,("Fatal error, killing connection!")); \
    talloc_free(cctx); \
    return ret; \
} while(0)

static struct sss_domain_info *nss_get_dom(struct sss_domain_info *doms,
                                           const char *domain)
{
    struct sss_domain_info *dom;

    for (dom = doms; dom; dom = dom->next) {
        if (strcasecmp(dom->name, domain) == 0) break;
    }
    if (!dom) DEBUG(2, ("Unknown domain [%s]!\n", domain));

    return dom;
}

static int fill_empty(struct sss_packet *packet)
{
    uint8_t *body;
    size_t blen;
    int ret;

    ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
    if (ret != EOK) return ret;

    sss_packet_get_body(packet, &body, &blen);
    ((uint32_t *)body)[0] = 0; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

    return EOK;
}

/****************************************************************************
 * PASSWD db related functions
 ***************************************************************************/

static int fill_pwent(struct sss_packet *packet,
                      struct sss_domain_info *dom,
                      struct nss_ctx *nctx,
                      bool filter_users,
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
    size_t s1, s2, s3, s4, s5;
    size_t dom_len = 0;
    int delim = 1;
    int i, ret, num, t;
    bool add_domain = dom->fqnames;
    const char *domain = dom->name;
    const char *namefmt = nctx->rctx->names->fq_fmt;
    bool packet_initialized = false;
    int ncret;

    if (add_domain) dom_len = strlen(domain);

    rp = 2*sizeof(uint32_t);

    num = 0;
    for (i = 0; i < count; i++) {
        msg = msgs[i];

        name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        uid = ldb_msg_find_attr_as_uint64(msg, SYSDB_UIDNUM, 0);
        gid = ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);

        if (!name || !uid || !gid) {
            DEBUG(1, ("Incomplete user object for %s[%llu]! Skipping\n",
                      name?name:"<NULL>", (unsigned long long int)uid));
            continue;
        }

        if (filter_users) {
            ncret = nss_ncache_check_user(nctx->ncache,
                                        nctx->neg_timeout,
                                        domain, name);
            if (ncret == EEXIST) {
                DEBUG(4, ("User [%s@%s] filtered out! (negative cache)\n",
                          name, domain));
                continue;
            }
        }

        if (!packet_initialized) {
            /* first 2 fields (len and reserved), filled up later */
            ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
            if (ret != EOK) return ret;
            packet_initialized = true;
        }

        gecos = ldb_msg_find_attr_as_string(msg, SYSDB_GECOS, NULL);
        homedir = ldb_msg_find_attr_as_string(msg, SYSDB_HOMEDIR, NULL);
        shell = ldb_msg_find_attr_as_string(msg, SYSDB_SHELL, NULL);

        if (!gecos) gecos = "";
        if (!homedir) homedir = "/";
        if (!shell) shell = "";

        s1 = strlen(name) + 1;
        s2 = strlen(gecos) + 1;
        s3 = strlen(homedir) + 1;
        s4 = strlen(shell) + 1;
        s5 = strlen(nctx->pwfield) + 1;
        if (add_domain) s1 += delim + dom_len;

        rsize = 2*sizeof(uint32_t) +s1 + s2 + s3 + s4 + s5;

        ret = sss_packet_grow(packet, rsize);
        if (ret != EOK) {
            num = 0;
            goto done;
        }
        sss_packet_get_body(packet, &body, &blen);

        ((uint32_t *)(&body[rp]))[0] = uid;
        ((uint32_t *)(&body[rp]))[1] = gid;
        rp += 2*sizeof(uint32_t);

        if (add_domain) {
            ret = snprintf((char *)&body[rp], s1, namefmt, name, domain);
            if (ret >= s1) {
                /* need more space, got creative with the print format ? */
                t = ret - s1 + 1;
                ret = sss_packet_grow(packet, t);
                if (ret != EOK) {
                    num = 0;
                    goto done;
                }
                delim += t;
                s1 += t;
                sss_packet_get_body(packet, &body, &blen);

                /* retry */
                ret = snprintf((char *)&body[rp], s1, namefmt, name, domain);
            }

            if (ret != s1-1) {
                DEBUG(1, ("Failed to generate a fully qualified name for user "
                          "[%s] in [%s]! Skipping user.\n", name, domain));
                continue;
            }
        } else {
            memcpy(&body[rp], name, s1);
        }
        rp += s1;

        memcpy(&body[rp], nctx->pwfield, s5);
        rp += s5;
        memcpy(&body[rp], gecos, s2);
        rp += s2;
        memcpy(&body[rp], homedir, s3);
        rp += s3;
        memcpy(&body[rp], shell, s4);
        rp += s4;

        num++;
    }

done:
    /* if there are no results just return ENOENT,
     * let the caller decide if this is the last packet or not */
    if (!packet_initialized) return ENOENT;

    sss_packet_get_body(packet, &body, &blen);
    ((uint32_t *)body)[0] = num; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

    return EOK;
}

static errno_t check_cache(struct nss_dom_ctx *dctx,
                           struct nss_ctx *nctx,
                           struct ldb_result *res,
                           int req_type,
                           const char *opt_name,
                           uint32_t opt_id,
                           sss_dp_callback_t callback)
{
    errno_t ret;
    int timeout;
    time_t now;
    uint64_t lastUpdate;
    uint64_t cacheExpire = 0;
    uint64_t midpoint_refresh;
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    bool off_band_update = false;

    /* when searching for a user, more than one reply is a db error */
    if ((req_type == SSS_DP_USER) && (res->count > 1)) {
        DEBUG(1, ("getpwXXX call returned more than one result!"
                  " DB Corrupted?\n"));
        ret = nss_cmd_send_error(cmdctx, ENOENT);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR_CODE(cctx, ENOENT);
        }
        sss_cmd_done(cctx, cmdctx);
        return ENOENT;
    }

    /* if we have any reply let's check cache validity */
    if (res->count > 0) {

        now = time(NULL);

        lastUpdate = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                 SYSDB_LAST_UPDATE, 0);
        if (req_type == SSS_DP_INITGROUPS) {
            cacheExpire = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                 SYSDB_INITGR_EXPIRE, 1);
        }
        if (cacheExpire == 0) {
            cacheExpire = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                 SYSDB_CACHE_EXPIRE, 0);
        }

        midpoint_refresh = 0;
        if(nctx->cache_refresh_percent) {
            midpoint_refresh = lastUpdate +
              (cacheExpire - lastUpdate)*nctx->cache_refresh_percent/100;
            if (midpoint_refresh - lastUpdate < 10) {
                /* If the percentage results in an expiration
                 * less than ten seconds after the lastUpdate time,
                 * that's too often we will simply set it to 10s
                 */
                midpoint_refresh = lastUpdate+10;
            }
        }

        if (cacheExpire > now) {
            /* cache still valid */

            if (midpoint_refresh && midpoint_refresh < now) {
                /* We're past the the cache refresh timeout
                 * We'll return the value from the cache, but we'll also
                 * queue the cache entry for update out-of-band.
                 */
                DEBUG(6, ("Performing midpoint cache update on [%s]\n",
                          opt_name));
                off_band_update = true;
            }
            else {

                /* Cache is still valid. Just return it. */
                return EOK;
            }
        }
    }

    if (off_band_update) {

        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        /* No callback required
         * This was an out-of-band update. We'll return EOK
         * so the calling function can return the cached entry
         * immediately.
         */
        ret = sss_dp_send_acct_req(cctx->rctx, NULL, NULL, NULL,
                                   timeout, dctx->domain->name,
                                   true, req_type,
                                   opt_name, opt_id);
        if (ret != EOK) {
            DEBUG(3, ("Failed to dispatch request: %d(%s)\n",
                      ret, strerror(ret)));
        } else {

            DEBUG(3, ("Updating cache out-of-band\n"));
        }

    } else {
       /* This is a cache miss. Or the cache is expired.
        * We need to get the updated user information before returning it.
        */

        /* dont loop forever :-) */
        dctx->check_provider = false;
        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        /* keep around current data in case backend is offline */
        if (res->count) {
            dctx->res = talloc_steal(dctx, res);
        }

        ret = sss_dp_send_acct_req(cctx->rctx, cmdctx,
                                   callback, dctx, timeout,
                                   dctx->domain->name,
                                   true, req_type,
                                   opt_name, opt_id);
        if (ret != EOK) {
            DEBUG(3, ("Failed to dispatch request: %d(%s)\n",
                      ret, strerror(ret)));
            ret = nss_cmd_send_error(cmdctx, ret);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR_CODE(cctx, EIO);
            }
            sss_cmd_done(cctx, cmdctx);
            return EIO;
        }

        return EAGAIN;
    }

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
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *dom;
    struct nss_ctx *nctx;
    uint8_t *body;
    size_t blen;
    bool neghit = false;
    int ncret;
    int ret;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    if (status != LDB_SUCCESS) {
        ret = nss_cmd_send_error(cmdctx, status);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_cmd_done(cctx, cmdctx);
        return;
    }

    if (dctx->check_provider) {
        ret = check_cache(dctx, nctx, res,
                          SSS_DP_USER, cmdctx->name, 0,
                          nss_cmd_getpwnam_dp_callback);
        if (ret != EOK) {
            /* Anything but EOK means we should reenter the mainloop
             * because we may be refreshing the cache
             */
            return;
        }
    }

    switch (res->count) {
    case 0:
        if (cmdctx->check_next) {

            ret = EOK;

            /* skip domains that require FQnames or have negative caches */
            for (dom = dctx->domain->next; dom; dom = dom->next) {

                if (dom->fqnames) continue;

                ncret = nss_ncache_check_user(nctx->ncache,
                                              nctx->neg_timeout,
                                              dom->name, cmdctx->name);
                if (ncret == ENOENT) break;

                neghit = true;
            }
            /* reset neghit if we still have a domain to check */
            if (dom) neghit = false;

           if (neghit) {
                DEBUG(2, ("User [%s] does not exist! (negative cache)\n",
                          cmdctx->name));
                ret = ENOENT;
            }
            if (dom == NULL) {
                DEBUG(2, ("No matching domain found for [%s], fail!\n",
                          cmdctx->name));
                ret = ENOENT;
            }

            if (ret == EOK) {
                dctx->domain = dom;
                dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
                if (dctx->res) talloc_free(res);
                dctx->res = NULL;

                DEBUG(4, ("Requesting info for [%s@%s]\n",
                          cmdctx->name, dctx->domain->name));

                ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                              dctx->domain, &sysdb);
                if (ret != EOK) {
                    DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
                    NSS_CMD_FATAL_ERROR(cctx);
                }
                ret = sysdb_getpwnam(cmdctx, sysdb,
                                     dctx->domain, cmdctx->name,
                                     nss_cmd_getpwnam_callback, dctx);
                if (ret != EOK) {
                    DEBUG(1, ("Failed to make request to our cache!\n"));
                }
            }

            /* we made another call, end here */
            if (ret == EOK) return;
        }

        DEBUG(2, ("No results for getpwnam call\n"));

        /* set negative cache only if not result of cache check */
        if (!neghit) {
            ret = nss_ncache_set_user(nctx->ncache, false,
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
        DEBUG(6, ("Returning info for user [%s]\n", cmdctx->name));

        /* create response packet */
        ret = sss_packet_new(cctx->creq, 0,
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        ret = fill_pwent(cctx->creq->out,
                         dctx->domain,
                         nctx, false,
                         res->msgs, res->count);
        if (ret == ENOENT) {
            ret = fill_empty(cctx->creq->out);
        }
        sss_packet_set_error(cctx->creq->out, ret);

        break;

    default:
        DEBUG(1, ("getpwnam call returned more than one result !?!\n"));
        ret = nss_cmd_send_error(cmdctx, ENOENT);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
    }

    sss_cmd_done(cctx, cmdctx);
}

static void nss_cmd_getpwnam_dp_callback(uint16_t err_maj, uint32_t err_min,
                                         const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sysdb_ctx *sysdb;
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

    ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                  dctx->domain, &sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
        NSS_CMD_FATAL_ERROR(cctx);
    }
    ret = sysdb_getpwnam(cmdctx, sysdb,
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
        sss_cmd_done(cctx, cmdctx);
    }
}

static int nss_cmd_getpwnam(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    const char *rawname;
    char *domname;
    uint8_t *body;
    size_t blen;
    int ret;
    int ncret;
    bool neghit = false;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmdctx = cmdctx;

    /* get user name to query */
    sss_packet_get_body(cctx->creq->in, &body, &blen);

    /* if not terminated fail */
    if (body[blen -1] != '\0') {
        ret = EINVAL;
        goto done;
    }
    rawname = (const char *)body;

    domname = NULL;
    ret = sss_parse_name(cmdctx, cctx->rctx->names, rawname,
                         &domname, &cmdctx->name);
    if (ret != EOK) {
        DEBUG(2, ("Invalid name received [%s]\n", rawname));
        ret = ENOENT;
        goto done;
    }

    DEBUG(4, ("Requesting info for [%s] from [%s]\n",
              cmdctx->name, domname?domname:"<ALL>"));

    if (domname) {
        dctx->domain = nss_get_dom(cctx->rctx->domains, domname);
        if (!dctx->domain) {
            ret = ENOENT;
            goto done;
        }

        /* verify this user has not yet been negatively cached,
         * or has been permanently filtered */
        ncret = nss_ncache_check_user(nctx->ncache, nctx->neg_timeout,
                                      dctx->domain->name, cmdctx->name);
        if (ncret == EEXIST) {
            neghit = true;
        }
    }
    else {
        /* skip domains that require FQnames or have negative caches */
        for (dom = cctx->rctx->domains; dom; dom = dom->next) {

            if (dom->fqnames) continue;

            /* verify this user has not yet been negatively cached,
            * or has been permanently filtered */
            ncret = nss_ncache_check_user(nctx->ncache, nctx->neg_timeout,
                                          dom->name, cmdctx->name);
            if (ncret == ENOENT) break;

            neghit = true;
        }
        /* reset neghit if we still have a domain to check */
        if (dom) neghit = false;

        dctx->domain = dom;
    }
    if (neghit) {
        DEBUG(2, ("User [%s] does not exist! (negative cache)\n", rawname));
        ret = ENOENT;
        goto done;
    }
    if (dctx->domain == NULL) {
        DEBUG(2, ("No matching domain found for [%s], fail!\n", rawname));
        ret = ENOENT;
        goto done;
    }

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    if (!domname) {
        /* this is a multidomain search */
        cmdctx->check_next = true;
    }

    DEBUG(4, ("Requesting info for [%s@%s]\n",
              cmdctx->name, dctx->domain->name));

    ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                  dctx->domain, &sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
        ret = EFAULT;
        goto done;
    }
    ret = sysdb_getpwnam(cmdctx, sysdb,
                         dctx->domain, cmdctx->name,
                         nss_cmd_getpwnam_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));
    }

done:
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* we do not have any entry to return */
            ret = sss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                                 sss_packet_get_cmd(cctx->creq->in),
                                 &cctx->creq->out);
            if (ret == EOK) {
                sss_packet_get_body(cctx->creq->out, &body, &blen);
                ((uint32_t *)body)[0] = 0; /* 0 results */
                ((uint32_t *)body)[1] = 0; /* reserved */
            }
        }
        if (ret != EOK) {
            ret = nss_cmd_send_error(cmdctx, ret);
        }
        if (ret == EOK) {
            sss_cmd_done(cctx, cmdctx);
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
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    uint8_t *body;
    size_t blen;
    bool neghit = false;
    int ret;
    int ncret;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    if (status != LDB_SUCCESS) {
        ret = nss_cmd_send_error(cmdctx, status);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_cmd_done(cctx, cmdctx);
        return;
    }

    if (dctx->check_provider) {
        ret = check_cache(dctx, nctx, res,
                          SSS_DP_USER, NULL, cmdctx->id,
                          nss_cmd_getpwuid_dp_callback);
        if (ret != EOK) {
            /* Anything but EOK means we should reenter the mainloop
             * because we may be refreshing the cache
             */
            return;
        }
    }

    switch (res->count) {
    case 0:
        if (cmdctx->check_next) {

            ret = EOK;

            dom = dctx->domain->next;
            ncret = nss_ncache_check_uid(nctx->ncache, nctx->neg_timeout,
                                             cmdctx->id);
            if (ncret == EEXIST) {
                DEBUG(3, ("Uid [%lu] does not exist! (negative cache)\n",
                          (unsigned long)cmdctx->id));
                ret = ENOENT;
            }
            if (dom == NULL) {
                DEBUG(0, ("No matching domain found for [%lu], fail!\n",
                          (unsigned long)cmdctx->id));
                ret = ENOENT;
            }

            if (ret == EOK) {
                dctx->domain = dom;
                dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
                if (dctx->res) talloc_free(res);
                dctx->res = NULL;

                DEBUG(4, ("Requesting info for [%s@%s]\n",
                          cmdctx->name, dctx->domain->name));

                ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                              dctx->domain, &sysdb);
                if (ret != EOK) {
                    DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
                    NSS_CMD_FATAL_ERROR(cctx);
                }
                ret = sysdb_getpwuid(cmdctx, sysdb,
                                     dctx->domain, cmdctx->id,
                                     nss_cmd_getpwuid_callback, dctx);
                if (ret != EOK) {
                    DEBUG(1, ("Failed to make request to our cache!\n"));
                }
            }

            /* we made another call, end here */
            if (ret == EOK) return;
        }

        DEBUG(2, ("No results for getpwuid call\n"));

        /* set negative cache only if not result of cache check */
        if (!neghit) {
            ret = nss_ncache_set_uid(nctx->ncache, false, cmdctx->id);
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
        DEBUG(6, ("Returning info for user [%u]\n", (unsigned)cmdctx->id));

        /* create response packet */
        ret = sss_packet_new(cctx->creq, 0,
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }

        ret = fill_pwent(cctx->creq->out,
                         dctx->domain,
                         nctx, true,
                         res->msgs, res->count);
        if (ret == ENOENT) {
            ret = fill_empty(cctx->creq->out);
        }
        sss_packet_set_error(cctx->creq->out, ret);

        break;

    default:
        DEBUG(1, ("getpwnam call returned more than one result !?!\n"));
        ret = nss_cmd_send_error(cmdctx, ENOENT);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
    }

    sss_cmd_done(cctx, cmdctx);
}

static void nss_cmd_getpwuid_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sysdb_ctx *sysdb;
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

    ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                  dctx->domain, &sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
        NSS_CMD_FATAL_ERROR(cctx);
    }
    ret = sysdb_getpwuid(cmdctx, sysdb,
                         dctx->domain, cmdctx->id,
                         nss_cmd_getpwuid_callback, dctx);

done:
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_cmd_done(cctx, cmdctx);
    }
}

static int nss_cmd_getpwuid(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    uint8_t *body;
    size_t blen;
    int ret;
    int ncret;

    ret = ENOENT;
    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmdctx = cmdctx;

    /* get uid to query */
    sss_packet_get_body(cctx->creq->in, &body, &blen);

    if (blen != sizeof(uint32_t)) {
        ret = EINVAL;
        goto done;
    }
    cmdctx->id = *((uint32_t *)body);

    /* this is a multidomain search */
    cmdctx->check_next = true;

    for (dom = cctx->rctx->domains; dom; dom = dom->next) {
        /* verify this user has not yet been negatively cached,
         * or has been permanently filtered */
        ncret = nss_ncache_check_uid(nctx->ncache, nctx->neg_timeout,
                                     cmdctx->id);
        if (ncret == EEXIST) {
            DEBUG(3, ("Uid [%lu] does not exist! (negative cache)\n",
                      (unsigned long)cmdctx->id));
            continue;
        }

        /* check that the uid is valid for this domain */
        if ((dom->id_min && (cmdctx->id < dom->id_min)) ||
            (dom->id_max && (cmdctx->id > dom->id_max))) {
            DEBUG(4, ("Uid [%lu] does not exist in domain [%s]! "
                      "(id out of range)\n",
                      (unsigned long)cmdctx->id, dom->name));
            continue;
        }

        dctx->domain = dom;
        dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

        DEBUG(4, ("Requesting info for [%lu@%s]\n",
                  cmdctx->id, dctx->domain->name));

        ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                      dctx->domain, &sysdb);
        if (ret != EOK) {
            DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
            ret = EFAULT;
            goto done;
        }
        ret = sysdb_getpwuid(cmdctx, sysdb,
                             dctx->domain, cmdctx->id,
                             nss_cmd_getpwuid_callback, dctx);
        if (ret != EOK) {
            DEBUG(1, ("Failed to make request to our cache!\n"));
        }

        break;
    }

done:
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* we do not have any entry to return */
            ret = sss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                                 sss_packet_get_cmd(cctx->creq->in),
                                 &cctx->creq->out);
            if (ret == EOK) {
                sss_packet_get_body(cctx->creq->out, &body, &blen);
                ((uint32_t *)body)[0] = 0; /* 0 results */
                ((uint32_t *)body)[1] = 0; /* reserved */
            }
        }
        if (ret != EOK) {
            ret = nss_cmd_send_error(cmdctx, ret);
        }
        if (ret == EOK) {
            sss_cmd_done(cctx, cmdctx);
        }
        return ret;
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

static void nss_cmd_setpw_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr);

static void nss_cmd_setpwent_callback(void *ptr, int status,
                                      struct ldb_result *res)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct getent_ctx *pctx;
    struct nss_ctx *nctx;
    int timeout;
    int ret;

    if (status != LDB_SUCCESS) {
        ret = nss_cmd_send_error(cmdctx, ENOENT);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_cmd_done(cctx, cmdctx);
        return;
    }

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    pctx = nctx->pctx;
    if (pctx == NULL) {
        pctx = talloc_zero(nctx, struct getent_ctx);
        if (!pctx) {
            ret = nss_cmd_send_error(cmdctx, ENOMEM);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
            sss_cmd_done(cctx, cmdctx);
            return;
        }
        nctx->pctx = pctx;
    }

    pctx->doms = talloc_realloc(pctx, pctx->doms, struct dom_ctx, pctx->num +1);
    if (!pctx->doms) {
        talloc_free(pctx);
        nctx->pctx = NULL;
        NSS_CMD_FATAL_ERROR(cctx);
    }

    pctx->doms[pctx->num].domain = dctx->domain;
    pctx->doms[pctx->num].res = talloc_steal(pctx->doms, res);
    pctx->doms[pctx->num].cur = 0;

    pctx->num++;

    /* do not reply until all domain searches are done */
    for (dom = dctx->domain->next; dom; dom = dom->next) {
        if (dom->enumerate != 0) break;
    }
    dctx->domain = dom;

    if (dctx->domain != NULL) {
        if (cmdctx->enum_cached) {
            dctx->check_provider = false;
        } else {
            dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
        }

        if (dctx->check_provider) {
            timeout = SSS_CLI_SOCKET_TIMEOUT;
            ret = sss_dp_send_acct_req(cctx->rctx, cmdctx,
                                       nss_cmd_setpw_dp_callback, dctx,
                                       timeout, dom->name, true,
                                       SSS_DP_USER, NULL, 0);
        } else {
            ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                          dctx->domain, &sysdb);
            if (ret != EOK) {
                DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
                NSS_CMD_FATAL_ERROR(cctx);
            }
            ret = sysdb_enumpwent(dctx, sysdb,
                                  dctx->domain, NULL,
                                  nss_cmd_setpwent_callback, dctx);
        }
        if (ret != EOK) {
            /* FIXME: shutdown ? */
            DEBUG(1, ("Failed to send enumeration request for domain [%s]!\n",
                      dom->name));

            ret = nss_cmd_send_error(cmdctx, ret);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
            sss_cmd_done(cctx, cmdctx);
        }
        return;
    }

    /* set cache mark */
    nctx->last_user_enum = time(NULL);

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
    sss_cmd_done(cctx, cmdctx);
}

static void nss_cmd_setpw_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sysdb_ctx *sysdb;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                  dctx->domain, &sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
        NSS_CMD_FATAL_ERROR(cctx);
    }
    ret = sysdb_enumpwent(cmdctx, sysdb,
                          dctx->domain, NULL,
                          nss_cmd_setpwent_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_cmd_done(cctx, cmdctx);
    }
}

static int nss_cmd_setpwent_ext(struct cli_ctx *cctx, bool immediate)
{
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct nss_ctx *nctx;
    time_t now = time(NULL);
    int timeout;
    uint8_t *body;
    size_t blen;
    int ret;

    DEBUG(4, ("Requesting info for all users\n"));

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    talloc_free(nctx->pctx);
    nctx->pctx = NULL;

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;
    cmdctx->immediate = immediate;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmdctx = cmdctx;

    /* do not query backends if we have a recent enumeration */
    if (nctx->enum_cache_timeout) {
        if (nctx->last_user_enum +
            nctx->enum_cache_timeout > now) {
            cmdctx->enum_cached = true;
        }
    }

    /* check if enumeration is enabled in any domain */
    for (dom = cctx->rctx->domains; dom; dom = dom->next) {
        if (dom->enumerate != 0) break;
    }
    dctx->domain = dom;

    if (dctx->domain == NULL) {
        DEBUG(2, ("Enumeration disabled on all domains!\n"));
        ret = ENOENT;
        goto done;
    }

    if (cmdctx->enum_cached) {
        dctx->check_provider = false;
    } else {
        dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
    }

    if (dctx->check_provider) {
        timeout = SSS_CLI_SOCKET_TIMEOUT;
        ret = sss_dp_send_acct_req(cctx->rctx, cmdctx,
                                   nss_cmd_setpw_dp_callback, dctx,
                                   timeout, dom->name, true,
                                   SSS_DP_USER, NULL, 0);
    } else {
        ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                      dctx->domain, &sysdb);
        if (ret != EOK) {
            DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
            ret = EFAULT;
            goto done;
        }
        ret = sysdb_enumpwent(dctx, sysdb,
                              dctx->domain, NULL,
                              nss_cmd_setpwent_callback, dctx);
    }
    if (ret != EOK) {
        /* FIXME: shutdown ? */
        DEBUG(1, ("Failed to send enumeration request for domain [%s]!\n",
                  dom->name));
    }

done:
    if (ret != EOK) {
        if (ret == ENOENT) {
            if (cmdctx->immediate) {
                /* we do not have any entry to return */
                ret = sss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                                     sss_packet_get_cmd(cctx->creq->in),
                                     &cctx->creq->out);
                if (ret == EOK) {
                    sss_packet_get_body(cctx->creq->out, &body, &blen);
                    ((uint32_t *)body)[0] = 0; /* 0 results */
                    ((uint32_t *)body)[1] = 0; /* reserved */
                }
            }
            else {
                /* create response packet */
                ret = sss_packet_new(cctx->creq, 0,
                                     sss_packet_get_cmd(cctx->creq->in),
                                     &cctx->creq->out);
            }
        }
        if (ret != EOK) {
            ret = nss_cmd_send_error(cmdctx, ret);
        }
        if (ret == EOK) {
            sss_cmd_done(cctx, cmdctx);
        }
        return ret;
    }

    return EOK;
}

static int nss_cmd_setpwent(struct cli_ctx *cctx)
{
    return nss_cmd_setpwent_ext(cctx, false);
}


static int nss_cmd_retpwent(struct cli_ctx *cctx, int num)
{
    struct nss_ctx *nctx;
    struct getent_ctx *pctx;
    struct ldb_message **msgs = NULL;
    struct dom_ctx *pdom = NULL;
    int n = 0;
    int ret;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    pctx = nctx->pctx;

retry:
    if (pctx->cur >= pctx->num) goto none;

    pdom = &pctx->doms[pctx->cur];

    n = pdom->res->count - pdom->cur;
    if (n == 0 && (pctx->cur+1 < pctx->num)) {
        pctx->cur++;
        pdom = &pctx->doms[pctx->cur];
        n = pdom->res->count - pdom->cur;
    }

    if (!n) goto none;

    if (n > num) n = num;

    msgs = &(pdom->res->msgs[pdom->cur]);
    pdom->cur += n;

    ret = fill_pwent(cctx->creq->out, pdom->domain, nctx, true, msgs, n);
    if (ret == ENOENT) goto retry;
    return ret;

none:
    return fill_empty(cctx->creq->out);
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
    sss_cmd_done(cctx, cmdctx);

    return EOK;
}

static int nss_cmd_getpwent(struct cli_ctx *cctx)
{
    struct nss_ctx *nctx;
    struct nss_cmd_ctx *cmdctx;

    DEBUG(4, ("Requesting info for all accounts\n"));

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    /* see if we need to trigger an implicit setpwent() */
    if (nctx->pctx == NULL) {
        nctx->pctx = talloc_zero(nctx, struct getent_ctx);
        if (!nctx->pctx) return ENOMEM;

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
    struct nss_ctx *nctx;
    int ret;

    DEBUG(4, ("Terminating request info for all accounts\n"));

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);

    if (nctx->pctx == NULL) goto done;

    /* free results and reset */
    talloc_free(nctx->pctx);
    nctx->pctx = NULL;

done:
    sss_cmd_done(cctx, NULL);
    return EOK;
}

/****************************************************************************
 * GROUP db related functions
 ***************************************************************************/

#define GID_ROFFSET 0
#define MNUM_ROFFSET sizeof(uint32_t)
#define STRS_ROFFSET 2*sizeof(uint32_t)

static int fill_grent(struct sss_packet *packet,
                      struct sss_domain_info *dom,
                      struct nss_ctx *nctx,
                      bool filter_groups,
                      struct ldb_message **msgs,
                      int max, int *count)
{
    struct ldb_message *msg;
    struct ldb_message_element *el;
    uint8_t *body;
    size_t blen;
    uint32_t gid;
    const char *name;
    size_t nsize;
    size_t delim;
    size_t dom_len;
    size_t pwlen;
    int i = 0;
    int j = 0;
    int ret, num, memnum;
    size_t rzero, rsize;
    bool add_domain = dom->fqnames;
    const char *domain = dom->name;
    const char *namefmt = nctx->rctx->names->fq_fmt;

    if (add_domain) {
        delim = 1;
        dom_len = strlen(domain);
    } else {
        delim = 0;
        dom_len = 0;
    }

    num = 0;
    pwlen = strlen(nctx->pwfield) + 1;

    /* first 2 fields (len and reserved), filled up later */
    ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
    if (ret != EOK) {
        goto done;
    }
    sss_packet_get_body(packet, &body, &blen);
    rzero = 2*sizeof(uint32_t);
    rsize = 0;

    for (i = 0; i < *count; i++) {
        msg = msgs[i];

        /* new group */
        if (!ldb_msg_check_string_attribute(msg, "objectClass",
                                            SYSDB_GROUP_CLASS)) {
            DEBUG(1, ("Wrong object (%s) found on stack!\n",
                      ldb_dn_get_linearized(msg->dn)));
            continue;
        }

        /* if we reached the max allowed entries, simply return */
        if (num >= max) {
            goto done;
        }

        /* new result starts at end of previous result */
        rzero += rsize;
        rsize = 0;

        /* find group name/gid */
        name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        gid = ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);
        if (!name || !gid) {
            DEBUG(1, ("Incomplete group object for %s[%llu]! Skipping\n",
                      name?name:"<NULL>", (unsigned long long int)gid));
            continue;
        }

        if (filter_groups) {
            ret = nss_ncache_check_group(nctx->ncache,
                                         nctx->neg_timeout, domain, name);
            if (ret == EEXIST) {
                DEBUG(4, ("Group [%s@%s] filtered out! (negative cache)\n",
                          name, domain));
                continue;
            }
        }

        nsize = strlen(name) + 1; /* includes terminating \0 */
        if (add_domain) nsize += delim + dom_len;

        /* fill in gid and name and set pointer for number of members */
        rsize = STRS_ROFFSET + nsize + pwlen; /* name\0x\0 */

        ret = sss_packet_grow(packet, rsize);
        if (ret != EOK) {
            num = 0;
            goto done;
        }
        sss_packet_get_body(packet, &body, &blen);

        /*  0-3: 32bit number gid */
        ((uint32_t *)(&body[rzero+GID_ROFFSET]))[0] = gid;

        /*  4-7: 32bit unsigned number of members */
        ((uint32_t *)(&body[rzero+MNUM_ROFFSET]))[0] = 0;

        /*  8-X: sequence of strings (name, passwd, mem..) */
        if (add_domain) {
            ret = snprintf((char *)&body[rzero+STRS_ROFFSET],
                            nsize, namefmt, name, domain);
            if (ret >= nsize) {
                /* need more space, got creative with the print format ? */
                int t = ret - nsize + 1;
                ret = sss_packet_grow(packet, t);
                if (ret != EOK) {
                    num = 0;
                    goto done;
                }
                sss_packet_get_body(packet, &body, &blen);
                rsize += t;
                delim += t;
                nsize += t;

                /* retry */
                ret = snprintf((char *)&body[rzero+STRS_ROFFSET],
                                nsize, namefmt, name, domain);
            }

            if (ret != nsize-1) {
                DEBUG(1, ("Failed to generate a fully qualified name for"
                          " group [%s] in [%s]! Skipping\n", name, domain));
                /* reclaim space */
                ret = sss_packet_shrink(packet, rsize);
                if (ret != EOK) {
                    num = 0;
                    goto done;
                }
                rsize = 0;
                continue;
            }
        } else {
            memcpy(&body[rzero+STRS_ROFFSET], name, nsize);
        }

        /* group passwd field */
        memcpy(&body[rzero + rsize -pwlen], nctx->pwfield, pwlen);

        el = ldb_msg_find_element(msg, SYSDB_MEMBERUID);
        if (el) {
            memnum = 0;

            for (j = 0; j < el->num_values; j++) {
                name = (const char *)el->values[j].data;

                if (nctx->filter_users_in_groups) {
                    ret = nss_ncache_check_user(nctx->ncache,
                                                nctx->neg_timeout,
                                                domain, name);
                    if (ret == EEXIST) {
                        DEBUG(6, ("Group [%s] member [%s@%s] filtered out!"
                                  " (negative cache)\n",
                                  (char *)&body[rzero+STRS_ROFFSET],
                                  name, domain));
                        continue;
                    }
                }

                nsize = strlen(name) + 1; /* includes terminating \0 */
                if (add_domain) nsize += delim + dom_len;

                ret = sss_packet_grow(packet, nsize);
                if (ret != EOK) {
                    num = 0;
                    goto done;
                }
                sss_packet_get_body(packet, &body, &blen);

                if (add_domain) {
                    ret = snprintf((char *)&body[rzero + rsize],
                                    nsize, namefmt, name, domain);
                    if (ret >= nsize) {
                        /* need more space,
                         * got creative with the print format ? */
                        int t = ret - nsize + 1;
                        ret = sss_packet_grow(packet, t);
                        if (ret != EOK) {
                            num = 0;
                            goto done;
                        }
                        sss_packet_get_body(packet, &body, &blen);
                        delim += t;
                        nsize += t;

                        /* retry */
                        ret = snprintf((char *)&body[rzero + rsize],
                                        nsize, namefmt, name, domain);
                    }

                    if (ret != nsize-1) {
                        DEBUG(1, ("Failed to generate a fully qualified name"
                                  " for member [%s@%s] of group [%s]!"
                                  " Skipping\n", name, domain,
                                  (char *)&body[rzero+STRS_ROFFSET]));
                        /* reclaim space */
                        ret = sss_packet_shrink(packet, nsize);
                        if (ret != EOK) {
                            num = 0;
                            goto done;
                        }
                        continue;
                    }

                } else {
                    memcpy(&body[rzero + rsize], name, nsize);
                }

                rsize += nsize;

                memnum++;
            }

            if (memnum) {
                /* set num of members */
                ((uint32_t *)(&body[rzero+MNUM_ROFFSET]))[0] = memnum;
            }
        }

        num++;
        continue;
    }

done:
    *count = i;

    if (num == 0) {
        /* if num is 0 most probably something went wrong,
         * reset packet and return ENOENT */
        ret = sss_packet_set_size(packet, 0);
        if (ret != EOK) return ret;
        return ENOENT;
    }

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
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    uint8_t *body;
    size_t blen;
    bool neghit = false;
    int ncret;
    int i, ret;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    if (status != LDB_SUCCESS) {
        ret = nss_cmd_send_error(cmdctx, status);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_cmd_done(cctx, cmdctx);
        return;
    }

    if (dctx->check_provider) {
        ret = check_cache(dctx, nctx, res,
                          SSS_DP_GROUP, cmdctx->name, 0,
                          nss_cmd_getgrnam_dp_callback);
        if (ret != EOK) {
            /* Anything but EOK means we should reenter the mainloop
             * because we may be refreshing the cache
             */
            return;
        }
    }

    switch (res->count) {
    case 0:
        if (cmdctx->check_next) {

            ret = EOK;

            /* skip domains that require FQnames or have negative caches */
            for (dom = dctx->domain->next; dom; dom = dom->next) {

                if (dom->fqnames) continue;

                ncret = nss_ncache_check_group(nctx->ncache,
                                               nctx->neg_timeout,
                                               dom->name, cmdctx->name);
                if (ncret == ENOENT) break;

                neghit = true;
            }
            /* reset neghit if we still have a domain to check */
            if (dom) neghit = false;

            if (neghit) {
                DEBUG(2, ("Group [%s] does not exist! (negative cache)\n",
                          cmdctx->name));
                ret = ENOENT;
            }
            if (dom == NULL) {
                DEBUG(2, ("No matching domain found for [%s], fail!\n",
                          cmdctx->name));
                ret = ENOENT;
            }

            if (ret == EOK) {
                dctx->domain = dom;
                dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
                if (dctx->res) talloc_free(res);
                dctx->res = NULL;

                DEBUG(4, ("Requesting info for [%s@%s]\n",
                          cmdctx->name, dctx->domain->name));

                ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                              dctx->domain, &sysdb);
                if (ret != EOK) {
                    DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
                    NSS_CMD_FATAL_ERROR(cctx);
                }
                ret = sysdb_getgrnam(cmdctx, sysdb,
                                     dctx->domain, cmdctx->name,
                                     nss_cmd_getgrnam_callback, dctx);
                if (ret != EOK) {
                    DEBUG(1, ("Failed to make request to our cache!\n"));
                }
            }

            /* we made another call, end here */
            if (ret == EOK) return;
        }


        DEBUG(2, ("No results for getgrnam call\n"));

        /* set negative cache only if not result of cache check */
        if (!neghit) {
            ret = nss_ncache_set_group(nctx->ncache, false,
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
        i = res->count;
        ret = fill_grent(cctx->creq->out,
                         dctx->domain,
                         nctx, false,
                         res->msgs, 1, &i);
        if (ret == ENOENT) {
            ret = fill_empty(cctx->creq->out);
        }
        sss_packet_set_error(cctx->creq->out, ret);
    }

    sss_cmd_done(cctx, cmdctx);
}

static void nss_cmd_getgrnam_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sysdb_ctx *sysdb;
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

    ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                  dctx->domain, &sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
        NSS_CMD_FATAL_ERROR(cctx);
    }
    ret = sysdb_getgrnam(cmdctx, sysdb,
                         dctx->domain, cmdctx->name,
                         nss_cmd_getgrnam_callback, dctx);

done:
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache! (%d [%s])\n",
                  ret, strerror(ret)));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_cmd_done(cctx, cmdctx);
    }
}

static int nss_cmd_getgrnam(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    const char *rawname;
    char *domname;
    uint8_t *body;
    size_t blen;
    int ret;
    int ncret;
    bool neghit = false;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmdctx = cmdctx;

    /* get user name to query */
    sss_packet_get_body(cctx->creq->in, &body, &blen);

    /* if not terminated fail */
    if (body[blen -1] != '\0') {
        ret = EINVAL;
        goto done;
    }
    rawname = (const char *)body;

    domname = NULL;
    ret = sss_parse_name(cmdctx, cctx->rctx->names, rawname,
                         &domname, &cmdctx->name);
    if (ret != EOK) {
        DEBUG(2, ("Invalid name received [%s]\n", rawname));
        ret = ENOENT;
        goto done;
    }

    DEBUG(4, ("Requesting info for [%s] from [%s]\n",
              cmdctx->name, domname?domname:"<ALL>"));

    if (domname) {
        dctx->domain = nss_get_dom(cctx->rctx->domains, domname);
        if (!dctx->domain) {
            ret = ENOENT;
            goto done;
        }

        /* verify this user has not yet been negatively cached,
         * or has been permanently filtered */
        ncret = nss_ncache_check_group(nctx->ncache, nctx->neg_timeout,
                                       dctx->domain->name, cmdctx->name);
        if (ncret == EEXIST) {
            neghit = true;
        }
    }
    else {
        /* skip domains that require FQnames or have negative caches */
        for (dom = cctx->rctx->domains; dom; dom = dom->next) {

            if (dom->fqnames) continue;

            /* verify this user has not yet been negatively cached,
             * or has been permanently filtered */
            ncret = nss_ncache_check_group(nctx->ncache, nctx->neg_timeout,
                                           dom->name, cmdctx->name);
            if (ncret == ENOENT) break;

            neghit = true;
        }
        /* reset neghit if we still have a domain to check */
        if (dom) neghit = false;

        dctx->domain = dom;
    }
    if (neghit) {
        DEBUG(2, ("Group [%s] does not exist! (negative cache)\n", rawname));
        ret = ENOENT;
        goto done;
    }
    if (dctx->domain == NULL) {
        DEBUG(2, ("No matching domain found for [%s], fail!\n", rawname));
        ret = ENOENT;
        goto done;
    }

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    if (!domname) {
        /* this is a multidomain search */
        cmdctx->check_next = true;
    }

    DEBUG(4, ("Requesting info for [%s@%s]\n",
              cmdctx->name, dctx->domain->name));

    ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                  dctx->domain, &sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
        ret = EFAULT;
        goto done;
    }
    ret = sysdb_getgrnam(cmdctx, sysdb,
                         dctx->domain, cmdctx->name,
                         nss_cmd_getgrnam_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));
    }

done:
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* we do not have any entry to return */
            ret = sss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                                 sss_packet_get_cmd(cctx->creq->in),
                                 &cctx->creq->out);
            if (ret == EOK) {
                sss_packet_get_body(cctx->creq->out, &body, &blen);
                ((uint32_t *)body)[0] = 0; /* 0 results */
                ((uint32_t *)body)[1] = 0; /* reserved */
            }
        }
        if (ret != EOK) {
            ret = nss_cmd_send_error(cmdctx, ret);
        }
        if (ret == EOK) {
            sss_cmd_done(cctx, cmdctx);
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
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    uint8_t *body;
    size_t blen;
    bool neghit = false;
    int i, ret;
    int ncret;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    if (status != LDB_SUCCESS) {
        ret = nss_cmd_send_error(cmdctx, status);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_cmd_done(cctx, cmdctx);
        return;
    }

    if (dctx->check_provider) {
        ret = check_cache(dctx, nctx, res,
                          SSS_DP_GROUP, NULL, cmdctx->id,
                          nss_cmd_getgrgid_dp_callback);
        if (ret != EOK) {
            /* Anything but EOK means we should reenter the mainloop
             * because we may be refreshing the cache
             */
            return;
        }
    }

    switch (res->count) {
    case 0:
        if (cmdctx->check_next) {

            ret = EOK;

            dom = dctx->domain->next;

            ncret = nss_ncache_check_gid(nctx->ncache, nctx->neg_timeout,
                                         cmdctx->id);
            if (ncret == EEXIST) {
                DEBUG(3, ("Gid [%lu] does not exist! (negative cache)\n",
                          (unsigned long)cmdctx->id));
                ret = ENOENT;
            }
            if (dom == NULL) {
                DEBUG(0, ("No matching domain found for [%lu], fail!\n",
                          (unsigned long)cmdctx->id));
                ret = ENOENT;
            }

            if (ret == EOK) {
                dctx->domain = dom;
                dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
                if (dctx->res) talloc_free(res);
                dctx->res = NULL;

                DEBUG(4, ("Requesting info for [%s@%s]\n",
                          cmdctx->name, dctx->domain->name));

                ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                              dctx->domain, &sysdb);
                if (ret != EOK) {
                    DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
                    NSS_CMD_FATAL_ERROR(cctx);
                }
                ret = sysdb_getgrgid(cmdctx, sysdb,
                                     dctx->domain, cmdctx->id,
                                     nss_cmd_getgrgid_callback, dctx);
                if (ret != EOK) {
                    DEBUG(1, ("Failed to make request to our cache!\n"));
                }
            }

            /* we made another call, end here */
            if (ret == EOK) return;
        }

        DEBUG(2, ("No results for getgrgid call\n"));

        /* set negative cache only if not result of cache check */
        if (!neghit) {
            ret = nss_ncache_set_gid(nctx->ncache, false, cmdctx->id);
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
        i = res->count;
        ret = fill_grent(cctx->creq->out,
                         dctx->domain,
                         nctx, true,
                         res->msgs, 1, &i);
        if (ret == ENOENT) {
            ret = fill_empty(cctx->creq->out);
        }
        sss_packet_set_error(cctx->creq->out, ret);
    }

    sss_cmd_done(cctx, cmdctx);
}

static void nss_cmd_getgrgid_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sysdb_ctx *sysdb;
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

    ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                  dctx->domain, &sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
        NSS_CMD_FATAL_ERROR(cctx);
    }
    ret = sysdb_getgrgid(cmdctx, sysdb,
                         dctx->domain, cmdctx->id,
                         nss_cmd_getgrgid_callback, dctx);

done:
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_cmd_done(cctx, cmdctx);
    }
}

static int nss_cmd_getgrgid(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    uint8_t *body;
    size_t blen;
    int ret;
    int ncret;

    ret = ENOENT;
    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmdctx = cmdctx;

    /* get uid to query */
    sss_packet_get_body(cctx->creq->in, &body, &blen);

    if (blen != sizeof(uint32_t)) {
        ret = EINVAL;
        goto done;
    }
    cmdctx->id = *((uint32_t *)body);

    /* this is a multidomain search */
    cmdctx->check_next = true;

    for (dom = cctx->rctx->domains; dom; dom = dom->next) {
        /* verify this user has not yet been negatively cached,
         * or has been permanently filtered */
        ncret = nss_ncache_check_gid(nctx->ncache, nctx->neg_timeout,
                                     cmdctx->id);
        if (ncret == EEXIST) {
            DEBUG(3, ("Gid [%lu] does not exist! (negative cache)\n",
                      (unsigned long)cmdctx->id));
            continue;
        }

        /* check that the uid is valid for this domain */
        if ((dom->id_min && (cmdctx->id < dom->id_min)) ||
            (dom->id_max && (cmdctx->id > dom->id_max))) {
            DEBUG(4, ("Gid [%lu] does not exist in domain [%s]! "
                      "(id out of range)\n",
                      (unsigned long)cmdctx->id, dom->name));
            continue;
        }

        dctx->domain = dom;
        dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

        DEBUG(4, ("Requesting info for [%lu@%s]\n",
                  cmdctx->id, dctx->domain->name));

        ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                      dctx->domain, &sysdb);
        if (ret != EOK) {
            DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
            ret = EFAULT;
            goto done;
        }
        ret = sysdb_getgrgid(cmdctx, sysdb,
                             dctx->domain, cmdctx->id,
                             nss_cmd_getgrgid_callback, dctx);
        if (ret != EOK) {
            DEBUG(1, ("Failed to make request to our cache!\n"));
        }

        break;
    }

done:
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* we do not have any entry to return */
            ret = sss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                                 sss_packet_get_cmd(cctx->creq->in),
                                 &cctx->creq->out);
            if (ret == EOK) {
                sss_packet_get_body(cctx->creq->out, &body, &blen);
                ((uint32_t *)body)[0] = 0; /* 0 results */
                ((uint32_t *)body)[1] = 0; /* reserved */
            }
        }
        if (ret != EOK) {
            ret = nss_cmd_send_error(cmdctx, ret);
        }
        if (ret == EOK) {
            sss_cmd_done(cctx, cmdctx);
        }
        return ret;
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

static void nss_cmd_setgr_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr);

static void nss_cmd_setgrent_callback(void *ptr, int status,
                                     struct ldb_result *res)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct getent_ctx *gctx;
    struct nss_ctx *nctx;
    int timeout;
    int ret;

    if (status != LDB_SUCCESS) {
        ret = nss_cmd_send_error(cmdctx, ENOENT);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_cmd_done(cctx, cmdctx);
        return;
    }

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    gctx = nctx->gctx;
    if (gctx == NULL) {
        gctx = talloc_zero(nctx, struct getent_ctx);
        if (!gctx) {
            ret = nss_cmd_send_error(cmdctx, ENOMEM);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
            sss_cmd_done(cctx, cmdctx);
            return;
        }
        nctx->gctx = gctx;
    }

    gctx->doms = talloc_realloc(gctx, gctx->doms, struct dom_ctx, gctx->num +1);
    if (!gctx->doms) NSS_CMD_FATAL_ERROR(cctx);

    gctx->doms[gctx->num].domain = dctx->domain;
    gctx->doms[gctx->num].res = talloc_steal(gctx->doms, res);
    gctx->doms[gctx->num].cur = 0;

    gctx->num++;

    /* do not reply until all domain searches are done */
    for (dom = dctx->domain->next; dom; dom = dom->next) {
        if (dom->enumerate != 0) break;
    }
    dctx->domain = dom;

    if (dctx->domain != NULL) {
        if (cmdctx->enum_cached) {
            dctx->check_provider = false;
        } else {
            dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
        }

        if (dctx->check_provider) {
            timeout = SSS_CLI_SOCKET_TIMEOUT;
            ret = sss_dp_send_acct_req(cctx->rctx, cmdctx,
                                       nss_cmd_setgr_dp_callback, dctx,
                                       timeout, dom->name, true,
                                       SSS_DP_GROUP, NULL, 0);
        } else {
            ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                          dctx->domain, &sysdb);
            if (ret != EOK) {
                DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
                NSS_CMD_FATAL_ERROR(cctx);
            }
            ret = sysdb_enumgrent(dctx, sysdb,
                                  dctx->domain,
                                  nss_cmd_setgrent_callback, dctx);
        }
        if (ret != EOK) {
            /* FIXME: shutdown ? */
            DEBUG(1, ("Failed to send enumeration request for domain [%s]!\n",
                      dom->name));

            ret = nss_cmd_send_error(cmdctx, ret);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
            sss_cmd_done(cctx, cmdctx);
        }
        return;
    }

    /* set cache mark */
    nctx->last_group_enum = time(NULL);

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
    sss_cmd_done(cctx, cmdctx);
}

static void nss_cmd_setgr_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sysdb_ctx *sysdb;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                  dctx->domain, &sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
        NSS_CMD_FATAL_ERROR(cctx);
    }
    ret = sysdb_enumgrent(dctx, sysdb,
                          dctx->domain,
                          nss_cmd_setgrent_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_cmd_done(cctx, cmdctx);
    }
}

static int nss_cmd_setgrent_ext(struct cli_ctx *cctx, bool immediate)
{
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct nss_ctx *nctx;
    time_t now = time(NULL);
    int timeout;
    uint8_t *body;
    size_t blen;
    int ret;

    DEBUG(4, ("Requesting info for all groups\n"));

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    talloc_free(nctx->gctx);
    nctx->gctx = NULL;

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;
    cmdctx->immediate = immediate;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmdctx = cmdctx;

    /* do not query backends if we have a recent enumeration */
    if (nctx->enum_cache_timeout) {
        if (nctx->last_group_enum +
            nctx->enum_cache_timeout > now) {
            cmdctx->enum_cached = true;
        }
    }

    /* check if enumeration is enabled in any domain */
    for (dom = cctx->rctx->domains; dom; dom = dom->next) {
        if (dom->enumerate != 0) break;
    }
    dctx->domain = dom;

    if (dctx->domain == NULL) {
        DEBUG(2, ("Enumeration disabled on all domains!\n"));
        ret = ENOENT;
        goto done;
    }

    if (cmdctx->enum_cached) {
        dctx->check_provider = false;
    } else {
        dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
    }

    if (dctx->check_provider) {
        timeout = SSS_CLI_SOCKET_TIMEOUT;
        ret = sss_dp_send_acct_req(cctx->rctx, cmdctx,
                                   nss_cmd_setgr_dp_callback, dctx,
                                   timeout, dom->name, true,
                                   SSS_DP_GROUP, NULL, 0);
    } else {
        ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                      dctx->domain, &sysdb);
        if (ret != EOK) {
            DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
            ret = EFAULT;
            goto done;
        }
        ret = sysdb_enumgrent(dctx, sysdb,
                              dctx->domain,
                              nss_cmd_setgrent_callback, dctx);
    }
    if (ret != EOK) {
        /* FIXME: shutdown ? */
        DEBUG(1, ("Failed to send enumeration request for domain [%s]!\n",
                  dom->name));
    }

done:
    if (ret != EOK) {
        if (ret == ENOENT) {
            if (cmdctx->immediate) {
                /* we do not have any entry to return */
                ret = sss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                                     sss_packet_get_cmd(cctx->creq->in),
                                     &cctx->creq->out);
                if (ret == EOK) {
                    sss_packet_get_body(cctx->creq->out, &body, &blen);
                    ((uint32_t *)body)[0] = 0; /* 0 results */
                    ((uint32_t *)body)[1] = 0; /* reserved */
                }
            }
            else {
                /* create response packet */
                ret = sss_packet_new(cctx->creq, 0,
                                     sss_packet_get_cmd(cctx->creq->in),
                                     &cctx->creq->out);
            }
        }
        if (ret != EOK) {
            ret = nss_cmd_send_error(cmdctx, ret);
        }
        if (ret == EOK) {
            sss_cmd_done(cctx, cmdctx);
        }
        return ret;
    }

    return EOK;
}

static int nss_cmd_setgrent(struct cli_ctx *cctx)
{
    return nss_cmd_setgrent_ext(cctx, false);
}

static int nss_cmd_retgrent(struct cli_ctx *cctx, int num)
{
    struct nss_ctx *nctx;
    struct getent_ctx *gctx;
    struct ldb_message **msgs = NULL;
    struct dom_ctx *gdom = NULL;
    int n = 0;
    int ret;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    gctx = nctx->gctx;

    do {
        if (gctx->cur >= gctx->num) goto none;

        gdom = &gctx->doms[gctx->cur];

        n = gdom->res->count - gdom->cur;
        if (n == 0 && (gctx->cur+1 < gctx->num)) {
            gctx->cur++;
            gdom = &gctx->doms[gctx->cur];
            n = gdom->res->count - gdom->cur;
        }

        if (!n) goto none;

        msgs = &(gdom->res->msgs[gdom->cur]);

        ret = fill_grent(cctx->creq->out, gdom->domain, nctx, true, msgs, num, &n);

        gdom->cur += n;

    } while(ret == ENOENT);

    return ret;

none:
    return fill_empty(cctx->creq->out);
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
    sss_cmd_done(cctx, cmdctx);

    return EOK;
}

static int nss_cmd_getgrent(struct cli_ctx *cctx)
{
    struct nss_ctx *nctx;
    struct nss_cmd_ctx *cmdctx;

    DEBUG(4, ("Requesting info for all groups\n"));

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    /* see if we need to trigger an implicit setpwent() */
    if (nctx->gctx == NULL) {
        nctx->gctx = talloc_zero(nctx, struct getent_ctx);
        if (!nctx->gctx) return ENOMEM;

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
    struct nss_ctx *nctx;
    int ret;

    DEBUG(4, ("Terminating request info for all groups\n"));

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);

    if (nctx->gctx == NULL) goto done;

    /* free results and reset */
    talloc_free(nctx->gctx);
    nctx->gctx = NULL;

done:
    sss_cmd_done(cctx, NULL);
    return EOK;
}

static int fill_initgr(struct sss_packet *packet, struct ldb_result *res)
{
    uint8_t *body;
    size_t blen;
    gid_t gid;
    int ret, i, num;

    if (res->count == 0) {
        return ENOENT;
    }

    /* one less, the first one is the user entry */
    num = res->count -1;

    ret = sss_packet_grow(packet, (2 + res->count) * sizeof(uint32_t));
    if (ret != EOK) {
        return ret;
    }
    sss_packet_get_body(packet, &body, &blen);

    /* skip first entry, it's the user entry */
    for (i = 0; i < num; i++) {
        gid = ldb_msg_find_attr_as_uint64(res->msgs[i + 1], SYSDB_GIDNUM, 0);
        if (!gid) {
            DEBUG(1, ("Incomplete group object for initgroups! Aborting\n"));
            return EFAULT;
        }
        ((uint32_t *)body)[2 + i] = gid;
    }

    ((uint32_t *)body)[0] = num; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

    return EOK;
}

static void nss_cmd_getinitgr_dp_callback(uint16_t err_maj, uint32_t err_min,
                                          const char *err_msg, void *ptr);

static void nss_cmd_getinitgr_callback(void *ptr, int status,
                                       struct ldb_result *res)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    uint8_t *body;
    size_t blen;
    bool neghit = false;
    int ncret;
    int ret;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    if (status != LDB_SUCCESS) {
        ret = nss_cmd_send_error(cmdctx, status);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_cmd_done(cctx, cmdctx);
        return;
    }

    if (dctx->check_provider) {
        ret = check_cache(dctx, nctx, res,
                          SSS_DP_INITGROUPS, cmdctx->name, 0,
                          nss_cmd_getinitgr_dp_callback);
        if (ret != EOK) {
            /* Anything but EOK means we should reenter the mainloop
             * because we may be refreshing the cache
             */
            return;
        }
    }

    switch (res->count) {
    case 0:
        if (cmdctx->check_next) {

            ret = EOK;

            /* skip domains that require FQnames or have negative caches */
            for (dom = dctx->domain->next; dom; dom = dom->next) {

                if (dom->fqnames) continue;

                ncret = nss_ncache_check_user(nctx->ncache,
                                              nctx->neg_timeout,
                                              dom->name, cmdctx->name);
                if (ncret == ENOENT) break;

                neghit = true;
            }
            /* reset neghit if we still have a domain to check */
            if (dom) neghit = false;

            if (neghit) {
                DEBUG(2, ("User [%s] does not exist! (negative cache)\n",
                          cmdctx->name));
                ret = ENOENT;
            }
            if (dom == NULL) {
                DEBUG(2, ("No matching domain found for [%s], fail!\n",
                          cmdctx->name));
                ret = ENOENT;
            }

            if (ret == EOK) {
                dctx->domain = dom;
                dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
                if (dctx->res) talloc_free(res);
                dctx->res = NULL;

                DEBUG(4, ("Requesting info for [%s@%s]\n",
                          cmdctx->name, dctx->domain->name));

                ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                              dctx->domain, &sysdb);
                if (ret != EOK) {
                    DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
                    NSS_CMD_FATAL_ERROR(cctx);
                }
                ret = sysdb_initgroups(cmdctx, sysdb,
                                       dctx->domain, cmdctx->name,
                                       nss_cmd_getinitgr_callback, dctx);
                if (ret != EOK) {
                    DEBUG(1, ("Failed to make request to our cache!\n"));
                }
            }

            /* we made another call, end here */
            if (ret == EOK) return;
        }

        DEBUG(2, ("No results for initgroups call\n"));

        /* set negative cache only if not result of cache check */
        if (!neghit) {
            ret = nss_ncache_set_user(nctx->ncache, false,
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

        DEBUG(6, ("Returning initgr for user [%s]\n", cmdctx->name));

        ret = sss_packet_new(cctx->creq, 0,
                             sss_packet_get_cmd(cctx->creq->in),
                             &cctx->creq->out);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        ret = fill_initgr(cctx->creq->out, res);
        if (ret == ENOENT) {
            ret = fill_empty(cctx->creq->out);
        }
        sss_packet_set_error(cctx->creq->out, ret);
    }

    sss_cmd_done(cctx, cmdctx);
}

static void nss_cmd_getinitgr_dp_callback(uint16_t err_maj, uint32_t err_min,
                                          const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sysdb_ctx *sysdb;
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

        nss_cmd_getinitgr_callback(dctx, LDB_SUCCESS, dctx->res);
        return;
    }

    ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                  dctx->domain, &sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
        NSS_CMD_FATAL_ERROR(cctx);
    }
    ret = sysdb_initgroups(cmdctx, sysdb,
                           dctx->domain, cmdctx->name,
                           nss_cmd_getinitgr_callback, dctx);

done:
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));

        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret != EOK) {
            NSS_CMD_FATAL_ERROR(cctx);
        }
        sss_cmd_done(cctx, cmdctx);
    }
}

/* for now, if we are online, try to always query the backend */
static int nss_cmd_initgroups(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    const char *rawname;
    char *domname;
    uint8_t *body;
    size_t blen;
    int ret;
    int ncret;
    bool neghit = false;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmdctx = cmdctx;

    /* get user name to query */
    sss_packet_get_body(cctx->creq->in, &body, &blen);

    /* if not terminated fail */
    if (body[blen -1] != '\0') {
        ret = EINVAL;
        goto done;
    }
    rawname = (const char *)body;

    domname = NULL;
    ret = sss_parse_name(cmdctx, cctx->rctx->names, rawname,
                         &domname, &cmdctx->name);
    if (ret != EOK) {
        DEBUG(2, ("Invalid name received [%s]\n", rawname));
        ret = ENOENT;
        goto done;
    }

    DEBUG(4, ("Requesting info for [%s] from [%s]\n",
              cmdctx->name, domname  ? : "<ALL>"));

    if (domname) {
        dctx->domain = nss_get_dom(cctx->rctx->domains, domname);
        if (!dctx->domain) {
            ret = ENOENT;
            goto done;
        }

        /* verify this user has not yet been negatively cached,
         * or has been permanently filtered */
        ncret = nss_ncache_check_user(nctx->ncache, nctx->neg_timeout,
                                    domname, cmdctx->name);
        if (ncret == EEXIST) {
            neghit = true;
        }
    }
    else {
        /* skip domains that require FQnames or have negative caches */
        for (dom = cctx->rctx->domains; dom; dom = dom->next) {

            if (dom->fqnames) continue;

            /* verify this user has not yet been negatively cached,
            * or has been permanently filtered */
            ncret = nss_ncache_check_user(nctx->ncache, nctx->neg_timeout,
                                          dom->name, cmdctx->name);
            if (ncret == ENOENT) break;

            neghit = true;
        }
        /* reset neghit if we still have a domain to check */
        if (dom) neghit = false;

        dctx->domain = dom;
    }
    if (neghit) {
        DEBUG(2, ("User [%s] does not exist! (negative cache)\n", rawname));
        ret = ENOENT;
        goto done;
    }
    if (dctx->domain == NULL) {
        DEBUG(2, ("No matching domain found for [%s], fail!\n", rawname));
        ret = ENOENT;
        goto done;
    }

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    if (!domname) {
        /* this is a multidomain search */
        cmdctx->check_next = true;
    }

    DEBUG(4, ("Requesting info for [%s@%s]\n",
              cmdctx->name, dctx->domain->name));

    ret = sysdb_get_ctx_from_list(cctx->rctx->db_list,
                                  dctx->domain, &sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
        ret = EFAULT;
        goto done;
    }
    ret = sysdb_initgroups(cmdctx, sysdb,
                           dctx->domain, cmdctx->name,
                           nss_cmd_getinitgr_callback, dctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to make request to our cache!\n"));
    }

done:
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* we do not have any entry to return */
            ret = sss_packet_new(cctx->creq, 2*sizeof(uint32_t),
                                 sss_packet_get_cmd(cctx->creq->in),
                                 &cctx->creq->out);
            if (ret == EOK) {
                sss_packet_get_body(cctx->creq->out, &body, &blen);
                ((uint32_t *)body)[0] = 0; /* 0 results */
                ((uint32_t *)body)[1] = 0; /* reserved */
            }
        }
        if (ret != EOK) {
            ret = nss_cmd_send_error(cmdctx, ret);
        }
        if (ret == EOK) {
            sss_cmd_done(cctx, cmdctx);
        }
        return ret;
    }

    return EOK;
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version nss_cli_protocol_version[] = {
        {1, "2008-09-05", "initial version, \\0 terminated strings"},
        {0, NULL, NULL}
    };

    return nss_cli_protocol_version;
}

static struct sss_cmd_table nss_cmds[] = {
    {SSS_GET_VERSION, sss_cmd_get_version},
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

struct sss_cmd_table *get_nss_cmds(void) {
    return nss_cmds;
}

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

