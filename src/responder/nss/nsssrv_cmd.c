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
#include "util/sss_nss.h"
#include "responder/nss/nsssrv.h"
#include "responder/nss/nsssrv_private.h"
#include "responder/nss/nsssrv_netgroup.h"
#include "responder/nss/nsssrv_services.h"
#include "responder/nss/nsssrv_mmap_cache.h"
#include "responder/common/negcache.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include <time.h>

static int nss_cmd_send_error(struct nss_cmd_ctx *cmdctx, int err)
{
    return sss_cmd_send_error(cmdctx->cctx, err);
}

static int nss_cmd_send_empty(struct nss_cmd_ctx *cmdctx)
{
    struct cli_ctx *cctx = cmdctx->cctx;
    return sss_cmd_send_empty(cctx, cmdctx);
}

int nss_cmd_done(struct nss_cmd_ctx *cmdctx, int ret)
{
    switch (ret) {
    case EOK:
        /* all fine, just return here */
        break;

    case ENOENT:
        ret = nss_cmd_send_empty(cmdctx);
        if (ret) {
            return EFAULT;
        }
        break;

    case EAGAIN:
        /* async processing, just return here */
        break;

    case EFAULT:
        /* very bad error */
        return EFAULT;

    default:
        ret = nss_cmd_send_error(cmdctx, ret);
        if (ret) {
            return EFAULT;
        }
        sss_cmd_done(cmdctx->cctx, cmdctx);
        break;
    }

    return EOK;
}

/***************************
 *  Enumeration procedures *
 ***************************/
errno_t nss_setent_add_ref(TALLOC_CTX *memctx,
                           struct getent_ctx *getent_ctx,
                           struct tevent_req *req)
{
    return setent_add_ref(memctx, getent_ctx, &getent_ctx->reqs, req);
}

void nss_setent_notify_error(struct getent_ctx *getent_ctx, errno_t ret)
{
    return setent_notify(&getent_ctx->reqs, ret);
}

void nss_setent_notify_done(struct getent_ctx *getent_ctx)
{
    return setent_notify_done(&getent_ctx->reqs);
}

struct setent_ctx {
    struct cli_ctx *client;
    struct nss_ctx *nctx;
    struct nss_dom_ctx *dctx;
    struct getent_ctx *getent_ctx;
};

/****************************************************************************
 * PASSWD db related functions
 ***************************************************************************/

static gid_t get_gid_override(struct ldb_message *msg,
                              struct sss_domain_info *dom)
{
    return dom->override_gid ?
        dom->override_gid :
        ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);
}

static const char *get_homedir_override(TALLOC_CTX *mem_ctx,
                                        struct ldb_message *msg,
                                        struct nss_ctx *nctx,
                                        struct sss_domain_info *dom,
                                        const char *name,
                                        uint32_t uid)
{
    const char *homedir;

    /* Check whether we are unconditionally overriding the server
     * for home directory locations.
     */
    if (dom->override_homedir) {
        return expand_homedir_template(mem_ctx, dom->override_homedir,
                                       name, uid, dom->name);
    } else if (nctx->override_homedir) {
        return expand_homedir_template(mem_ctx, nctx->override_homedir,
                                       name, uid, dom->name);
    }

    homedir = ldb_msg_find_attr_as_string(msg, SYSDB_HOMEDIR, NULL);
    if (!homedir || *homedir == '\0') {
        /* In the case of a NULL or empty homedir, check to see if
         * we have a fallback homedir to use.
         */
        if (dom->fallback_homedir) {
            return expand_homedir_template(mem_ctx, dom->fallback_homedir,
                                           name, uid, dom->name);
        } else if (nctx->fallback_homedir) {
            return expand_homedir_template(mem_ctx, nctx->fallback_homedir,
                                           name, uid, dom->name);
        }
    }

    /* Return the value we got from the provider */
    return talloc_strdup(mem_ctx, homedir);
}

static const char *get_shell_override(TALLOC_CTX *mem_ctx,
                                      struct ldb_message *msg,
                                      struct nss_ctx *nctx,
                                      struct sss_domain_info *dom)
{
    const char *user_shell;
    int i;

    /* Check whether we are unconditionally overriding the server
     * for the login shell.
     */
    if (dom->override_shell) {
        return dom->override_shell;
    } else if (nctx->override_shell) {
        return nctx->override_shell;
    }

    user_shell = ldb_msg_find_attr_as_string(msg, SYSDB_SHELL, NULL);
    if (!user_shell) {
        /* Check whether there is a default shell specified */
        if (nctx->default_shell) {
            return talloc_strdup(mem_ctx, nctx->default_shell);
        }
        return NULL;
    }
    if (!nctx->allowed_shells && !nctx->vetoed_shells) return talloc_strdup(mem_ctx, user_shell);

    if (nctx->vetoed_shells) {
        for (i=0; nctx->vetoed_shells[i]; i++) {
            if (strcmp(nctx->vetoed_shells[i], user_shell) == 0) {
                DEBUG(5, ("The shell '%s' is vetoed. "
                         "Using fallback\n", user_shell));
                return talloc_strdup(mem_ctx, nctx->shell_fallback);
            }
        }
    }

    if (nctx->etc_shells) {
        for (i=0; nctx->etc_shells[i]; i++) {
            if (strcmp(user_shell, nctx->etc_shells[i]) == 0) {
                DEBUG(9, ("Shell %s found in /etc/shells\n",
                        nctx->etc_shells[i]));
                break;
            }
        }

        if (nctx->etc_shells[i]) {
            DEBUG(9, ("Using original shell '%s'\n", user_shell));
            return talloc_strdup(mem_ctx, user_shell);
        }
    }

    if (nctx->allowed_shells) {
        for (i=0; nctx->allowed_shells[i]; i++) {
            if (strcmp(nctx->allowed_shells[i], user_shell) == 0) {
                DEBUG(5, ("The shell '%s' is allowed but does not exist. "
                        "Using fallback\n", user_shell));
                return talloc_strdup(mem_ctx, nctx->shell_fallback);
            }
        }
    }

    DEBUG(5, ("The shell '%s' is not allowed and does not exist.\n",
              user_shell));
    return talloc_strdup(mem_ctx, NOLOGIN_SHELL);
}

static int fill_pwent(struct sss_packet *packet,
                      struct sss_domain_info *dom,
                      struct nss_ctx *nctx,
                      bool filter_users, bool pw_mmap_cache,
                      struct ldb_message **msgs,
                      int *count)
{
    struct ldb_message *msg;
    uint8_t *body;
    const char *tmpstr;
    const char *orig_name;
    struct sized_string name;
    struct sized_string gecos;
    struct sized_string homedir;
    struct sized_string shell;
    struct sized_string pwfield;
    struct sized_string fullname;
    uint32_t uid;
    uint32_t gid;
    size_t rsize, rp, blen;
    size_t dom_len = 0;
    int delim = 1;
    int i, ret, num, t;
    bool add_domain = dom->fqnames;
    const char *domain = dom->name;
    const char *namefmt;
    bool packet_initialized = false;
    int ncret;
    TALLOC_CTX *tmp_ctx = NULL;

    namefmt = dom->names->fq_fmt;

    if (add_domain) dom_len = strlen(domain);

    to_sized_string(&pwfield, nctx->pwfield);

    rp = 2*sizeof(uint32_t);

    num = 0;
    for (i = 0; i < *count; i++) {
        talloc_zfree(tmp_ctx);
        tmp_ctx = talloc_new(NULL);

        msg = msgs[i];

        orig_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        uid = ldb_msg_find_attr_as_uint64(msg, SYSDB_UIDNUM, 0);
        gid = get_gid_override(msg, dom);

        if (!orig_name || !uid || !gid) {
            DEBUG(SSSDBG_OP_FAILURE, ("Incomplete user object for %s[%llu]! Skipping\n",
                      orig_name?orig_name:"<NULL>", (unsigned long long int)uid));
            continue;
        }

        if (filter_users) {
            ncret = sss_ncache_check_user(nctx->ncache,
                                        nctx->neg_timeout,
                                        dom, orig_name);
            if (ncret == EEXIST) {
                DEBUG(4, ("User [%s@%s] filtered out! (negative cache)\n",
                          orig_name, domain));
                continue;
            }
        }

        if (!packet_initialized) {
            /* first 2 fields (len and reserved), filled up later */
            ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
            if (ret != EOK) return ret;
            packet_initialized = true;
        }

        tmpstr = sss_get_cased_name(tmp_ctx, orig_name, dom->case_sensitive);
        if (tmpstr == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("sss_get_cased_name failed, skipping\n"));
            continue;
        }
        to_sized_string(&name, tmpstr);

        tmpstr = ldb_msg_find_attr_as_string(msg, SYSDB_GECOS, NULL);
        if (!tmpstr) {
            to_sized_string(&gecos, "");
        } else {
            to_sized_string(&gecos, tmpstr);
        }
        tmpstr = get_homedir_override(tmp_ctx, msg, nctx, dom, name.str, uid);
        if (!tmpstr) {
            to_sized_string(&homedir, "/");
        } else {
            to_sized_string(&homedir, tmpstr);
        }
        tmpstr = get_shell_override(tmp_ctx, msg, nctx, dom);
        if (!tmpstr) {
            to_sized_string(&shell, "");
        } else {
            to_sized_string(&shell, tmpstr);
        }

        rsize = 2 * sizeof(uint32_t) + name.len + gecos.len +
                                       homedir.len + shell.len + pwfield.len;
        if (add_domain) rsize += delim + dom_len;

        ret = sss_packet_grow(packet, rsize);
        if (ret != EOK) {
            num = 0;
            goto done;
        }
        sss_packet_get_body(packet, &body, &blen);

        SAFEALIGN_SET_UINT32(&body[rp], uid, &rp);
        SAFEALIGN_SET_UINT32(&body[rp], gid, &rp);

        if (add_domain) {
            ret = snprintf((char *)&body[rp],
                            name.len + delim + dom_len,
                            namefmt, name.str, domain);
            if (ret >= (name.len + delim + dom_len)) {
                /* need more space, got creative with the print format ? */
                t = ret - (name.len + delim + dom_len) + 1;
                ret = sss_packet_grow(packet, t);
                if (ret != EOK) {
                    num = 0;
                    goto done;
                }
                delim += t;
                sss_packet_get_body(packet, &body, &blen);

                /* retry */
                ret = snprintf((char *)&body[rp],
                            name.len + delim + dom_len,
                            namefmt, name.str, domain);
            }

            if (ret != name.len + delim + dom_len - 1) {
                DEBUG(1, ("Failed to generate a fully qualified name for user "
                          "[%s] in [%s]! Skipping user.\n", name.str, domain));
                continue;
            }
        } else {
            memcpy(&body[rp], name.str, name.len);
        }
        to_sized_string(&fullname, (const char *)&body[rp]);
        rp += fullname.len;

        memcpy(&body[rp], pwfield.str, pwfield.len);
        rp += pwfield.len;
        memcpy(&body[rp], gecos.str, gecos.len);
        rp += gecos.len;
        memcpy(&body[rp], homedir.str, homedir.len);
        rp += homedir.len;
        memcpy(&body[rp], shell.str, shell.len);
        rp += shell.len;

        num++;

        if (pw_mmap_cache && nctx->pwd_mc_ctx) {
            ret = sss_mmap_cache_pw_store(nctx->pwd_mc_ctx,
                                          &fullname, &pwfield,
                                          uid, gid,
                                          &gecos, &homedir, &shell);
            if (ret != EOK && ret != ENOMEM) {
                DEBUG(1, ("Failed to store user %s(%s) in mmap cache!",
                          name.str, domain));
            }
        }
    }
    talloc_zfree(tmp_ctx);

done:
    *count = i;

    /* if there are no results just return ENOENT,
     * let the caller decide if this is the last packet or not */
    if (!packet_initialized) return ENOENT;

    sss_packet_get_body(packet, &body, &blen);
    ((uint32_t *)body)[0] = num; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

    return EOK;
}

static int nss_cmd_getpw_send_reply(struct nss_dom_ctx *dctx, bool filter)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct nss_ctx *nctx;
    int ret;
    int i;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return EFAULT;
    }
    i = dctx->res->count;

    ret = fill_pwent(cctx->creq->out,
                     dctx->domain,
                     nctx, filter, true,
                     dctx->res->msgs, &i);
    if (ret) {
        return ret;
    }
    sss_packet_set_error(cctx->creq->out, EOK);
    sss_cmd_done(cctx, cmdctx);
    return EOK;
}

static void nsssrv_dp_send_acct_req_done(struct tevent_req *req);

/* FIXME: do not check res->count, but get in a msgs and check in parent */
/* FIXME: do not sss_cmd_done, but return error and let parent do it */
errno_t check_cache(struct nss_dom_ctx *dctx,
                    struct nss_ctx *nctx,
                    struct ldb_result *res,
                    int req_type,
                    const char *opt_name,
                    uint32_t opt_id,
                    sss_dp_callback_t callback,
                    void *pvt)
{
    errno_t ret;
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct tevent_req *req = NULL;
    struct dp_callback_ctx *cb_ctx = NULL;
    uint64_t cacheExpire = 0;

    /* when searching for a user or netgroup, more than one reply is a
     * db error
     */
    if ((req_type == SSS_DP_USER || req_type == SSS_DP_NETGR) &&
            (res->count > 1)) {
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
        if (req_type == SSS_DP_INITGROUPS) {
            cacheExpire = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                      SYSDB_INITGR_EXPIRE, 1);
        }
        if (cacheExpire == 0) {
            cacheExpire = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                      SYSDB_CACHE_EXPIRE, 0);
        }

        /* if we have any reply let's check cache validity */
        ret = sss_cmd_check_cache(res->msgs[0], nctx->cache_refresh_percent,
                                  cacheExpire);
        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_FUNC, ("Cached entry is valid, returning..\n"));
            return EOK;
        } else if (ret != EAGAIN && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Error checking cache: %d\n", ret));
            goto error;
        }
    } else {
        /* No replies */
        ret = ENOENT;
    }

    /* EAGAIN (off band) or ENOENT (cache miss) -> check cache */
    if (ret == EAGAIN) {
        /* No callback required
         * This was an out-of-band update. We'll return EOK
         * so the calling function can return the cached entry
         * immediately.
         */
        DEBUG(SSSDBG_TRACE_FUNC,
             ("Performing midpoint cache update on [%s]\n", opt_name));

        req = sss_dp_get_account_send(cctx, cctx->rctx, dctx->domain, true,
                                      req_type, opt_name, opt_id, NULL);
        if (!req) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Out of memory sending out-of-band data provider "
                   "request\n"));
            /* This is non-fatal, so we'll continue here */
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, ("Updating cache out-of-band\n"));
        }

        /* We don't need to listen for a reply, so we will free the
         * request here.
         */
        talloc_zfree(req);

    } else {
       /* This is a cache miss. Or the cache is expired.
        * We need to get the updated user information before returning it.
        */

        /* dont loop forever :-) */
        dctx->check_provider = false;

        /* keep around current data in case backend is offline */
        if (res->count) {
            dctx->res = talloc_steal(dctx, res);
        }

        req = sss_dp_get_account_send(cctx, cctx->rctx, dctx->domain, true,
                                      req_type, opt_name, opt_id, NULL);
        if (!req) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Out of memory sending data provider request\n"));
            ret = ENOMEM;
            goto error;
        }

        cb_ctx = talloc_zero(dctx, struct dp_callback_ctx);
        if(!cb_ctx) {
            talloc_zfree(req);
            ret = ENOMEM;
            goto error;
        }
        cb_ctx->callback = callback;
        cb_ctx->ptr = pvt;
        cb_ctx->cctx = dctx->cmdctx->cctx;
        cb_ctx->mem_ctx = dctx;

        tevent_req_set_callback(req, nsssrv_dp_send_acct_req_done, cb_ctx);

        return EAGAIN;
    }

    return EOK;

error:
    ret = nss_cmd_send_error(cmdctx, ret);
    if (ret != EOK) {
        NSS_CMD_FATAL_ERROR_CODE(cctx, ret);
    }
    sss_cmd_done(cctx, cmdctx);
    return EOK;
}

static void nsssrv_dp_send_acct_req_done(struct tevent_req *req)
{
    struct dp_callback_ctx *cb_ctx =
            tevent_req_callback_data(req, struct dp_callback_ctx);

    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;

    ret = sss_dp_get_account_recv(cb_ctx->mem_ctx, req,
                                  &err_maj, &err_min,
                                  &err_msg);
    talloc_zfree(req);
    if (ret != EOK) {
        NSS_CMD_FATAL_ERROR(cb_ctx->cctx);
    }

    cb_ctx->callback(err_maj, err_min, err_msg, cb_ctx->ptr);
}

static void nss_cmd_getpwnam_dp_callback(uint16_t err_maj, uint32_t err_min,
                                         const char *err_msg, void *ptr);

/* search for a user.
 * Returns:
 *   ENOENT, if user is definitely not found
 *   EAGAIN, if user is beeing fetched from backend via async operations
 *   EOK, if found
 *   anything else on a fatal error
 */

static int nss_cmd_getpwnam_search(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct sss_domain_info *dom = dctx->domain;
    struct cli_ctx *cctx = cmdctx->cctx;
    char *name = NULL;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    int ret;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    while (dom) {
       /* if it is a domainless search, skip domains that require fully
         * qualified names instead */
        while (dom && cmdctx->check_next && dom->fqnames) {
            dom = dom->next;
        }

        if (!dom) break;

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        talloc_free(name);
        name = sss_get_cased_name(dctx, cmdctx->name, dom->case_sensitive);
        if (!name) return ENOMEM;

        /* verify this user has not yet been negatively cached,
        * or has been permanently filtered */
        ret = sss_ncache_check_user(nctx->ncache, nctx->neg_timeout,
                                    dom, name);

        /* if neg cached, return we didn't find it */
        if (ret == EEXIST) {
            DEBUG(2, ("User [%s] does not exist in [%s]! (negative cache)\n",
                      name, dom->name));
            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = dom->next;
                continue;
            }
            /* There are no further domains or this was a
             * fully-qualified user request.
             */
            return ENOENT;
        }

        DEBUG(4, ("Requesting info for [%s@%s]\n", name, dom->name));

        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
            return EIO;
        }

        ret = sysdb_getpwnam(cmdctx, sysdb, name, &dctx->res);
        if (ret != EOK) {
            DEBUG(1, ("Failed to make request to our cache!\n"));
            return EIO;
        }

        if (dctx->res->count > 1) {
            DEBUG(0, ("getpwnam call returned more than one result !?!\n"));
            return ENOENT;
        }

        if (dctx->res->count == 0 && !dctx->check_provider) {
            /* set negative cache only if not result of cache check */
            ret = sss_ncache_set_user(nctx->ncache, false, dom, name);
            if (ret != EOK) {
                return ret;
            }

            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = dom->next;
                if (dom) continue;
            }

            DEBUG(2, ("No results for getpwnam call\n"));

            return ENOENT;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (dctx->check_provider) {
            ret = check_cache(dctx, nctx, dctx->res,
                              SSS_DP_USER, name, 0,
                              nss_cmd_getpwnam_dp_callback,
                              dctx);
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                return ret;
            }
        }

        /* One result found */
        DEBUG(6, ("Returning info for user [%s@%s]\n", name, dom->name));

        return EOK;
    }

    DEBUG(SSSDBG_MINOR_FAILURE,
          ("No matching domain found for [%s], fail!\n", cmdctx->name));
    return ENOENT;
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

        if (dctx->res && dctx->res->count == 1) {
            ret = nss_cmd_getpw_send_reply(dctx, false);
            goto done;
        }

        /* no previous results, just loop to next domain if possible */
        if (dctx->domain->next && cmdctx->check_next) {
            dctx->domain = dctx->domain->next;
            dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
        } else {
            /* nothing available */
            ret = ENOENT;
            goto done;
        }
    }

    /* ok the backend returned, search to see if we have updated results */
    ret = nss_cmd_getpwnam_search(dctx);
    if (ret == EOK) {
        /* we have results to return */
        ret = nss_cmd_getpw_send_reply(dctx, false);
    }

done:
    ret = nss_cmd_done(cmdctx, ret);
    if (ret) {
        NSS_CMD_FATAL_ERROR(cctx);
    }
}

static void nss_cmd_getpwnam_cb(struct tevent_req *req);
static int nss_cmd_getpwnam(struct cli_ctx *cctx)
{
    struct tevent_req *req;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    const char *rawname;
    char *domname;
    uint8_t *body;
    size_t blen;
    int ret;

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

    /* If the body isn't valid UTF-8, fail */
    if (!sss_utf8_check(body, blen -1)) {
        ret = EINVAL;
        goto done;
    }

    rawname = (const char *)body;

    domname = NULL;
    ret = sss_parse_name_for_domains(cmdctx, cctx->rctx->domains, rawname,
                                     &domname, &cmdctx->name);
    if (ret == EAGAIN) {
        req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, true, domname);
        if (req == NULL) {
            ret = ENOMEM;
        } else {
            dctx->rawname = rawname;
            tevent_req_set_callback(req, nss_cmd_getpwnam_cb, dctx);
            ret = EAGAIN;
        }
        goto done;
    } if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Invalid name received [%s]\n", rawname));
        ret = ENOENT;
        goto done;
    }

    DEBUG(4, ("Requesting info for [%s] from [%s]\n",
              cmdctx->name, domname?domname:"<ALL>"));

    if (domname) {
        dctx->domain = responder_get_domain(dctx, cctx->rctx, domname);
        if (!dctx->domain) {
            ret = ENOENT;
            goto done;
        }
    } else {
        /* this is a multidomain search */
        dctx->rawname = rawname;
        dctx->domain = cctx->rctx->domains;
        cmdctx->check_next = true;
        if (cctx->rctx->get_domains_last_call.tv_sec == 0) {
            req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, false, NULL);
            if (req == NULL) {
                ret = ENOMEM;
            } else {
                tevent_req_set_callback(req, nss_cmd_getpwnam_cb, dctx);
                ret = EAGAIN;
            }
            goto done;
        }
    }

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    /* ok, find it ! */
    ret = nss_cmd_getpwnam_search(dctx);
    if (ret == EOK) {
        /* we have results to return */
        ret = nss_cmd_getpw_send_reply(dctx, false);
    }

done:
    return nss_cmd_done(cmdctx, ret);
}

static void nss_cmd_getpwnam_cb(struct tevent_req *req)
{
    struct nss_dom_ctx *dctx = tevent_req_callback_data(req, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    char *domname = NULL;
    const char *rawname = dctx->rawname;
    errno_t ret;

    ret = sss_dp_get_domains_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        goto done;
    }

    ret = sss_parse_name_for_domains(cmdctx, cctx->rctx->domains, rawname,
                                     &domname, &cmdctx->name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Invalid name received [%s]\n", rawname));
        ret = ENOENT;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Requesting info for [%s] from [%s]\n",
              cmdctx->name, domname?domname:"<ALL>"));

    if (domname) {
        dctx->domain = responder_get_domain(dctx, cctx->rctx, domname);
        if (dctx->domain == NULL) {
            ret = ENOENT;
            goto done;
        }
    } else {
        /* this is a multidomain search */
        dctx->domain = cctx->rctx->domains;
        cmdctx->check_next = true;
    }

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    /* ok, find it ! */
    ret = nss_cmd_getpwnam_search(dctx);
    if (ret == EOK) {
        /* we have results to return */
        ret = nss_cmd_getpw_send_reply(dctx, false);
    }

done:
    nss_cmd_done(cmdctx, ret);
}

static void nss_cmd_getpwuid_dp_callback(uint16_t err_maj, uint32_t err_min,
                                        const char *err_msg, void *ptr);

/* search for a uid.
 * Returns:
 *   ENOENT, if uid is definitely not found
 *   EAGAIN, if uid is beeing fetched from backend via async operations
 *   EOK, if found
 *   anything else on a fatal error
 */

struct sss_domain_info *get_next_dom_or_subdom(struct sss_domain_info *dom)
{
    /* Note that we don't know if the dom is a domain or a subdomain,
     * therefore:
     *
     * If it is a subdomain and it doesn't have any siblings (subdomains
     * of the same primary domain), return next primary domain
     */
    if (dom->next == NULL && dom->parent != NULL) {
        return dom->parent->next;
    }

    /* If it's primary domain, the next returned should be its first
     * subdomain */
    if (dom->subdomains != NULL) {
        return dom->subdomains[0];
    }

    /* Any other scenario */
    return dom->next;
}

static int nss_cmd_getpwuid_search(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct sss_domain_info *dom = dctx->domain;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    int ret;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    while (dom) {

        /* check that the uid is valid for this domain */
        if ((dom->id_min && (cmdctx->id < dom->id_min)) ||
            (dom->id_max && (cmdctx->id > dom->id_max))) {
            DEBUG(4, ("Uid [%lu] does not exist in domain [%s]! "
                      "(id out of range)\n",
                      (unsigned long)cmdctx->id, dom->name));
            if (cmdctx->check_next) {
                dom = get_next_dom_or_subdom(dom);
                continue;
            }
            return ENOENT;
        }

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        DEBUG(4, ("Requesting info for [%d@%s]\n", cmdctx->id, dom->name));

        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
            return EIO;
        }

        ret = sysdb_getpwuid(cmdctx, sysdb, cmdctx->id, &dctx->res);
        if (ret != EOK) {
            DEBUG(1, ("Failed to make request to our cache!\n"));
            return EIO;
        }

        if (dctx->res->count > 1) {
            DEBUG(0, ("getpwuid call returned more than one result !?!\n"));
            return ENOENT;
        }

        if (dctx->res->count == 0 && !dctx->check_provider) {
            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = get_next_dom_or_subdom(dom);
                continue;
            }

            DEBUG(2, ("No results for getpwuid call\n"));

            /* set negative cache only if not result of cache check */
            ret = sss_ncache_set_uid(nctx->ncache, false, cmdctx->id);
            if (ret != EOK) {
                return ret;
            }

            return ENOENT;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (dctx->check_provider) {
            ret = check_cache(dctx, nctx, dctx->res,
                              SSS_DP_USER, NULL, cmdctx->id,
                              nss_cmd_getpwuid_dp_callback,
                              dctx);
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                return ret;
            }
        }

        /* One result found */
        DEBUG(6, ("Returning info for uid [%d@%s]\n", cmdctx->id, dom->name));

        return EOK;
    }

    DEBUG(2, ("No matching domain found for [%d], fail!\n", cmdctx->id));
    return ENOENT;
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

        if (dctx->res && dctx->res->count == 1) {
            ret = nss_cmd_getpw_send_reply(dctx, true);
            goto done;
        }

        /* no previous results, just loop to next domain if possible */
        if (dctx->domain->next && cmdctx->check_next) {
            dctx->domain = dctx->domain->next;
            dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
        } else {
            /* nothing available */
            ret = ENOENT;
            goto done;
        }
    }

    /* ok the backend returned, search to see if we have updated results */
    ret = nss_cmd_getpwuid_search(dctx);
    if (ret == EOK) {
        /* we have results to return */
        ret = nss_cmd_getpw_send_reply(dctx, true);
    }

done:
    ret = nss_cmd_done(cmdctx, ret);
    if (ret) {
        NSS_CMD_FATAL_ERROR(cctx);
    }
}

static int nss_cmd_getpwuid(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct nss_ctx *nctx;
    uint8_t *body;
    size_t blen;
    int ret;

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

    ret = sss_ncache_check_uid(nctx->ncache, nctx->neg_timeout, cmdctx->id);
    if (ret == EEXIST) {
        DEBUG(3, ("Uid [%lu] does not exist! (negative cache)\n",
                  (unsigned long)cmdctx->id));
        ret = ENOENT;
        goto done;
    }

    /* uid searches are always multidomain */
    dctx->domain = cctx->rctx->domains;
    cmdctx->check_next = true;

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    /* ok, find it ! */
    ret = nss_cmd_getpwuid_search(dctx);
    if (ret == EOK) {
        /* we have results to return */
        ret = nss_cmd_getpw_send_reply(dctx, true);
    }

done:
    return nss_cmd_done(cmdctx, ret);
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
 *
 * Alternatively:
 * - use a smarter search mechanism that keeps track of the
 *   last user searched and return the next X users doing
 *   an alphabetic sort and starting from the user following
 *   the last returned user.
 */
static int nss_cmd_getpwent_immediate(struct nss_cmd_ctx *cmdctx);
struct tevent_req * nss_cmd_setpwent_send(TALLOC_CTX *mem_ctx,
                                          struct cli_ctx *client);
static void nss_cmd_setpwent_done(struct tevent_req *req);
static int nss_cmd_setpwent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct tevent_req *req;
    errno_t ret = EOK;

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    req = nss_cmd_setpwent_send(cmdctx, cctx);
    if (!req) {
        DEBUG(0, ("Fatal error calling nss_cmd_setpwent_send\n"));
        ret = EIO;
        goto done;
    }
    tevent_req_set_callback(req, nss_cmd_setpwent_done, cmdctx);

done:
    return nss_cmd_done(cmdctx, ret);
}

static errno_t nss_cmd_setpwent_step(struct setent_step_ctx *step_ctx);
struct tevent_req *nss_cmd_setpwent_send(TALLOC_CTX *mem_ctx,
                                         struct cli_ctx *client)
{
    errno_t ret;
    struct nss_ctx *nctx;
    struct tevent_req *req;
    struct setent_ctx *state;
    struct sss_domain_info *dom;
    struct setent_step_ctx *step_ctx;

    DEBUG(4, ("Received setpwent request\n"));
    nctx = talloc_get_type(client->rctx->pvt_ctx, struct nss_ctx);

    /* Reset the read pointers */
    client->pwent_dom_idx = 0;
    client->pwent_cur = 0;

    req = tevent_req_create(mem_ctx, &state, struct setent_ctx);
    if (!req) {
        DEBUG(0, ("Could not create tevent request for setpwent\n"));
        return NULL;
    }

    state->nctx = nctx;
    state->client = client;

    state->dctx = talloc_zero(state, struct nss_dom_ctx);
    if (!state->dctx) {
        ret = ENOMEM;
        goto error;
    }

    /* check if enumeration is enabled in any domain */
    for (dom = client->rctx->domains; dom; dom = dom->next) {
        if (dom->enumerate != 0) break;
    }
    state->dctx->domain = dom;

    if (state->dctx->domain == NULL) {
        DEBUG(2, ("Enumeration disabled on all domains!\n"));
        ret = ENOENT;
        goto error;
    }

    state->dctx->check_provider =
            NEED_CHECK_PROVIDER(state->dctx->domain->provider);

    /* Is the result context already available */
    if (state->nctx->pctx) {
        if (state->nctx->pctx->ready) {
            /* All of the necessary data is in place
             * We can return now, getpwent requests will work at this point
             */
            tevent_req_done(req);
            tevent_req_post(req, state->nctx->rctx->ev);
        }
        else {
            /* Object is still being constructed
             * Register for notification when it's
             * ready.
             */
            ret = nss_setent_add_ref(state, state->nctx->pctx, req);
            if (ret != EOK) {
                talloc_free(req);
                return NULL;
            }
        }
        return req;
    }

    /* Create a new result context
     * We are creating it on the nss_ctx so that it doesn't
     * go away if the original request does. We will delete
     * it when the refcount goes to zero;
     */
    state->nctx->pctx = talloc_zero(nctx, struct getent_ctx);
    if (!state->nctx->pctx) {
        ret = ENOMEM;
        goto error;
    }
    state->getent_ctx = nctx->pctx;

    /* Add a callback reference for ourselves */
    ret = nss_setent_add_ref(state, state->nctx->pctx, req);
    if (ret) goto error;

    /* ok, start the searches */
    step_ctx = talloc_zero(state->getent_ctx, struct setent_step_ctx);
    if (!step_ctx) {
        ret = ENOMEM;
        goto error;
    }

    /* Steal the dom_ctx onto the step_ctx so it doesn't go out of scope if
     * this request is canceled while other requests are in-progress.
     */
    step_ctx->dctx = talloc_steal(step_ctx, state->dctx);
    step_ctx->nctx = state->nctx;
    step_ctx->getent_ctx = state->getent_ctx;
    step_ctx->rctx = client->rctx;
    step_ctx->cctx = client;
    step_ctx->returned_to_mainloop = false;

    ret = nss_cmd_setpwent_step(step_ctx);
    if (ret != EOK && ret != EAGAIN) goto error;

    if (ret == EOK) {
        tevent_req_post(req, client->rctx->ev);
    }

    return req;

 error:
     tevent_req_error(req, ret);
     tevent_req_post(req, client->rctx->ev);
     return req;
}

static void nss_cmd_setpwent_dp_callback(uint16_t err_maj, uint32_t err_min,
                                         const char *err_msg, void *ptr);
static void setpwent_result_timeout(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval current_time,
                                    void *pvt);

/* nss_cmd_setpwent_step returns
 *   EOK if everything is done and the request needs to be posted explicitly
 *   EAGAIN if the caller can safely return to the main loop
 */
static errno_t nss_cmd_setpwent_step(struct setent_step_ctx *step_ctx)
{
    errno_t ret;
    struct sss_domain_info *dom = step_ctx->dctx->domain;
    struct resp_ctx *rctx = step_ctx->rctx;
    struct nss_dom_ctx *dctx = step_ctx->dctx;
    struct getent_ctx *pctx = step_ctx->getent_ctx;
    struct nss_ctx *nctx = step_ctx->nctx;
    struct sysdb_ctx *sysdb;
    struct ldb_result *res;
    struct timeval tv;
    struct tevent_timer *te;
    struct tevent_req *dpreq;
    struct dp_callback_ctx *cb_ctx;

    while (dom) {
        while (dom && dom->enumerate == 0) {
            dom = dom->next;
        }

        if (!dom) break;

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        DEBUG(6, ("Requesting info for domain [%s]\n", dom->name));

        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
            return EIO;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (dctx->check_provider) {
            step_ctx->returned_to_mainloop = true;
            /* Only do this once per provider */
            dctx->check_provider = false;

            dpreq = sss_dp_get_account_send(step_ctx, rctx, dctx->domain, true,
                                          SSS_DP_USER, NULL, 0, NULL);
            if (!dpreq) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Enum Cache refresh for domain [%s] failed."
                       " Trying to return what we have in cache!\n",
                       dom->name));
            } else {
                cb_ctx = talloc_zero(step_ctx, struct dp_callback_ctx);
                if(!cb_ctx) {
                    talloc_zfree(dpreq);
                    return ENOMEM;
                }

                cb_ctx->callback = nss_cmd_setpwent_dp_callback;
                cb_ctx->ptr = step_ctx;
                cb_ctx->cctx = step_ctx->cctx;
                cb_ctx->mem_ctx = step_ctx;

                tevent_req_set_callback(dpreq, nsssrv_dp_send_acct_req_done, cb_ctx);

                return EAGAIN;
            }
        }

        ret = sysdb_enumpwent(dctx, sysdb, &res);
        if (ret != EOK) {
            DEBUG(1, ("Enum from cache failed, skipping domain [%s]\n",
                      dom->name));
            dom = dom->next;
            continue;
        }

        if (res->count == 0) {
            DEBUG(4, ("Domain [%s] has no users, skipping.\n", dom->name));
            dom = dom->next;
            continue;
        }

        nctx->pctx->doms = talloc_realloc(pctx, pctx->doms,
                                    struct dom_ctx, pctx->num +1);
        if (!pctx->doms) {
            talloc_free(pctx);
            nctx->pctx = NULL;
            return ENOMEM;
        }

        nctx->pctx->doms[pctx->num].domain = dctx->domain;
        nctx->pctx->doms[pctx->num].res = talloc_steal(pctx->doms, res);

        nctx->pctx->num++;

        /* do not reply until all domain searches are done */
        dom = dom->next;
    }

    /* We've finished all our lookups
     * The result object is now safe to read.
     */
    nctx->pctx->ready = true;

    /* Set up a lifetime timer for this result object
     * We don't want this result object to outlive the
     * enum cache refresh timeout
     */
    tv = tevent_timeval_current_ofs(nctx->enum_cache_timeout, 0);
    te = tevent_add_timer(rctx->ev, nctx->pctx, tv,
                          setpwent_result_timeout, nctx);
    if (!te) {
        DEBUG(0, ("Could not set up life timer for setpwent result object. "
                  "Entries may become stale.\n"));
    }

    /* Notify the waiting clients */
    nss_setent_notify_done(nctx->pctx);

    if (step_ctx->returned_to_mainloop) {
        return EAGAIN;
    } else {
        return EOK;
    }
}

static void setpwent_result_timeout(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval current_time,
                                    void *pvt)
{
    struct nss_ctx *nctx = talloc_get_type(pvt, struct nss_ctx);

    DEBUG(1, ("setpwent result object has expired. Cleaning up.\n"));

    /* Free the passwd enumeration context.
     * If additional getpwent requests come in, they will invoke
     * an implicit setpwent and refresh the result object.
     */
    talloc_zfree(nctx->pctx);
}

static void nss_cmd_setpwent_dp_callback(uint16_t err_maj, uint32_t err_min,
                                         const char *err_msg, void *ptr)
{
    struct setent_step_ctx *step_ctx =
            talloc_get_type(ptr, struct setent_step_ctx);
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = nss_cmd_setpwent_step(step_ctx);
    if (ret != EOK && ret != EAGAIN) {
        /* Notify any waiting processes of failure */
        nss_setent_notify_error(step_ctx->nctx->pctx, ret);
    }
}

static errno_t nss_cmd_setpwent_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static void nss_cmd_setpwent_done(struct tevent_req *req)
{
    errno_t ret;
    struct nss_cmd_ctx *cmdctx =
            tevent_req_callback_data(req, struct nss_cmd_ctx);

    ret = nss_cmd_setpwent_recv(req);
    talloc_zfree(req);
    if (ret == EOK || ret == ENOENT) {
        /* Either we succeeded or no domains were eligible */
        ret = sss_packet_new(cmdctx->cctx->creq, 0,
                             sss_packet_get_cmd(cmdctx->cctx->creq->in),
                             &cmdctx->cctx->creq->out);
        if (ret == EOK) {
            sss_cmd_done(cmdctx->cctx, cmdctx);
            return;
        }
    }

    /* Something bad happened */
    nss_cmd_done(cmdctx, ret);
}

static void nss_cmd_implicit_setpwent_done(struct tevent_req *req);
static int nss_cmd_getpwent(struct cli_ctx *cctx)
{
    struct nss_ctx *nctx;
    struct nss_cmd_ctx *cmdctx;
    struct tevent_req *req;

    DEBUG(4, ("Requesting info for all accounts\n"));

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    /* Save the current index and cursor locations
     * If we end up calling setpwent implicitly, because the response object
     * expired and has to be recreated, we want to resume from the same
     * location.
     */
    cmdctx->saved_dom_idx = cctx->pwent_dom_idx;
    cmdctx->saved_cur = cctx->pwent_cur;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    if(!nctx->pctx || !nctx->pctx->ready) {
        /* Make sure we invoke setpwent if it hasn't been run or is still
         * processing from another client
         */
        req = nss_cmd_setpwent_send(cctx, cctx);
        if (!req) {
            return EIO;
        }
        tevent_req_set_callback(req, nss_cmd_implicit_setpwent_done, cmdctx);
        return EOK;
    }

    return nss_cmd_getpwent_immediate(cmdctx);
}

static int nss_cmd_retpwent(struct cli_ctx *cctx, int num);
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

static int nss_cmd_retpwent(struct cli_ctx *cctx, int num)
{
    struct nss_ctx *nctx;
    struct getent_ctx *pctx;
    struct ldb_message **msgs = NULL;
    struct dom_ctx *pdom = NULL;
    int n = 0;
    int ret = ENOENT;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    if (!nctx->pctx) goto none;

    pctx = nctx->pctx;

    while (ret == ENOENT) {
        if (cctx->pwent_dom_idx >= pctx->num) break;

        pdom = &pctx->doms[cctx->pwent_dom_idx];

        n = pdom->res->count - cctx->pwent_cur;
        if (n <= 0 && (cctx->pwent_dom_idx+1 < pctx->num)) {
            cctx->pwent_dom_idx++;
            pdom = &pctx->doms[cctx->pwent_dom_idx];
            n = pdom->res->count;
            cctx->pwent_cur = 0;
        }

        if (!n) break;

        if (n > num) n = num;

        msgs = &(pdom->res->msgs[cctx->pwent_cur]);

        ret = fill_pwent(cctx->creq->out, pdom->domain, nctx,
                         true, false, msgs, &n);

        cctx->pwent_cur += n;
    }

none:
    if (ret == ENOENT) {
        ret = sss_cmd_empty_packet(cctx->creq->out);
    }
    return ret;
}

static void nss_cmd_implicit_setpwent_done(struct tevent_req *req)
{
    errno_t ret;
    struct nss_cmd_ctx *cmdctx =
            tevent_req_callback_data(req, struct nss_cmd_ctx);

    ret = nss_cmd_setpwent_recv(req);
    talloc_zfree(req);

    /* ENOENT is acceptable, as it just means that there were no entries
     * to be returned. This will be handled gracefully in nss_cmd_retpwent
     * later.
     */
    if (ret != EOK && ret != ENOENT) {
        DEBUG(0, ("Implicit setpwent failed with unexpected error [%d][%s]\n",
                  ret, strerror(ret)));
        NSS_CMD_FATAL_ERROR(cmdctx);
    }

    /* Restore the saved index and cursor locations */
    cmdctx->cctx->pwent_dom_idx = cmdctx->saved_dom_idx;
    cmdctx->cctx->pwent_cur = cmdctx->saved_cur;

    ret = nss_cmd_getpwent_immediate(cmdctx);
    if (ret != EOK) {
        DEBUG(0, ("Immediate retrieval failed with unexpected error "
                  "[%d][%s]\n", ret, strerror(ret)));
        NSS_CMD_FATAL_ERROR(cmdctx);
    }
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

    if (ret != EOK) {
        return ret;
    }
    if (nctx->pctx == NULL) goto done;

    /* Reset the indices so that subsequent requests start at zero */
    cctx->pwent_dom_idx = 0;
    cctx->pwent_cur = 0;

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

static int fill_members(struct sss_packet *packet,
                        struct sss_domain_info *dom,
                        struct nss_ctx *nctx,
                        struct ldb_message_element *el,
                        size_t *_rzero,
                        size_t *_rsize,
                        int *_memnum)
{
    int i, ret = EOK;
    int memnum = *_memnum;
    size_t rzero= *_rzero;
    size_t rsize = *_rsize;
    char *tmpstr;
    struct sized_string name;
    const char *namefmt = dom->names->fq_fmt;
    TALLOC_CTX *tmp_ctx = NULL;

    size_t delim;
    size_t dom_len;

    uint8_t *body;
    size_t blen;

    const char *domain = dom->name;
    bool add_domain = dom->fqnames;

    if (add_domain) {
        delim = 1;
        dom_len = strlen(domain);
    } else {
        delim = 0;
        dom_len = 0;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    sss_packet_get_body(packet, &body, &blen);
    for (i = 0; i < el->num_values; i++) {
        tmpstr = sss_get_cased_name(tmp_ctx, (char *)el->values[i].data,
                                    dom->case_sensitive);
        if (tmpstr == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("sss_get_cased_name failed, skipping\n"));
            continue;
        }

        if (nctx->filter_users_in_groups) {
            ret = sss_ncache_check_user(nctx->ncache,
                                        nctx->neg_timeout,
                                        dom, tmpstr);
            if (ret == EEXIST) {
                DEBUG(SSSDBG_TRACE_FUNC, ("Group [%s] member [%s@%s] filtered out!"
                                          " (negative cache)\n",
                                          (char *)&body[rzero+STRS_ROFFSET],
                                          tmpstr, domain));
                continue;
            }
        }

        to_sized_string(&name, tmpstr);

        if (add_domain) {
            ret = sss_packet_grow(packet, name.len + delim + dom_len);
        } else {
            ret = sss_packet_grow(packet, name.len);
        }
        if (ret != EOK) {
            goto done;
        }
        sss_packet_get_body(packet, &body, &blen);

        if (add_domain) {
            ret = snprintf((char *)&body[rzero + rsize],
                           name.len + delim + dom_len,
                           namefmt, name.str, domain);
            if (ret >= (name.len + delim + dom_len)) {
                /* need more space,
                 * got creative with the print format ? */
                int t = ret - name.len + delim + dom_len + 1;
                ret = sss_packet_grow(packet, t);
                if (ret != EOK) {
                    goto done;
                }
                sss_packet_get_body(packet, &body, &blen);
                delim += t;

                /* retry */
                ret = snprintf((char *)&body[rzero + rsize],
                               name.len + delim + dom_len,
                               namefmt, name.str, domain);
            }

            if (ret != name.len + delim + dom_len - 1) {
                DEBUG(SSSDBG_OP_FAILURE, ("Failed to generate a fully qualified name"
                                          " for member [%s@%s] of group [%s]!"
                                          " Skipping\n", name.str, domain,
                                          (char *)&body[rzero+STRS_ROFFSET]));
                /* reclaim space */
                ret = sss_packet_shrink(packet, name.len + delim + dom_len);
                if (ret != EOK) {
                    goto done;
                }
                continue;
            }

        } else {
            memcpy(&body[rzero + rsize], name.str, name.len);
        }

        if (add_domain) {
            rsize += name.len + delim + dom_len;
        } else {
            rsize += name.len;
        }

        memnum++;
    }

done:
    *_memnum = memnum;
    *_rzero = rzero;
    *_rsize = rsize;
    talloc_zfree(tmp_ctx);
    return ret;
}

static int fill_grent(struct sss_packet *packet,
                      struct sss_domain_info *dom,
                      struct nss_ctx *nctx,
                      bool filter_groups, bool gr_mmap_cache,
                      struct ldb_message **msgs,
                      int *count)
{
    struct ldb_message *msg;
    struct ldb_message_element *el;
    uint8_t *body;
    size_t blen;
    uint32_t gid;
    const char *tmpstr;
    const char *orig_name;
    struct sized_string name;
    struct sized_string pwfield;
    struct sized_string fullname;
    size_t delim;
    size_t dom_len;
    int i = 0;
    int ret, num, memnum;
    size_t rzero, rsize;
    bool add_domain = dom->fqnames;
    const char *domain = dom->name;
    const char *namefmt;
    TALLOC_CTX *tmp_ctx = NULL;

    namefmt = dom->names->fq_fmt;

    if (add_domain) {
        delim = 1;
        dom_len = strlen(domain);
    } else {
        delim = 0;
        dom_len = 0;
    }

    to_sized_string(&pwfield, nctx->pwfield);

    num = 0;

    /* first 2 fields (len and reserved), filled up later */
    ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
    if (ret != EOK) {
        goto done;
    }
    sss_packet_get_body(packet, &body, &blen);
    rzero = 2*sizeof(uint32_t);
    rsize = 0;

    for (i = 0; i < *count; i++) {
        talloc_zfree(tmp_ctx);
        tmp_ctx = talloc_new(NULL);
        msg = msgs[i];

        /* new group */
        if (!ldb_msg_check_string_attribute(msg, "objectClass",
                                            SYSDB_GROUP_CLASS)) {
            DEBUG(1, ("Wrong object (%s) found on stack!\n",
                      ldb_dn_get_linearized(msg->dn)));
            continue;
        }

        /* new result starts at end of previous result */
        rzero += rsize;
        rsize = 0;

        /* find group name/gid */
        orig_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        gid = ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);
        if (!orig_name || !gid) {
            DEBUG(2, ("Incomplete group object for %s[%llu]! Skipping\n",
                      orig_name?orig_name:"<NULL>", (unsigned long long int)gid));
            continue;
        }

        if (filter_groups) {
            ret = sss_ncache_check_group(nctx->ncache,
                                         nctx->neg_timeout, dom, orig_name);
            if (ret == EEXIST) {
                DEBUG(4, ("Group [%s@%s] filtered out! (negative cache)\n",
                          orig_name, domain));
                continue;
            }
        }

        tmpstr = sss_get_cased_name(tmp_ctx, orig_name, dom->case_sensitive);
        if (tmpstr == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("sss_get_cased_name failed, skipping\n"));
            continue;
        }
        to_sized_string(&name, tmpstr);

        /* fill in gid and name and set pointer for number of members */
        rsize = STRS_ROFFSET + name.len + pwfield.len; /* name\0x\0 */
        if (add_domain) rsize += delim + dom_len;

        ret = sss_packet_grow(packet, rsize);
        if (ret != EOK) {
            num = 0;
            goto done;
        }
        sss_packet_get_body(packet, &body, &blen);

        /*  0-3: 32bit number gid */
        SAFEALIGN_SET_UINT32(&body[rzero+GID_ROFFSET], gid, NULL);

        /*  4-7: 32bit unsigned number of members */
        SAFEALIGN_SET_UINT32(&body[rzero+MNUM_ROFFSET], 0, NULL);

        /*  8-X: sequence of strings (name, passwd, mem..) */
        if (add_domain) {
            ret = snprintf((char *)&body[rzero+STRS_ROFFSET],
                            name.len + delim + dom_len,
                            namefmt, name.str, domain);
            if (ret >= (name.len + delim + dom_len)) {
                /* need more space, got creative with the print format ? */
                int t = ret - (name.len + delim + dom_len) + 1;
                ret = sss_packet_grow(packet, t);
                if (ret != EOK) {
                    num = 0;
                    goto done;
                }
                sss_packet_get_body(packet, &body, &blen);
                rsize += t;
                delim += t;

                /* retry */
                ret = snprintf((char *)&body[rzero+STRS_ROFFSET],
                                name.len + delim + dom_len,
                                namefmt, name.str, domain);
            }

            if (ret != name.len + delim + dom_len - 1) {
                DEBUG(1, ("Failed to generate a fully qualified name for"
                          " group [%s] in [%s]! Skipping\n", name.str, domain));
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
            memcpy(&body[rzero+STRS_ROFFSET], name.str, name.len);
        }
        to_sized_string(&fullname, (const char *)&body[rzero+STRS_ROFFSET]);

        /* group passwd field */
        memcpy(&body[rzero+STRS_ROFFSET + fullname.len],
                                            pwfield.str, pwfield.len);

        memnum = 0;
        el = ldb_msg_find_element(msg, SYSDB_MEMBERUID);
        if (el) {
            ret = fill_members(packet, dom, nctx, el, &rzero, &rsize, &memnum);
            if (ret != EOK) {
                num = 0;
                goto done;
            }
            sss_packet_get_body(packet, &body, &blen);
        }

        el = ldb_msg_find_element(msg, SYSDB_GHOST);
        if (el) {
            ret = fill_members(packet, dom, nctx, el, &rzero, &rsize, &memnum);
            if (ret != EOK) {
                num = 0;
                goto done;
            }
            sss_packet_get_body(packet, &body, &blen);
        }
        if (memnum) {
            /* set num of members */
            SAFEALIGN_SET_UINT32(&body[rzero+MNUM_ROFFSET], memnum, NULL);
        }

        num++;

        if (gr_mmap_cache && nctx->grp_mc_ctx) {
            /* body was reallocated, so fullname might be pointing to
             * where body used to be, not where it is */
            to_sized_string(&fullname, (const char *)&body[rzero+STRS_ROFFSET]);
            ret = sss_mmap_cache_gr_store(nctx->grp_mc_ctx,
                                          &fullname, &pwfield, gid, memnum,
                                          (char *)&body[rzero] + STRS_ROFFSET +
                                            fullname.len + pwfield.len,
                                          rsize - STRS_ROFFSET -
                                            fullname.len - pwfield.len);
            if (ret != EOK && ret != ENOMEM) {
                DEBUG(SSSDBG_OP_FAILURE,
                      ("Failed to store group %s(%s) in mmap cache!",
                       name.str, domain));
            }
        }

        continue;
    }
    talloc_zfree(tmp_ctx);

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

static int nss_cmd_getgr_send_reply(struct nss_dom_ctx *dctx, bool filter)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct nss_ctx *nctx;
    int ret;
    int i;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return EFAULT;
    }
    i = dctx->res->count;
    ret = fill_grent(cctx->creq->out,
                     dctx->domain,
                     nctx, filter, true,
                     dctx->res->msgs, &i);
    if (ret) {
        return ret;
    }
    sss_packet_set_error(cctx->creq->out, EOK);
    sss_cmd_done(cctx, cmdctx);
    return EOK;
}

static void nss_cmd_getgrnam_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr);

/* search for a group.
 * Returns:
 *   ENOENT, if group is definitely not found
 *   EAGAIN, if group is beeing fetched from backend via async operations
 *   EOK, if found
 *   anything else on a fatal error
 */

static int nss_cmd_getgrnam_search(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct sss_domain_info *dom = dctx->domain;
    struct cli_ctx *cctx = cmdctx->cctx;
    char *name = NULL;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    int ret;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    while (dom) {
       /* if it is a domainless search, skip domains that require fully
         * qualified names instead */
        while (dom && cmdctx->check_next && dom->fqnames) {
            dom = dom->next;
        }

        if (!dom) break;

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        talloc_free(name);
        name = sss_get_cased_name(dctx, cmdctx->name, dom->case_sensitive);
        if (!name) return ENOMEM;

        /* verify this group has not yet been negatively cached,
        * or has been permanently filtered */
        ret = sss_ncache_check_group(nctx->ncache, nctx->neg_timeout,
                                     dom, name);

        /* if neg cached, return we didn't find it */
        if (ret == EEXIST) {
            DEBUG(2, ("Group [%s] does not exist in [%s]! (negative cache)\n",
                    name, dom->name));
            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = dom->next;
                continue;
            }
            /* There are no further domains or this was a
             * fully-qualified user request.
             */
            return ENOENT;
        }

        DEBUG(4, ("Requesting info for [%s@%s]\n", name, dom->name));

        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
            return EIO;
        }

        ret = sysdb_getgrnam(cmdctx, sysdb, name, &dctx->res);
        if (ret != EOK) {
            DEBUG(1, ("Failed to make request to our cache!\n"));
            return EIO;
        }

        if (dctx->res->count > 1) {
            DEBUG(0, ("getgrnam call returned more than one result !?!\n"));
            return ENOENT;
        }

        if (dctx->res->count == 0 && !dctx->check_provider) {
            /* set negative cache only if not result of cache check */
            ret = sss_ncache_set_group(nctx->ncache, false, dom, name);
            if (ret != EOK) {
                return ret;
            }

            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = dom->next;
                if (dom) continue;
            }

            DEBUG(2, ("No results for getgrnam call\n"));

            return ENOENT;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (dctx->check_provider) {
            ret = check_cache(dctx, nctx, dctx->res,
                              SSS_DP_GROUP, name, 0,
                              nss_cmd_getgrnam_dp_callback,
                              dctx);
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                return ret;
            }
        }

        /* One result found */
        DEBUG(6, ("Returning info for group [%s@%s]\n", name, dom->name));

        return EOK;
    }

    DEBUG(SSSDBG_MINOR_FAILURE,
          ("No matching domain found for [%s], fail!\n", cmdctx->name));
    return ENOENT;
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

        if (dctx->res && dctx->res->count == 1) {
            ret = nss_cmd_getgr_send_reply(dctx, false);
            goto done;
        }

        /* no previous results, just loop to next domain if possible */
        if (dctx->domain->next && cmdctx->check_next) {
            dctx->domain = dctx->domain->next;
            dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
        } else {
            /* nothing available */
            ret = ENOENT;
            goto done;
        }
    }

    /* ok the backend returned, search to see if we have updated results */
    ret = nss_cmd_getgrnam_search(dctx);
    if (ret == EOK) {
        /* we have results to return */
        ret = nss_cmd_getgr_send_reply(dctx, false);
    }

done:
    ret = nss_cmd_done(cmdctx, ret);
    if (ret) {
        NSS_CMD_FATAL_ERROR(cctx);
    }
}

static void nss_cmd_getgrnam_cb(struct tevent_req *req);
static int nss_cmd_getgrnam(struct cli_ctx *cctx)
{
    struct tevent_req *req;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    const char *rawname;
    char *domname;
    uint8_t *body;
    size_t blen;
    int ret;

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

    /* If the body isn't valid UTF-8, fail */
    if (!sss_utf8_check(body, blen -1)) {
        ret = EINVAL;
        goto done;
    }

    rawname = (const char *)body;

    domname = NULL;
    ret = sss_parse_name_for_domains(cmdctx, cctx->rctx->domains, rawname,
                                     &domname, &cmdctx->name);
    if (ret == EAGAIN) {
        req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, true, domname);
        if (req == NULL) {
            ret = ENOMEM;
        } else {
            dctx->rawname = rawname;
            tevent_req_set_callback(req, nss_cmd_getgrnam_cb, dctx);
            ret = EAGAIN;
        }
        goto done;
    } else if (ret != EOK) {
        DEBUG(2, ("Invalid name received [%s]\n", rawname));
        ret = ENOENT;
        goto done;
    }

    DEBUG(4, ("Requesting info for [%s] from [%s]\n",
              cmdctx->name, domname?domname:"<ALL>"));

    if (domname) {
        dctx->domain = responder_get_domain(dctx, cctx->rctx, domname);
        if (!dctx->domain) {
            ret = ENOENT;
            goto done;
        }
    } else {
        /* this is a multidomain search */
        dctx->rawname = rawname;
        dctx->domain = cctx->rctx->domains;
        cmdctx->check_next = true;
        if (cctx->rctx->get_domains_last_call.tv_sec == 0) {
            req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, false, NULL);
            if (req == NULL) {
                ret = ENOMEM;
            } else {
                tevent_req_set_callback(req, nss_cmd_getgrnam_cb, dctx);
                ret = EAGAIN;
            }
            goto done;
        }
    }

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    /* ok, find it ! */
    ret = nss_cmd_getgrnam_search(dctx);
    if (ret == EOK) {
        /* we have results to return */
        ret = nss_cmd_getgr_send_reply(dctx, false);
    }

done:
    return nss_cmd_done(cmdctx, ret);
}

static void nss_cmd_getgrnam_cb(struct tevent_req *req)
{
    struct nss_dom_ctx *dctx = tevent_req_callback_data(req, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    char *domname = NULL;
    const char *rawname = dctx->rawname;
    errno_t ret;

    ret = sss_dp_get_domains_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        goto done;
    }

    ret = sss_parse_name_for_domains(cmdctx, cctx->rctx->domains, rawname,
                                     &domname, &cmdctx->name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Invalid name received [%s]\n", rawname));
        ret = ENOENT;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Requesting info for [%s] from [%s]\n",
                              cmdctx->name, domname?domname:"<ALL>"));
    if (domname) {
        dctx->domain = responder_get_domain(dctx, cctx->rctx, domname);
        if (!dctx->domain) {
            ret = ENOENT;
            goto done;
        }
    } else {
        /* this is a multidomain search */
        dctx->domain = cctx->rctx->domains;
        cmdctx->check_next = true;
    }

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    /* ok, find it ! */
    ret = nss_cmd_getgrnam_search(dctx);
    if (ret == EOK) {
        /* we have results to return */
        ret = nss_cmd_getgr_send_reply(dctx, false);
    }

done:
    nss_cmd_done(cmdctx, ret);
}

static void nss_cmd_getgrgid_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr);

/* search for a gid.
 * Returns:
 *   ENOENT, if gid is definitely not found
 *   EAGAIN, if gid is beeing fetched from backend via async operations
 *   EOK, if found
 *   anything else on a fatal error
 */

static int nss_cmd_getgrgid_search(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct sss_domain_info *dom = dctx->domain;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    int ret;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    while (dom) {

        /* check that the gid is valid for this domain */
        if ((dom->id_min && (cmdctx->id < dom->id_min)) ||
            (dom->id_max && (cmdctx->id > dom->id_max))) {
            DEBUG(4, ("Gid [%lu] does not exist in domain [%s]! "
                      "(id out of range)\n",
                      (unsigned long)cmdctx->id, dom->name));
            if (cmdctx->check_next) {
                dom = get_next_dom_or_subdom(dom);
                continue;
            }
            return ENOENT;
        }

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        DEBUG(4, ("Requesting info for [%d@%s]\n", cmdctx->id, dom->name));

        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
            return EIO;
        }

        ret = sysdb_getgrgid(cmdctx, sysdb, cmdctx->id, &dctx->res);
        if (ret != EOK) {
            DEBUG(1, ("Failed to make request to our cache!\n"));
            return EIO;
        }

        if (dctx->res->count > 1) {
            DEBUG(0, ("getgrgid call returned more than one result !?!\n"));
            return ENOENT;
        }

        if (dctx->res->count == 0 && !dctx->check_provider) {
            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = get_next_dom_or_subdom(dom);
                continue;
            }

            DEBUG(2, ("No results for getgrgid call\n"));

            /* set negative cache only if not result of cache check */
            ret = sss_ncache_set_gid(nctx->ncache, false, cmdctx->id);
            if (ret != EOK) {
                return ret;
            }

            return ENOENT;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (dctx->check_provider) {
            ret = check_cache(dctx, nctx, dctx->res,
                              SSS_DP_GROUP, NULL, cmdctx->id,
                              nss_cmd_getgrgid_dp_callback,
                              dctx);
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                return ret;
            }
        }

        /* One result found */
        DEBUG(6, ("Returning info for gid [%d@%s]\n", cmdctx->id, dom->name));

        return EOK;
    }

    DEBUG(2, ("No matching domain found for [%d], fail!\n", cmdctx->id));
    return ENOENT;
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

        if (dctx->res && dctx->res->count == 1) {
            ret = nss_cmd_getgr_send_reply(dctx, true);
            goto done;
        }

        /* no previous results, just loop to next domain if possible */
        if (dctx->domain->next && cmdctx->check_next) {
            dctx->domain = dctx->domain->next;
            dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
        } else {
            /* nothing available */
            ret = ENOENT;
            goto done;
        }
    }

    /* ok the backend returned, search to see if we have updated results */
    ret = nss_cmd_getgrgid_search(dctx);
    if (ret == EOK) {
        /* we have results to return */
        ret = nss_cmd_getgr_send_reply(dctx, true);
    }

done:
    ret = nss_cmd_done(cmdctx, ret);
    if (ret) {
        NSS_CMD_FATAL_ERROR(cctx);
    }
}

static int nss_cmd_getgrgid(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct nss_ctx *nctx;
    uint8_t *body;
    size_t blen;
    int ret;

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

    ret = sss_ncache_check_gid(nctx->ncache, nctx->neg_timeout, cmdctx->id);
    if (ret == EEXIST) {
        DEBUG(3, ("Gid [%lu] does not exist! (negative cache)\n",
                  (unsigned long)cmdctx->id));
        ret = ENOENT;
        goto done;
    }

    /* gid searches are always multidomain */
    dctx->domain = cctx->rctx->domains;
    cmdctx->check_next = true;

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    /* ok, find it ! */
    ret = nss_cmd_getgrgid_search(dctx);
    if (ret == EOK) {
        /* we have results to return */
        ret = nss_cmd_getgr_send_reply(dctx, true);
    }

done:
    return nss_cmd_done(cmdctx, ret);
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
struct tevent_req *nss_cmd_setgrent_send(TALLOC_CTX *mem_ctx,
                                         struct cli_ctx *client);
static void nss_cmd_setgrent_done(struct tevent_req *req);
static int nss_cmd_setgrent(struct cli_ctx *cctx)
{
    struct nss_cmd_ctx *cmdctx;
    struct tevent_req *req;
    errno_t ret = EOK;

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    req = nss_cmd_setgrent_send(cmdctx, cctx);
    if (!req) {
        DEBUG(0, ("Fatal error calling nss_cmd_setgrent_send\n"));
        ret = EIO;
        goto done;
    }
    tevent_req_set_callback(req, nss_cmd_setgrent_done, cmdctx);

done:
    return nss_cmd_done(cmdctx, ret);
}

static errno_t nss_cmd_setgrent_step(struct setent_step_ctx *step_ctx);
struct tevent_req *nss_cmd_setgrent_send(TALLOC_CTX *mem_ctx,
                                         struct cli_ctx *client)
{
    errno_t ret;
    struct nss_ctx *nctx;
    struct tevent_req *req;
    struct setent_ctx *state;
    struct sss_domain_info *dom;
    struct setent_step_ctx *step_ctx;

    DEBUG(4, ("Received setgrent request\n"));
    nctx = talloc_get_type(client->rctx->pvt_ctx, struct nss_ctx);

    /* Reset the read pointers */
    client->grent_dom_idx = 0;
    client->grent_cur = 0;

    req = tevent_req_create(mem_ctx, &state, struct setent_ctx);
    if (!req) {
        DEBUG(0, ("Could not create tevent request for setgrent\n"));
        return NULL;
    }

    state->nctx = nctx;
    state->client = client;

    state->dctx = talloc_zero(state, struct nss_dom_ctx);
    if (!state->dctx) {
        ret = ENOMEM;
        goto error;
    }

    /* check if enumeration is enabled in any domain */
    for (dom = client->rctx->domains; dom; dom = dom->next) {
        if (dom->enumerate != 0) break;
    }
    state->dctx->domain = dom;

    if (state->dctx->domain == NULL) {
        DEBUG(2, ("Enumeration disabled on all domains!\n"));
        ret = ENOENT;
        goto error;
    }

    state->dctx->check_provider =
            NEED_CHECK_PROVIDER(state->dctx->domain->provider);

    /* Is the result context already available */
    if (state->nctx->gctx) {
        if (state->nctx->gctx->ready) {
            /* All of the necessary data is in place
             * We can return now, getgrent requests will work at this point
             */
            tevent_req_done(req);
            tevent_req_post(req, state->nctx->rctx->ev);
        }
        else {
            /* Object is still being constructed
             * Register for notification when it's
             * ready.
             */
            ret = nss_setent_add_ref(state, state->nctx->gctx, req);
            if (ret != EOK) {
                talloc_free(req);
                return NULL;
            }
        }
        return req;
    }

    /* Create a new result context
     * We are creating it on the nss_ctx so that it doesn't
     * go away if the original request does. We will delete
     * it when the refcount goes to zero;
     */
    state->nctx->gctx = talloc_zero(nctx, struct getent_ctx);
    if (!state->nctx->gctx) {
        ret = ENOMEM;
        goto error;
    }
    state->getent_ctx = nctx->gctx;

    /* Add a callback reference for ourselves */
    ret = nss_setent_add_ref(state, state->nctx->gctx, req);
    if (ret) goto error;

    /* ok, start the searches */
    step_ctx = talloc_zero(state->getent_ctx, struct setent_step_ctx);
    if (!step_ctx) {
        ret = ENOMEM;
        goto error;
    }

    /* Steal the dom_ctx onto the step_ctx so it doesn't go out of scope if
     * this request is canceled while other requests are in-progress.
     */
    step_ctx->dctx = talloc_steal(step_ctx, state->dctx);
    step_ctx->nctx = state->nctx;
    step_ctx->getent_ctx = state->getent_ctx;
    step_ctx->rctx = client->rctx;
    step_ctx->cctx = client;
    step_ctx->returned_to_mainloop = false;

    ret = nss_cmd_setgrent_step(step_ctx);
    if (ret != EOK && ret != EAGAIN) goto error;

    if (ret == EOK) {
        tevent_req_post(req, client->rctx->ev);
    }

    return req;

 error:
     tevent_req_error(req, ret);
     tevent_req_post(req, client->rctx->ev);
     return req;
}

static void nss_cmd_setgrent_dp_callback(uint16_t err_maj, uint32_t err_min,
                                         const char *err_msg, void *ptr);
static void setgrent_result_timeout(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval current_time,
                                    void *pvt);

/* nss_cmd_setgrent_step returns
 *   EOK if everything is done and the request needs to be posted explicitly
 *   EAGAIN if the caller can safely return to the main loop
 */
static errno_t nss_cmd_setgrent_step(struct setent_step_ctx *step_ctx)
{
    errno_t ret;
    struct sss_domain_info *dom = step_ctx->dctx->domain;
    struct resp_ctx *rctx = step_ctx->rctx;
    struct nss_dom_ctx *dctx = step_ctx->dctx;
    struct getent_ctx *gctx = step_ctx->getent_ctx;
    struct nss_ctx *nctx = step_ctx->nctx;
    struct sysdb_ctx *sysdb;
    struct ldb_result *res;
    struct timeval tv;
    struct tevent_timer *te;
    struct tevent_req *dpreq;
    struct dp_callback_ctx *cb_ctx;

    while (dom) {
        while (dom && dom->enumerate == 0) {
            dom = dom->next;
        }

        if (!dom) break;

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        DEBUG(6, ("Requesting info for domain [%s]\n", dom->name));

        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
            return EIO;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (dctx->check_provider) {
            step_ctx->returned_to_mainloop = true;
            /* Only do this once per provider */
            dctx->check_provider = false;

            dpreq = sss_dp_get_account_send(step_ctx, rctx, dctx->domain, true,
                                            SSS_DP_GROUP, NULL, 0, NULL);
            if (!dpreq) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Enum Cache refresh for domain [%s] failed."
                       " Trying to return what we have in cache!\n",
                       dom->name));
            } else {
                cb_ctx = talloc_zero(step_ctx, struct dp_callback_ctx);
                if(!cb_ctx) {
                    talloc_zfree(dpreq);
                    return ENOMEM;
                }

                cb_ctx->callback = nss_cmd_setgrent_dp_callback;
                cb_ctx->ptr = step_ctx;
                cb_ctx->cctx = step_ctx->cctx;
                cb_ctx->mem_ctx = step_ctx;

                tevent_req_set_callback(dpreq, nsssrv_dp_send_acct_req_done, cb_ctx);

                return EAGAIN;
            }
        }

        ret = sysdb_enumgrent(dctx, sysdb, &res);
        if (ret != EOK) {
            DEBUG(1, ("Enum from cache failed, skipping domain [%s]\n",
                      dom->name));
            dom = dom->next;
            continue;
        }

        if (res->count == 0) {
            DEBUG(4, ("Domain [%s] has no groups, skipping.\n", dom->name));
            dom = dom->next;
            continue;
        }

        nctx->gctx->doms = talloc_realloc(gctx, gctx->doms,
                                    struct dom_ctx, gctx->num +1);
        if (!gctx->doms) {
            talloc_free(gctx);
            nctx->gctx = NULL;
            return ENOMEM;
        }

        nctx->gctx->doms[gctx->num].domain = dctx->domain;
        nctx->gctx->doms[gctx->num].res = talloc_steal(gctx->doms, res);

        nctx->gctx->num++;

        /* do not reply until all domain searches are done */
        dom = dom->next;
    }

    /* We've finished all our lookups
     * The result object is now safe to read.
     */
    nctx->gctx->ready = true;

    /* Set up a lifetime timer for this result object
     * We don't want this result object to outlive the
     * enum cache refresh timeout
     */
    tv = tevent_timeval_current_ofs(nctx->enum_cache_timeout, 0);
    te = tevent_add_timer(rctx->ev, nctx->gctx, tv,
                          setgrent_result_timeout, nctx);
    if (!te) {
        DEBUG(0, ("Could not set up life timer for setgrent result object. "
                  "Entries may become stale.\n"));
    }

    /* Notify the waiting clients */
    nss_setent_notify_done(nctx->gctx);

    if (step_ctx->returned_to_mainloop) {
        return EAGAIN;
    } else {
        return EOK;
    }

}

static void setgrent_result_timeout(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval current_time,
                                    void *pvt)
{
    struct nss_ctx *nctx = talloc_get_type(pvt, struct nss_ctx);

    DEBUG(1, ("setgrent result object has expired. Cleaning up.\n"));

    /* Free the group enumeration context.
     * If additional getgrent requests come in, they will invoke
     * an implicit setgrent and refresh the result object.
     */
    talloc_zfree(nctx->gctx);
}

static void nss_cmd_setgrent_dp_callback(uint16_t err_maj, uint32_t err_min,
                                         const char *err_msg, void *ptr)
{
    struct setent_step_ctx *step_ctx =
            talloc_get_type(ptr, struct setent_step_ctx);
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = nss_cmd_setgrent_step(step_ctx);
    if (ret != EOK && ret != EAGAIN) {
        /* Notify any waiting processes of failure */
        nss_setent_notify_error(step_ctx->nctx->gctx, ret);
    }
}

static errno_t nss_cmd_setgrent_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static void nss_cmd_setgrent_done(struct tevent_req *req)
{
    errno_t ret;
    struct nss_cmd_ctx *cmdctx =
            tevent_req_callback_data(req, struct nss_cmd_ctx);

    ret = nss_cmd_setgrent_recv(req);
    talloc_zfree(req);
    if (ret == EOK || ret == ENOENT) {
        /* Either we succeeded or no domains were eligible */
        ret = sss_packet_new(cmdctx->cctx->creq, 0,
                             sss_packet_get_cmd(cmdctx->cctx->creq->in),
                             &cmdctx->cctx->creq->out);
        if (ret == EOK) {
            sss_cmd_done(cmdctx->cctx, cmdctx);
            return;
        }
    }

    /* Something bad happened */
    nss_cmd_done(cmdctx, ret);
}

static int nss_cmd_retgrent(struct cli_ctx *cctx, int num)
{
    struct nss_ctx *nctx;
    struct getent_ctx *gctx;
    struct ldb_message **msgs = NULL;
    struct dom_ctx *gdom = NULL;
    int n = 0;
    int ret = ENOENT;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    if (!nctx->gctx) goto none;

    gctx = nctx->gctx;

    while (ret == ENOENT) {
        if (cctx->grent_dom_idx >= gctx->num) break;

        gdom = &gctx->doms[cctx->grent_dom_idx];

        n = gdom->res->count - cctx->grent_cur;
        if (n <= 0 && (cctx->grent_dom_idx+1 < gctx->num)) {
            cctx->grent_dom_idx++;
            gdom = &gctx->doms[cctx->grent_dom_idx];
            n = gdom->res->count;
            cctx->grent_cur = 0;
        }

        if (!n) break;

        if (n > num) n = num;

        msgs = &(gdom->res->msgs[cctx->grent_cur]);

        ret = fill_grent(cctx->creq->out,
                         gdom->domain,
                         nctx, true, false, msgs, &n);

        cctx->grent_cur += n;
    }

none:
    if (ret == ENOENT) {
        ret = sss_cmd_empty_packet(cctx->creq->out);
    }
    return ret;
}

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

static void nss_cmd_implicit_setgrent_done(struct tevent_req *req);
static int nss_cmd_getgrent(struct cli_ctx *cctx)
{
    struct nss_ctx *nctx;
    struct nss_cmd_ctx *cmdctx;
    struct tevent_req *req;

    DEBUG(4, ("Requesting info for all groups\n"));

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;

    /* Save the current index and cursor locations
     * If we end up calling setgrent implicitly, because the response object
     * expired and has to be recreated, we want to resume from the same
     * location.
     */
    cmdctx->saved_dom_idx = cctx->grent_dom_idx;
    cmdctx->saved_cur = cctx->grent_cur;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    if(!nctx->gctx || !nctx->gctx->ready) {
        /* Make sure we invoke setgrent if it hasn't been run or is still
         * processing from another client
         */
        req = nss_cmd_setgrent_send(cctx, cctx);
        if (!req) {
            return EIO;
        }
        tevent_req_set_callback(req, nss_cmd_implicit_setgrent_done, cmdctx);
        return EOK;
    }

    return nss_cmd_getgrent_immediate(cmdctx);
}

static errno_t nss_cmd_setgrent_recv(struct tevent_req *req);
static void nss_cmd_implicit_setgrent_done(struct tevent_req *req)
{
    errno_t ret;
    struct nss_cmd_ctx *cmdctx =
            tevent_req_callback_data(req, struct nss_cmd_ctx);

    ret = nss_cmd_setgrent_recv(req);
    talloc_zfree(req);

    /* ENOENT is acceptable, as it just means that there were no entries
     * to be returned. This will be handled gracefully in nss_cmd_retpwent
     * later.
     */
    if (ret != EOK && ret != ENOENT) {
        DEBUG(0, ("Implicit setgrent failed with unexpected error [%d][%s]\n",
                  ret, strerror(ret)));
        NSS_CMD_FATAL_ERROR(cmdctx);
    }

    /* Restore the saved index and cursor locations */
    cmdctx->cctx->grent_dom_idx = cmdctx->saved_dom_idx;
    cmdctx->cctx->grent_cur = cmdctx->saved_cur;

    ret = nss_cmd_getgrent_immediate(cmdctx);
    if (ret != EOK) {
        DEBUG(0, ("Immediate retrieval failed with unexpected error "
                  "[%d][%s]\n", ret, strerror(ret)));
        NSS_CMD_FATAL_ERROR(cmdctx);
    }
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

    if (ret != EOK) {
        return ret;
    }
    if (nctx->gctx == NULL) goto done;

    /* Reset the indices so that subsequent requests start at zero */
    cctx->grent_dom_idx = 0;
    cctx->grent_cur = 0;

done:
    sss_cmd_done(cctx, NULL);
    return EOK;
}

/* FIXME: what about mpg, should we return the user's GID ? */
/* FIXME: should we filter out GIDs ? */
static int fill_initgr(struct sss_packet *packet, struct ldb_result *res)
{
    uint8_t *body;
    size_t blen;
    gid_t gid;
    int ret, i, num, bindex;
    int skipped = 0;
    const char *posix;

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
    bindex = 0;
    for (i = 0; i < num; i++) {
        gid = ldb_msg_find_attr_as_uint64(res->msgs[i + 1], SYSDB_GIDNUM, 0);
        posix = ldb_msg_find_attr_as_string(res->msgs[i + 1], SYSDB_POSIX, NULL);
        if (!gid) {
            if (posix && strcmp(posix, "FALSE") == 0) {
                skipped++;
                continue;
            } else {
                DEBUG(1, ("Incomplete group object for initgroups! Aborting\n"));
                return EFAULT;
            }
        }
        ((uint32_t *)body)[2 + bindex] = gid;
        bindex++;
    }

    ((uint32_t *)body)[0] = num-skipped; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

    return EOK;
}

static int nss_cmd_initgr_send_reply(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int ret;

    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return EFAULT;
    }

    ret = fill_initgr(cctx->creq->out, dctx->res);
    if (ret) {
        return ret;
    }
    sss_packet_set_error(cctx->creq->out, EOK);
    sss_cmd_done(cctx, cmdctx);
    return EOK;
}

static void nss_cmd_initgroups_dp_callback(uint16_t err_maj, uint32_t err_min,
                                           const char *err_msg, void *ptr);

static int nss_cmd_initgroups_search(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct sss_domain_info *dom = dctx->domain;
    struct cli_ctx *cctx = cmdctx->cctx;
    char *name = NULL;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    int ret;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    while (dom) {
       /* if it is a domainless search, skip domains that require fully
         * qualified names instead */
        while (dom && cmdctx->check_next && dom->fqnames) {
            dom = dom->next;
        }

        if (!dom) break;

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        talloc_free(name);
        name = sss_get_cased_name(dctx, cmdctx->name, dom->case_sensitive);
        if (!name) return ENOMEM;

        /* verify this user has not yet been negatively cached,
        * or has been permanently filtered */
        ret = sss_ncache_check_user(nctx->ncache, nctx->neg_timeout,
                                    dom, name);

        /* if neg cached, return we didn't find it */
        if (ret == EEXIST) {
            DEBUG(2, ("User [%s] does not exist in [%s]! (negative cache)\n",
                      name, dom->name));
            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = dom->next;
                continue;
            }
            /* There are no further domains or this was a
             * fully-qualified user request.
             */
            return ENOENT;
        }

        DEBUG(4, ("Requesting info for [%s@%s]\n", name, dom->name));

        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
            return EIO;
        }

        ret = sysdb_initgroups(cmdctx, sysdb, name, &dctx->res);
        if (ret != EOK) {
            DEBUG(1, ("Failed to make request to our cache! [%d][%s]\n",
                      ret, strerror(ret)));
            return EIO;
        }

        if (dctx->res->count == 0 && !dctx->check_provider) {
            /* set negative cache only if not result of cache check */
            ret = sss_ncache_set_user(nctx->ncache, false, dom, name);
            if (ret != EOK) {
                return ret;
            }

            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = dom->next;
                if (dom) continue;
            }

            DEBUG(2, ("No results for initgroups call\n"));

            return ENOENT;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (dctx->check_provider) {
            ret = check_cache(dctx, nctx, dctx->res,
                              SSS_DP_INITGROUPS, name, 0,
                              nss_cmd_initgroups_dp_callback,
                              dctx);
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                return ret;
            }
        }

        DEBUG(6, ("Initgroups for [%s@%s] completed\n", name, dom->name));
        return EOK;
    }

    DEBUG(SSSDBG_MINOR_FAILURE,
          ("No matching domain found for [%s], fail!\n", cmdctx->name));
    return ENOENT;
}

static void nss_cmd_initgroups_dp_callback(uint16_t err_maj, uint32_t err_min,
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

        if (dctx->res && dctx->res->count != 0) {
            ret = nss_cmd_initgr_send_reply(dctx);
            goto done;
        }

        /* no previous results, just loop to next domain if possible */
        if (dctx->domain->next && cmdctx->check_next) {
            dctx->domain = dctx->domain->next;
            dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
        } else {
            /* nothing available */
            ret = ENOENT;
            goto done;
        }
    }

    /* ok the backend returned, search to see if we have updated results */
    ret = nss_cmd_initgroups_search(dctx);
    if (ret == EOK) {
        /* we have results to return */
        ret = nss_cmd_initgr_send_reply(dctx);
    }

done:
    ret = nss_cmd_done(cmdctx, ret);
    if (ret) {
        NSS_CMD_FATAL_ERROR(cctx);
    }
}

/* for now, if we are online, try to always query the backend */
static void nss_cmd_initgroups_cb(struct tevent_req *req);
static int nss_cmd_initgroups(struct cli_ctx *cctx)
{
    struct tevent_req *req;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    const char *rawname;
    char *domname;
    uint8_t *body;
    size_t blen;
    int ret;

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

    /* If the body isn't valid UTF-8, fail */
    if (!sss_utf8_check(body, blen -1)) {
        ret = EINVAL;
        goto done;
    }

    rawname = (const char *)body;

    domname = NULL;
    ret = sss_parse_name_for_domains(cmdctx, cctx->rctx->domains, rawname,
                                     &domname, &cmdctx->name);
    if (ret == EAGAIN) {
        req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, true, domname);
        if (req == NULL) {
            ret = ENOMEM;
        } else {
            dctx->rawname = rawname;
            tevent_req_set_callback(req, nss_cmd_initgroups_cb, dctx);
            ret = EAGAIN;
        }
        goto done;
    } else if (ret != EOK) {
        DEBUG(2, ("Invalid name received [%s]\n", rawname));
        ret = ENOENT;
        goto done;
    }

    DEBUG(4, ("Requesting info for [%s] from [%s]\n",
              cmdctx->name, domname?domname:"<ALL>"));

    if (domname) {
        dctx->domain = responder_get_domain(dctx, cctx->rctx, domname);
        if (!dctx->domain) {
            ret = ENOENT;
            goto done;
        }
    } else {
        /* this is a multidomain search */
        dctx->rawname = rawname;
        dctx->domain = cctx->rctx->domains;
        cmdctx->check_next = true;
        if (cctx->rctx->get_domains_last_call.tv_sec == 0) {
            req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, false, NULL);
            if (req == NULL) {
                ret = ENOMEM;
            } else {
                tevent_req_set_callback(req, nss_cmd_initgroups_cb, dctx);
                ret = EAGAIN;
            }
            goto done;
        }
    }

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    /* ok, find it ! */
    ret = nss_cmd_initgroups_search(dctx);
    if (ret == EOK) {
        /* we have results to return */
        ret = nss_cmd_initgr_send_reply(dctx);
    }

done:
    return nss_cmd_done(cmdctx, ret);
}

static void nss_cmd_initgroups_cb(struct tevent_req *req)
{
    struct nss_dom_ctx *dctx = tevent_req_callback_data(req, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    char *domname = NULL;
    const char *rawname = dctx->rawname;
    errno_t ret;

    ret = sss_dp_get_domains_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        goto done;
    }

    ret = sss_parse_name_for_domains(cmdctx, cctx->rctx->domains, rawname,
                                     &domname, &cmdctx->name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Invalid name received [%s]\n", rawname));
        ret = ENOENT;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Requesting info for [%s] from [%s]\n",
                              cmdctx->name, domname?domname:"<ALL>"));

    if (domname) {
        dctx->domain = responder_get_domain(dctx, cctx->rctx, domname);
        if (!dctx->domain) {
            ret = ENOENT;
            goto done;
        }
    } else {
        /* this is a multidomain search */
        dctx->domain = cctx->rctx->domains;
        cmdctx->check_next = true;
    }

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    /* ok, find it ! */
    ret = nss_cmd_initgroups_search(dctx);
    if (ret == EOK) {
        /* we have results to return */
        ret = nss_cmd_initgr_send_reply(dctx);
    }

done:
    nss_cmd_done(cmdctx, ret);
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
    {SSS_NSS_SETNETGRENT, nss_cmd_setnetgrent},
    {SSS_NSS_GETNETGRENT, nss_cmd_getnetgrent},
    {SSS_NSS_ENDNETGRENT, nss_cmd_endnetgrent},
    {SSS_NSS_GETSERVBYNAME, nss_cmd_getservbyname},
    {SSS_NSS_GETSERVBYPORT, nss_cmd_getservbyport},
    {SSS_NSS_SETSERVENT, nss_cmd_setservent},
    {SSS_NSS_GETSERVENT, nss_cmd_getservent},
    {SSS_NSS_ENDSERVENT, nss_cmd_endservent},
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
