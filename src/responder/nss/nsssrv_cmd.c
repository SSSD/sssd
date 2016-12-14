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
#include "util/sss_cli_cmd.h"
#include "util/crypto/sss_crypto.h"
#include "util/cert.h"
#include "responder/nss/nsssrv.h"
#include "responder/nss/nsssrv_private.h"
#include "responder/nss/nsssrv_netgroup.h"
#include "responder/nss/nsssrv_services.h"
#include "responder/nss/nsssrv_mmap_cache.h"
#include "responder/common/negcache.h"
#include "responder/common/cache_req/cache_req.h"
#include "providers/data_provider.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "sss_client/idmap/sss_nss_idmap.h"
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
    return setent_add_ref(memctx, &getent_ctx->reqs, req);
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

static int nss_reset_negcache(struct resp_ctx *rctx)
{
    return sss_ncache_reset_repopulate_permanent(rctx, rctx->ncache);
}

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
                                        struct sss_nss_homedir_ctx *homedir_ctx)
{
    const char *homedir;

    homedir = sss_view_ldb_msg_find_attr_as_string(dom, msg, SYSDB_HOMEDIR,
                                                   NULL);
    homedir_ctx->original = homedir;

    /* Check to see which homedir_prefix to use. */
    if (dom->homedir_substr != NULL) {
        homedir_ctx->config_homedir_substr = dom->homedir_substr;
    } else if (nctx->homedir_substr != NULL) {
        homedir_ctx->config_homedir_substr = nctx->homedir_substr;
    }

    /* Check whether we are unconditionally overriding the server
     * for home directory locations.
     */
    if (dom->override_homedir) {
        return expand_homedir_template(mem_ctx, dom->override_homedir,
                                       dom->case_preserve, homedir_ctx);
    } else if (nctx->override_homedir) {
        return expand_homedir_template(mem_ctx, nctx->override_homedir,
                                       dom->case_preserve, homedir_ctx);
    }

    if (!homedir || *homedir == '\0') {
        /* In the case of a NULL or empty homedir, check to see if
         * we have a fallback homedir to use.
         */
        if (dom->fallback_homedir) {
            return expand_homedir_template(mem_ctx, dom->fallback_homedir,
                                           dom->case_preserve, homedir_ctx);
        } else if (nctx->fallback_homedir) {
            return expand_homedir_template(mem_ctx, nctx->fallback_homedir,
                                           dom->case_preserve, homedir_ctx);
        }
    }

    /* Provider can also return template, try to expand it.*/
    return expand_homedir_template(mem_ctx, homedir,
                                   dom->case_preserve, homedir_ctx);
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

    user_shell = sss_view_ldb_msg_find_attr_as_string(dom, msg, SYSDB_SHELL,
                                                      NULL);
    if (!user_shell) {
        /* Check whether there is a default shell specified */
        if (dom->default_shell) {
            return talloc_strdup(mem_ctx, dom->default_shell);
        } else if (nctx->default_shell) {
            return talloc_strdup(mem_ctx, nctx->default_shell);
        }
        return NULL;
    }
    if (!nctx->allowed_shells && !nctx->vetoed_shells) return talloc_strdup(mem_ctx, user_shell);

    if (nctx->vetoed_shells) {
        for (i=0; nctx->vetoed_shells[i]; i++) {
            if (strcmp(nctx->vetoed_shells[i], user_shell) == 0) {
                DEBUG(SSSDBG_FUNC_DATA, "The shell '%s' is vetoed. "
                         "Using fallback\n", user_shell);
                return talloc_strdup(mem_ctx, nctx->shell_fallback);
            }
        }
    }

    if (nctx->etc_shells) {
        for (i=0; nctx->etc_shells[i]; i++) {
            if (strcmp(user_shell, nctx->etc_shells[i]) == 0) {
                DEBUG(SSSDBG_TRACE_ALL, "Shell %s found in /etc/shells\n",
                        nctx->etc_shells[i]);
                break;
            }
        }

        if (nctx->etc_shells[i]) {
            DEBUG(SSSDBG_TRACE_ALL, "Using original shell '%s'\n", user_shell);
            return talloc_strdup(mem_ctx, user_shell);
        }
    }

    if (nctx->allowed_shells) {
        if (strcmp(nctx->allowed_shells[0], "*") == 0) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "The shell '%s' is allowed but does not exist. "
                  "Using fallback\n", user_shell);
            return talloc_strdup(mem_ctx, nctx->shell_fallback);
        } else {
            for (i=0; nctx->allowed_shells[i]; i++) {
                if (strcmp(nctx->allowed_shells[i], user_shell) == 0) {
                    DEBUG(SSSDBG_FUNC_DATA,
                          "The shell '%s' is allowed but does not exist. "
                          "Using fallback\n", user_shell);
                    return talloc_strdup(mem_ctx, nctx->shell_fallback);
                }
            }
        }
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "The shell '%s' is not allowed and does not exist.\n",
              user_shell);
    return talloc_strdup(mem_ctx, NOLOGIN_SHELL);
}

static int sized_output_name(TALLOC_CTX *mem_ctx,
                             struct resp_ctx *rctx,
                             const char *orig_name,
                             struct sss_domain_info *name_dom,
                             struct sized_string **_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    char *username;
    struct sized_string *name;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    username = sss_output_name(tmp_ctx, orig_name, name_dom->case_preserve,
                               rctx->override_space);
    if (username == NULL) {
        ret = EIO;
        goto done;
    }

    if (name_dom->fqnames) {
        username = sss_tc_fqname(tmp_ctx, name_dom->names, name_dom, username);
        if (username == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_replace_space failed\n");
            ret = EIO;
            goto done;
        }
    }

    name = talloc_zero(tmp_ctx, struct sized_string);
    if (name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    to_sized_string(name, username);
    name->str = talloc_steal(name, username);
    *_name = talloc_steal(mem_ctx, name);
    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static int sized_member_name(TALLOC_CTX *mem_ctx,
                             struct resp_ctx *rctx,
                             const char *member_name,
                             struct sized_string **_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    char *domname;
    struct sss_domain_info *member_dom;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_parse_internal_fqname(tmp_ctx, member_name, NULL, &domname);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_parse_internal_fqname failed\n");
        goto done;
    }

    if (domname == NULL) {
        ret = ERR_WRONG_NAME_FORMAT;
        goto done;
    }

    member_dom = find_domain_by_name(get_domains_head(rctx->domains),
                                     domname, true);
    if (member_dom == NULL) {
        ret = ERR_DOMAIN_NOT_FOUND;
        goto done;
    }

    ret = sized_output_name(mem_ctx, rctx, member_name,
                            member_dom, _name);
done:
    talloc_free(tmp_ctx);
    return ret;
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
    const char *upn;
    const char *tmpstr;
    const char *orig_name;
    struct sized_string *name;
    struct sized_string gecos;
    struct sized_string homedir;
    struct sized_string shell;
    struct sized_string pwfield;
    uint32_t uid;
    uint32_t gid;
    size_t rsize, rp, blen;
    int i, ret, num;
    const char *domain = dom->name;
    bool packet_initialized = false;
    int ncret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct sss_nss_homedir_ctx homedir_ctx;

    to_sized_string(&pwfield, nctx->pwfield);

    rp = 2*sizeof(uint32_t);

    num = 0;
    for (i = 0; i < *count; i++) {
        talloc_zfree(tmp_ctx);
        tmp_ctx = talloc_new(NULL);

        msg = msgs[i];

        upn = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);

        if (DOM_HAS_VIEWS(dom)) {
            orig_name = ldb_msg_find_attr_as_string(msg,
                                                    OVERRIDE_PREFIX SYSDB_NAME,
                                                    NULL);

            gid = ldb_msg_find_attr_as_uint64(msg,
                                              OVERRIDE_PREFIX SYSDB_GIDNUM, 0);
        } else {
            orig_name = NULL;
            gid = 0;
        }

        if (orig_name == NULL) {
            orig_name = ldb_msg_find_attr_as_string(msg,
                                                    SYSDB_DEFAULT_OVERRIDE_NAME,
                                                    NULL);
            if (orig_name == NULL) {
                orig_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
            }
        }

        uid = sss_view_ldb_msg_find_attr_as_uint64(dom, msg, SYSDB_UIDNUM, 0);

        if (gid == 0) {
            gid = get_gid_override(msg, dom);
        }

        if (!orig_name || !uid || !gid) {
            DEBUG(SSSDBG_OP_FAILURE, "Incomplete user object for %s[%llu]! Skipping\n",
                      orig_name?orig_name:"<NULL>", (unsigned long long int)uid);
            continue;
        }

        if (filter_users) {
            ncret = sss_ncache_check_user(nctx->rctx->ncache, dom, orig_name);
            if (ncret == EEXIST) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "User [%s] filtered out! (negative cache)\n", orig_name);
                continue;
            }
        }

        if (!packet_initialized) {
            /* first 2 fields (len and reserved), filled up later */
            ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
            if (ret != EOK) return ret;
            packet_initialized = true;
        }

        ret = sized_output_name(tmp_ctx, nctx->rctx, orig_name,
                                dom, &name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sized_output_name failed, skipping\n");
            continue;
        }

        tmpstr = sss_view_ldb_msg_find_attr_as_string(dom, msg, SYSDB_GECOS,
                                                      NULL);
        if (!tmpstr) {
            to_sized_string(&gecos, "");
        } else {
            to_sized_string(&gecos, tmpstr);
        }

        ZERO_STRUCT(homedir_ctx);
        homedir_ctx.username = orig_name;
        homedir_ctx.uid = uid;
        homedir_ctx.domain = dom->name;
        homedir_ctx.upn = upn;

        tmpstr = get_homedir_override(tmp_ctx, msg, nctx, dom, &homedir_ctx);
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

        rsize = 2 * sizeof(uint32_t) + name->len + gecos.len +
                                       homedir.len + shell.len + pwfield.len;

        ret = sss_packet_grow(packet, rsize);
        if (ret != EOK) {
            num = 0;
            goto done;
        }
        sss_packet_get_body(packet, &body, &blen);

        SAFEALIGN_SET_UINT32(&body[rp], uid, &rp);
        SAFEALIGN_SET_UINT32(&body[rp], gid, &rp);
        memcpy(&body[rp], name->str, name->len);
        rp += name->len;

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
            ret = sss_mmap_cache_pw_store(&nctx->pwd_mc_ctx,
                                          name, &pwfield,
                                          uid, gid,
                                          &gecos, &homedir, &shell);
            if (ret != EOK && ret != ENOMEM) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to store user %s(%s) in mmap cache!\n",
                       name->str, domain);
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
    SAFEALIGN_COPY_UINT32(body, &num, NULL); /* num results */
    SAFEALIGN_SETMEM_UINT32(body + sizeof(uint32_t), 0, NULL); /* reserved */

    return EOK;
}

static int nss_cmd_getpw_send_reply(struct nss_dom_ctx *dctx, bool filter)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct cli_protocol *pctx;
    struct nss_ctx *nctx;
    int ret;
    int i;

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);
    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        return EFAULT;
    }
    i = dctx->res->count;

    ret = fill_pwent(pctx->creq->out,
                     dctx->domain,
                     nctx, filter, true,
                     dctx->res->msgs, &i);
    if (ret) {
        return ret;
    }
    sss_packet_set_error(pctx->creq->out, EOK);
    sss_cmd_done(cctx, cmdctx);
    return EOK;
}

static bool
is_refreshed_on_bg(enum sss_dp_acct_type req_type,
                   uint32_t refresh_expired_interval)
{
    if (refresh_expired_interval == 0) {
        return false;
    }

    switch (req_type) {
    case SSS_DP_NETGR:
    case SSS_DP_USER:
    case SSS_DP_GROUP:
        return true;
    default:
        return false;
    }

    return false;
}

static void nsssrv_dp_send_acct_req_done(struct tevent_req *req);

static void get_dp_name_and_id(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *dom,
                              enum sss_dp_acct_type req_type,
                              const char *opt_name,
                              uint32_t opt_id,
                              const char **_name,
                              uint32_t *_id)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res = NULL;
    const char *attr;
    const char *name;
    uint32_t id;
    errno_t ret;

    /* First set the same values to make things easier. */
    *_name = opt_name;
    *_id = opt_id;

    if (!DOM_HAS_VIEWS(dom) || !is_local_view(dom->view_name)) {
        DEBUG(SSSDBG_TRACE_FUNC, "Not a LOCAL view, continuing with "
              "provided values.\n");
        return;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return;
    }

    if (opt_name != NULL) {
        switch (req_type) {
        case SSS_DP_USER:
        case SSS_DP_INITGROUPS:
            ret = sysdb_getpwnam_with_views(tmp_ctx, dom, opt_name, &res);
            if (ret != EOK) {
                DEBUG(SSSDBG_CONF_SETTINGS,
                      "sysdb_getpwnam_with_views() failed [%d]: %s\n",
                      ret, sss_strerror(ret));
                goto done;
            }
            break;
        case SSS_DP_GROUP:
            ret = sysdb_getgrnam_with_views(tmp_ctx, dom, opt_name, &res);
            if (ret != EOK) {
                DEBUG(SSSDBG_CONF_SETTINGS,
                      "sysdb_getgrnam_with_views() failed [%d]: %s\n",
                      ret, sss_strerror(ret));
                goto done;
            }
            break;
        default:
            goto done;
        }

        if (res == NULL || res->count != 1) {
            /* This should not happen with LOCAL view and overridden value. */
            DEBUG(SSSDBG_TRACE_FUNC, "Entry is missing?! Continuing with "
                  "provided values.\n");
            goto done;
        }

        name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: name cannot be NULL\n");
            goto done;
        }

        *_name = talloc_steal(mem_ctx, name);
    } else if (opt_id != 0) {
        switch (req_type) {
        case SSS_DP_USER:
            ret = sysdb_getpwuid_with_views(tmp_ctx, dom, opt_id, &res);
            if (ret != EOK) {
                DEBUG(SSSDBG_CONF_SETTINGS,
                      "sysdb_getpwuid_with_views() failed [%d]: %s\n",
                      ret, sss_strerror(ret));
                goto done;
            }

            attr = SYSDB_UIDNUM;
            break;
        case SSS_DP_GROUP:
            ret = sysdb_getgrgid_with_views(tmp_ctx, dom, opt_id, &res);
            if (ret != EOK) {
                DEBUG(SSSDBG_CONF_SETTINGS,
                      "sysdb_getgrgid_with_views() failed [%d]: %s\n",
                      ret, sss_strerror(ret));
                goto done;
            }

            attr = SYSDB_GIDNUM;
            break;
        default:
            goto done;
        }

        if (res == NULL || res->count != 1) {
            /* This should not happen with LOCAL view and overridden value. */
            DEBUG(SSSDBG_TRACE_FUNC, "Entry is missing?! Continuing with "
                  "provided values.\n");
            goto done;
        }

        id = ldb_msg_find_attr_as_uint64(res->msgs[0], attr, 0);
        if (id == 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: id cannot be 0\n");
            goto done;
        }

        *_id = id;
    }

done:
    talloc_free(tmp_ctx);
}

/* FIXME: do not check res->count, but get in a msgs and check in parent */
errno_t check_cache(struct nss_dom_ctx *dctx,
                    struct nss_ctx *nctx,
                    struct ldb_result *res,
                    enum sss_dp_acct_type req_type,
                    const char *opt_name,
                    uint32_t opt_id,
                    const char *extra,
                    sss_dp_callback_t callback,
                    void *pvt)
{
    errno_t ret;
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct tevent_req *req = NULL;
    struct dp_callback_ctx *cb_ctx = NULL;
    uint64_t cacheExpire = 0;
    const char *name = opt_name;
    uint32_t id = opt_id;

    /* when searching for a user or netgroup, more than one reply is a
     * db error
     */
    if ((req_type == SSS_DP_USER || req_type == SSS_DP_NETGR) &&
            (res->count > 1)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "getpwXXX call returned more than one result! DB Corrupted?\n");
        return ENOENT;
    }

    /* In case of local view we have to always contant DP with the original
     * name or id. */
    get_dp_name_and_id(dctx->cmdctx, dctx->domain, req_type, opt_name, opt_id,
                       &name, &id);

    /* if we have any reply let's check cache validity */
    if (res->count > 0) {
        bool refreshed_on_bg;
        uint32_t bg_refresh_interval = dctx->domain->refresh_expired_interval;

        if (req_type == SSS_DP_INITGROUPS) {
            cacheExpire = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                      SYSDB_INITGR_EXPIRE,
                                                      0);
        } else {
            cacheExpire = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                      SYSDB_CACHE_EXPIRE,
                                                      0);
        }

        /* Check if background refresh is enabled for this entry */
        refreshed_on_bg = is_refreshed_on_bg(req_type, bg_refresh_interval);

        /* if we have any reply let's check cache validity */
        ret = sss_cmd_check_cache(res->msgs[0],
                                  nctx->cache_refresh_percent,
                                  cacheExpire);
        if (ret == EOK || (ret == EAGAIN && refreshed_on_bg))  {
            DEBUG(SSSDBG_TRACE_FUNC, "Cached entry is valid, returning..\n");
            return EOK;
        } else if (ret != EAGAIN && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Error checking cache: %d\n", ret);
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
             "Performing midpoint cache update on [%s]\n", name);

        req = sss_dp_get_account_send(cctx, cctx->rctx, dctx->domain, true,
                                      req_type, name, id, extra);
        if (!req) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Out of memory sending out-of-band data provider "
                   "request\n");
            /* This is non-fatal, so we'll continue here */
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "Updating cache out-of-band\n");
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
                                      req_type, name, id, extra);
        if (!req) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Out of memory sending data provider request\n");
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

static int delete_entry_from_memcache(struct sss_domain_info *dom,
                                      char *name,
                                      struct resp_ctx *rctx,
                                      struct sss_mc_ctx *mc_ctx,
                                      enum sss_mc_type type)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sized_string *delete_name;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory.\n");
        return ENOMEM;
    }

    ret = sized_output_name(tmp_ctx, rctx, name, dom, &delete_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sized_output_name failed: %d\n", ret);
        goto done;
    }

    switch (type) {
    case SSS_MC_PASSWD:
        ret = sss_mmap_cache_pw_invalidate(mc_ctx, delete_name);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Internal failure in memory cache code: %d [%s]\n",
                  ret, strerror(ret));
            goto done;
        }
        break;
    case SSS_MC_GROUP:
        ret = sss_mmap_cache_gr_invalidate(mc_ctx, delete_name);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Internal failure in memory cache code: %d [%s]\n",
                  ret, strerror(ret));
            goto done;
        }
        break;
    case SSS_MC_INITGROUPS:
        ret = sss_mmap_cache_initgr_invalidate(mc_ctx, delete_name);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Internal failure in memory cache code: %d [%s]\n",
                  ret, strerror(ret));
            goto done;
        }
        break;
    default:
        ret = EINVAL;
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;

}

static void nss_cmd_getby_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr);
static int nss_cmd_assume_upn(struct nss_dom_ctx *dctx);

/* search for a user.
 * Returns:
 *   ENOENT, if user is definitely not found
 *   EAGAIN, if user is being fetched from backend via async operations
 *   EOK, if found
 *   anything else on a fatal error
 */

static int nss_cmd_getpwnam_search(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct sss_domain_info *dom = dctx->domain;
    struct cli_ctx *cctx = cmdctx->cctx;
    char *name = NULL;
    struct nss_ctx *nctx;
    int ret;
    static const char *user_attrs[] = SYSDB_PW_ATTRS;
    struct ldb_message *msg;
    const char *extra_flag = NULL;
    const char *sysdb_name;
    char *neg_cache_name;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    while (dom) {
       /* if it is a domainless search, skip domains that require fully
         * qualified names instead */
        while (dom && cmdctx->check_next && dom->fqnames
                && !cmdctx->name_is_upn) {
            dom = get_next_domain(dom, 0);
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
        name = sss_resp_create_fqname(dctx, nctx->rctx, dctx->domain,
                                      cmdctx->name_is_upn, cmdctx->name);
        if (name == NULL) {
            return ENOMEM;
        }

        if (cmdctx->name_is_upn) {
            neg_cache_name = talloc_asprintf(name, "@%s", name);
        } else {
            neg_cache_name = name;
        }

        /* verify this user has not yet been negatively cached,
        * or has been permanently filtered */
        ret = sss_ncache_check_user(nctx->rctx->ncache, dom, neg_cache_name);

        /* if neg cached, return we didn't find it */
        if (ret == EEXIST) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "User [%s] does not exist in [%s]! (negative cache)\n",
                   name, dom->name);
            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                if (cmdctx->name_is_upn) {
                    dom = get_next_domain(dom, SSS_GND_DESCEND);
                } else {
                    dom = get_next_domain(dom, 0);
                }
                continue;
            }
            /* There are no further domains or this was a
             * fully-qualified user request.
             */

            return ENOENT;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Requesting info for [%s]\n", name);

        if (dom->sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Fatal: Sysdb CTX not found for this domain!\n");
            return EIO;
        }

        if (cmdctx->name_is_upn) {
            ret = sysdb_search_user_by_upn(cmdctx, dom, name, user_attrs, &msg);
            if (ret != EOK && ret != ENOENT) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_user_by_upn failed.\n");
                return ret;
            }

            dctx->res = talloc_zero(cmdctx, struct ldb_result);
            if (dctx->res == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
                return ENOMEM;
            }

            if (ret == ENOENT) {
                dctx->res->count = 0;
                dctx->res->msgs = NULL;
                ret = EOK;
            } else {
                dctx->res->count = 1;
                dctx->res->msgs = talloc_array(dctx->res,
                                               struct ldb_message *, 1);
                if (dctx->res->msgs == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
                    return ENOMEM;
                }

                dctx->res->msgs[0] = talloc_steal(dctx->res->msgs, msg);

                /* Since sysdb_search_user_by_upn() searches the whole cache we
                 * have to set the domain so that it matches the result. */
                sysdb_name = ldb_msg_find_attr_as_string(dctx->res->msgs[0],
                                                         SYSDB_NAME, NULL);
                if (sysdb_name == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Cached entry has no name.\n");
                    return EINVAL;
                }
                dctx->domain = find_domain_by_object_name(get_domains_head(dom),
                                                          sysdb_name);
                if (dctx->domain == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Cannot find matching domain for [%s].\n",
                          sysdb_name);
                    return EINVAL;
                }
            }
        } else {
            ret = sysdb_getpwnam_with_views(cmdctx, dom, name, &dctx->res);
        }
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to make request to our cache!\n");
            return EIO;
        }

        if (dctx->res->count > 1) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "getpwnam call returned more than one result !?!\n");
            sss_log(SSS_LOG_ERR,
                    "More users have the same name [%s] in SSSD cache. "
                    "SSSD will not work correctly.\n",
                    name);
            return ENOENT;
        }

        if (dctx->res->count == 0 && !dctx->check_provider) {
            /* set negative cache only if not result of cache check */
            ret = sss_ncache_set_user(nctx->rctx->ncache, false, dom,
                                      neg_cache_name);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Cannot set negcache for %s\n",
                      name);
            }

            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                if (cmdctx->name_is_upn) {
                    dom = get_next_domain(dom, SSS_GND_DESCEND);
                } else {
                    dom = get_next_domain(dom, 0);
                }
                if (dom) continue;
            }

            /* User not found in ldb -> delete user from memory cache. */
            ret = delete_entry_from_memcache(dctx->domain, name, nctx->rctx,
                                             nctx->pwd_mc_ctx, SSS_MC_PASSWD);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Deleting user from memcache failed.\n");
            }

            ret = delete_entry_from_memcache(dctx->domain,
                                             name, nctx->rctx,
                                             nctx->initgr_mc_ctx,
                                             SSS_MC_INITGROUPS);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Deleting user from memcache failed.\n");
            }

            DEBUG(SSSDBG_OP_FAILURE, "No results for getpwnam call\n");

            return ENOENT;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (dctx->check_provider) {

            if (cmdctx->name_is_upn) {
                extra_flag = EXTRA_NAME_IS_UPN;
            } else if (DOM_HAS_VIEWS(dom) && (dctx->res->count == 0
                    || ldb_msg_find_attr_as_string(dctx->res->msgs[0],
                                                   OVERRIDE_PREFIX SYSDB_NAME,
                                                   NULL) != NULL)) {
                extra_flag = EXTRA_INPUT_MAYBE_WITH_VIEW;
            } else {
                extra_flag = NULL;
            }

            ret = check_cache(dctx, nctx, dctx->res, SSS_DP_USER, name, 0,
                              extra_flag, nss_cmd_getby_dp_callback, dctx);
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                return ret;
            }
        }

        /* One result found */
        DEBUG(SSSDBG_TRACE_FUNC, "Returning info for user [%s]\n", name);
        return EOK;
    }

    DEBUG(SSSDBG_MINOR_FAILURE,
          "No matching domain found for [%s], fail!\n", cmdctx->name);
    return ENOENT;
}

static int nss_cmd_getgrnam_search(struct nss_dom_ctx *dctx);
static int nss_cmd_getgr_send_reply(struct nss_dom_ctx *dctx, bool filter);
static int nss_cmd_initgroups_search(struct nss_dom_ctx *dctx);
static int nss_cmd_initgr_send_reply(struct nss_dom_ctx *dctx);
static int nss_cmd_getpwuid_search(struct nss_dom_ctx *dctx);
static int nss_cmd_getgrgid_search(struct nss_dom_ctx *dctx);
static errno_t nss_cmd_getbysid_search(struct nss_dom_ctx *dctx);
static errno_t nss_cmd_getbysid_send_reply(struct nss_dom_ctx *dctx);
static errno_t nss_cmd_getsidby_search(struct nss_dom_ctx *dctx);

static int nss_cmd_assume_upn(struct nss_dom_ctx *dctx)
{
    int ret;

    if (dctx->cmdctx->name_is_upn == false) {
        dctx->domain = dctx->cmdctx->cctx->rctx->domains;
        dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
        dctx->cmdctx->check_next = true;
        dctx->cmdctx->name = talloc_strdup(dctx->cmdctx, dctx->rawname);
        dctx->cmdctx->name_is_upn = true;
        if (dctx->cmdctx->name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            return ENOMEM;
        }
    }

    switch (dctx->cmdctx->cmd) {
    case SSS_NSS_GETPWNAM:
        ret = nss_cmd_getpwnam_search(dctx);
        if (ret == EOK) {
            ret = nss_cmd_getpw_send_reply(dctx, false);
        }
        break;
    case SSS_NSS_INITGR:
        ret = nss_cmd_initgroups_search(dctx);
        if (ret == EOK) {
            ret = nss_cmd_initgr_send_reply(dctx);
        }
        break;
    case SSS_NSS_GETSIDBYNAME:
    case SSS_NSS_GETORIGBYNAME:
        ret = nss_cmd_getsidby_search(dctx);
        if (ret == EOK) {
            ret = nss_cmd_getbysid_send_reply(dctx);
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid command [%d][%s].\n",
              dctx->cmdctx->cmd, sss_cmd2str(dctx->cmdctx->cmd));
        ret = EINVAL;
    }

    return ret;
}

static void nss_cmd_getby_dp_callback(uint16_t err_maj, uint32_t err_min,
                                      const char *err_msg, void *ptr)
{
    struct nss_dom_ctx *dctx = talloc_get_type(ptr, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    int ret;
    uint32_t gnd_flags;
    struct nss_ctx *nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    if (err_maj) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg);

        if ((dctx->res && dctx->res->count == 1) ||
            (dctx->cmdctx->cmd == SSS_NSS_INITGR &&
             dctx->res && dctx->res->count != 0)) {
            switch (dctx->cmdctx->cmd) {
            case SSS_NSS_GETPWNAM:
                ret = nss_cmd_getpw_send_reply(dctx, false);
                break;
            case SSS_NSS_GETGRNAM:
                ret = nss_cmd_getgr_send_reply(dctx, false);
                break;
            case SSS_NSS_INITGR:
                ret = nss_cmd_initgr_send_reply(dctx);
                break;
            case SSS_NSS_GETPWUID:
                ret = nss_cmd_getpw_send_reply(dctx, true);
                break;
            case SSS_NSS_GETGRGID:
                ret = nss_cmd_getgr_send_reply(dctx, true);
                break;
            case SSS_NSS_GETNAMEBYSID:
            case SSS_NSS_GETIDBYSID:
            case SSS_NSS_GETSIDBYNAME:
            case SSS_NSS_GETORIGBYNAME:
            case SSS_NSS_GETSIDBYID:
                ret = nss_cmd_getbysid_send_reply(dctx);
                break;
            default:
                DEBUG(SSSDBG_CRIT_FAILURE, "Invalid command [%d][%s].\n",
                      dctx->cmdctx->cmd, sss_cmd2str(dctx->cmdctx->cmd));
                ret = EINVAL;
            }
            goto done;
        }

        /* Since subdomain users and groups are fully qualified they are
         * typically not subject of multi-domain searches. But since POSIX
         * ID do not contain a domain name we have to descend to subdomains
         * here. */
        switch (dctx->cmdctx->cmd) {
        case SSS_NSS_GETPWUID:
            ret = sss_ncache_set_uid(nctx->rctx->ncache, false, dctx->domain,
                                     cmdctx->id);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Cannot set negative cache for UID %"PRIu32"\n",
                      cmdctx->id);
            }
            gnd_flags = SSS_GND_DESCEND;
            break;
        case SSS_NSS_GETGRGID:
            ret = sss_ncache_set_gid(nctx->rctx->ncache, false, dctx->domain,
                                     cmdctx->id);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Cannot set negative cache for GID %"PRIu32"\n",
                      cmdctx->id);
            }
            gnd_flags = SSS_GND_DESCEND;
            break;
        case SSS_NSS_GETSIDBYID:
            ret = sss_ncache_set_uid(nctx->rctx->ncache, false, dctx->domain,
                                     cmdctx->id);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Cannot set negative cache for UID %"PRIu32"\n",
                       cmdctx->id);
            }
            ret = sss_ncache_set_gid(nctx->rctx->ncache, false, dctx->domain,
                                     cmdctx->id);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Cannot set negative cache for GID %"PRIu32"\n",
                      cmdctx->id);
            }
            gnd_flags = SSS_GND_DESCEND;
            break;
        default:
            /* Do not descend to subdomains */
            gnd_flags = 0;
        }

        /* no previous results, just loop to next domain if possible */
        if (cmdctx->check_next &&
            get_next_domain(dctx->domain, gnd_flags)) {
            dctx->domain = get_next_domain(dctx->domain, gnd_flags);
            dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
        } else {
            /* nothing available */
            ret = ENOENT;
            goto done;
        }
    }

    /* ok the backend returned, search to see if we have updated results */
    switch (dctx->cmdctx->cmd) {
    case SSS_NSS_GETPWNAM:
        ret = nss_cmd_getpwnam_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_getpw_send_reply(dctx, false);
        }
        break;
    case SSS_NSS_GETGRNAM:
        ret = nss_cmd_getgrnam_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_getgr_send_reply(dctx, false);
        }
        break;
    case SSS_NSS_INITGR:
        ret = nss_cmd_initgroups_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_initgr_send_reply(dctx);
        }
        break;
    case SSS_NSS_GETPWUID:
        ret = nss_cmd_getpwuid_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_getpw_send_reply(dctx, true);
        }
        break;
    case SSS_NSS_GETGRGID:
        ret = nss_cmd_getgrgid_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_getgr_send_reply(dctx, true);
        }
        break;
    case SSS_NSS_GETNAMEBYSID:
    case SSS_NSS_GETIDBYSID:
        ret = nss_cmd_getbysid_search(dctx);
        if (ret == EOK) {
            ret = nss_cmd_getbysid_send_reply(dctx);
        }
        break;
    case SSS_NSS_GETSIDBYNAME:
    case SSS_NSS_GETORIGBYNAME:
        ret = nss_cmd_getsidby_search(dctx);
        if (ret == EOK) {
            ret = nss_cmd_getbysid_send_reply(dctx);
        }
        break;
    case SSS_NSS_GETSIDBYID:
        ret = nss_cmd_getsidby_search(dctx);
        if (ret == EOK) {
            ret = nss_cmd_getbysid_send_reply(dctx);
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid command [%d][%s].\n",
              dctx->cmdctx->cmd, sss_cmd2str(dctx->cmdctx->cmd));
        ret = EINVAL;
    }

done:
    if (ret == ENOENT
        && (dctx->cmdctx->cmd == SSS_NSS_GETPWNAM
                || dctx->cmdctx->cmd == SSS_NSS_INITGR)
        && dctx->rawname != NULL && strchr(dctx->rawname, '@') != NULL) {
        /* assume Kerberos principal */
        ret = nss_cmd_assume_upn(dctx);
    }

    ret = nss_cmd_done(cmdctx, ret);
    if (ret) {
        NSS_CMD_FATAL_ERROR(cctx);
    }
}

static int nss_check_name_of_well_known_sid(struct nss_cmd_ctx *cmdctx,
                                            const char *full_name)
{
    char *wk_name = NULL;
    char *wk_dom_name = NULL;
    const char *wk_sid;
    int ret;
    struct sized_string sid;
    uint8_t *body;
    size_t blen;
    struct cli_protocol *pctx;
    size_t pctr = 0;

    ret = sss_parse_name(cmdctx, cmdctx->cctx->rctx->global_names, full_name,
                         &wk_dom_name, &wk_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_parse_name failed.\n");
        return ret;
    }

    if (wk_dom_name == NULL || wk_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to split [%s] in name and domain part. " \
              "Skipping check for well-known name.\n", full_name);

        return ENOENT;
    }

    ret = name_to_well_known_sid(wk_dom_name, wk_name, &wk_sid);
    talloc_free(wk_dom_name);
    talloc_free(wk_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_ALL, "Name [%s] is not the name of a " \
                                 "Well-Known SID.\n", full_name);
        return ret;
    }

    to_sized_string(&sid, wk_sid);

    pctx = talloc_get_type(cmdctx->cctx->protocol_ctx, struct cli_protocol);
    ret = sss_packet_new(pctx->creq, sid.len + 3 * sizeof(uint32_t),
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        return ENOMEM;
    }

    sss_packet_get_body(pctx->creq->out, &body, &blen);
    SAFEALIGN_SETMEM_UINT32(body, 1, &pctr);  /* num results */
    SAFEALIGN_SETMEM_UINT32(body + pctr, 0, &pctr); /* reserved */
    SAFEALIGN_SETMEM_UINT32(body + pctr, SSS_ID_TYPE_GID, &pctr);
    memcpy(&body[pctr], sid.str, sid.len);

    sss_packet_set_error(pctx->creq->out, EOK);
    sss_cmd_done(cmdctx->cctx, cmdctx);
    return EOK;
}

static int nss_cmd_getbynam(enum sss_cli_command cmd, struct cli_ctx *cctx);
static void nss_cmd_getbynam_done(struct tevent_req *req);
static int nss_cmd_getpwnam(struct cli_ctx *cctx)
{
    return nss_cmd_getbynam(SSS_NSS_GETPWNAM, cctx);
}

static int nss_cmd_getbynam(enum sss_cli_command cmd, struct cli_ctx *cctx)
{

    struct tevent_req *req;
    struct cli_protocol *pctx;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    const char *rawname;
    char *domname;
    uint8_t *body;
    size_t blen;
    int ret;

    switch(cmd) {
    case SSS_NSS_GETPWNAM:
    case SSS_NSS_GETGRNAM:
    case SSS_NSS_INITGR:
    case SSS_NSS_GETSIDBYNAME:
    case SSS_NSS_GETORIGBYNAME:
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid command type [%d][%s].\n",
              cmd, sss_cmd2str(cmd));
        return EINVAL;
    }

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;
    cmdctx->cmd = cmd;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmdctx = cmdctx;

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);

    /* get user name to query */
    sss_packet_get_body(pctx->creq->in, &body, &blen);

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
    dctx->mc_name = rawname;
    dctx->rawname = rawname;

    DEBUG(SSSDBG_TRACE_FUNC, "Running command [%d][%s] with input [%s].\n",
          cmd, sss_cmd2str(dctx->cmdctx->cmd), rawname);

    if (dctx->cmdctx->cmd == SSS_NSS_GETSIDBYNAME) {
        ret = nss_check_name_of_well_known_sid(cmdctx, rawname);
        if (ret != ENOENT) {
            if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_ALL, "Name [%s] is the name of a " \
                                         "Well-Known SID.\n", rawname);
            } else {
                DEBUG(SSSDBG_OP_FAILURE,
                      "nss_check_name_of_well_known_sid failed.\n");
            }
            goto done;
        }
    }

    /* We need to attach to subdomain request, if the first one is not
     * finished yet. We may not be able to lookup object in AD otherwise. */
    if (cctx->rctx->get_domains_last_call.tv_sec == 0) {
        req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, true, NULL);
        if (req == NULL) {
            ret = ENOMEM;
        } else {
            tevent_req_set_callback(req, nss_cmd_getbynam_done, dctx);
            ret = EAGAIN;
        }
        goto done;
    }

    domname = NULL;
    ret = sss_parse_name_for_domains(cmdctx, cctx->rctx->domains,
                                     cctx->rctx->default_domain, rawname,
                                     &domname, &cmdctx->name);
    if (ret == EAGAIN) {
        req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, true, domname);
        if (req == NULL) {
            ret = ENOMEM;
        } else {
            tevent_req_set_callback(req, nss_cmd_getbynam_done, dctx);
            ret = EAGAIN;
        }
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Invalid name received [%s]\n", rawname);
        ret = ENOENT;
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Requesting info for [%s] from [%s]\n",
              cmdctx->name, domname?domname:"<ALL>");

    if (domname) {
        dctx->domain = responder_get_domain(cctx->rctx, domname);
        if (!dctx->domain) {
            ret = ENOENT;
            goto done;
        }
    } else {
        /* this is a multidomain search */
        dctx->domain = cctx->rctx->domains;
        cmdctx->check_next = true;
        if (cctx->rctx->get_domains_last_call.tv_sec == 0) {
            req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, false, NULL);
            if (req == NULL) {
                ret = ENOMEM;
            } else {
                tevent_req_set_callback(req, nss_cmd_getbynam_done, dctx);
                ret = EAGAIN;
            }
            goto done;
        }
    }

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    /* ok, find it ! */
    switch (dctx->cmdctx->cmd) {
    case SSS_NSS_GETPWNAM:
        ret = nss_cmd_getpwnam_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_getpw_send_reply(dctx, false);
        } else if (ret == ENOENT
                && dctx->rawname != NULL
                && strchr(dctx->rawname, '@') != NULL) {
            /* assume Kerberos principal */
            ret = nss_cmd_assume_upn(dctx);
        }
        break;
    case SSS_NSS_GETGRNAM:
        ret = nss_cmd_getgrnam_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_getgr_send_reply(dctx, false);
        }
        break;
    case SSS_NSS_INITGR:
        ret = nss_cmd_initgroups_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_initgr_send_reply(dctx);
        } else if (ret == ENOENT
                && dctx->rawname != NULL
                && strchr(dctx->rawname, '@') != NULL) {
            /* assume Kerberos principal */
            ret = nss_cmd_assume_upn(dctx);
        }
        break;
    case SSS_NSS_GETSIDBYNAME:
    case SSS_NSS_GETORIGBYNAME:
        ret = nss_cmd_getsidby_search(dctx);
        if (ret == EOK) {
            ret = nss_cmd_getbysid_send_reply(dctx);
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid command [%d][%s].\n",
              dctx->cmdctx->cmd, sss_cmd2str(dctx->cmdctx->cmd));
        ret = EINVAL;
    }

done:
    return nss_cmd_done(cmdctx, ret);
}

static void nss_cmd_getbynam_done(struct tevent_req *req)
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

    ret = sss_parse_name_for_domains(cmdctx, cctx->rctx->domains,
                                     cctx->rctx->default_domain, rawname,
                                     &domname, &cmdctx->name);
    if (ret == EAGAIN && (dctx->cmdctx->cmd == SSS_NSS_GETPWNAM
                            || dctx->cmdctx->cmd == SSS_NSS_GETSIDBYNAME
                            || dctx->cmdctx->cmd == SSS_NSS_GETORIGBYNAME
                            || dctx->cmdctx->cmd == SSS_NSS_INITGR)) {
        /* assume Kerberos principal */
        ret = nss_cmd_assume_upn(dctx);
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Invalid name received [%s]\n", rawname);
        ret = ENOENT;
        goto done;
    }

    ret = nss_reset_negcache(cctx->rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot reset negcache records\n");
        /* Not fatal */
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Requesting info for [%s] from [%s]\n",
              cmdctx->name, domname?domname:"<ALL>");

    if (domname) {
        dctx->domain = responder_get_domain(cctx->rctx, domname);
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
    switch (dctx->cmdctx->cmd) {
    case SSS_NSS_GETPWNAM:
        ret = nss_cmd_getpwnam_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_getpw_send_reply(dctx, false);
        } else if (ret == ENOENT
                    && dctx->rawname != NULL
                    && strchr(dctx->rawname, '@') != NULL) {
            /* assume Kerberos principal */
            ret = nss_cmd_assume_upn(dctx);
        }
        break;
    case SSS_NSS_GETGRNAM:
        ret = nss_cmd_getgrnam_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_getgr_send_reply(dctx, false);
        }
        break;
    case SSS_NSS_INITGR:
        ret = nss_cmd_initgroups_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_initgr_send_reply(dctx);
        } else if (ret == ENOENT
                    && dctx->rawname != NULL
                    && strchr(dctx->rawname, '@') != NULL) {
            /* assume Kerberos principal */
            ret = nss_cmd_assume_upn(dctx);
        }
        break;
    case SSS_NSS_GETSIDBYNAME:
    case SSS_NSS_GETORIGBYNAME:
        ret = nss_cmd_getsidby_search(dctx);
        if (ret == EOK) {
            ret = nss_cmd_getbysid_send_reply(dctx);
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid command [%d][%s].\n",
              dctx->cmdctx->cmd, sss_cmd2str(dctx->cmdctx->cmd));
        ret = EINVAL;
    }

done:
    nss_cmd_done(cmdctx, ret);
}

/* search for a uid.
 * Returns:
 *   ENOENT, if uid is definitely not found
 *   EAGAIN, if uid is being fetched from backend via async operations
 *   EOK, if found
 *   anything else on a fatal error
 */

static int nss_cmd_getpwuid_search(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct sss_domain_info *dom = dctx->domain;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct nss_ctx *nctx;
    int ret;
    int err;
    const char *extra_flag = NULL;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    while (dom) {

        /* check that the uid is valid for this domain */
        if ((dom->id_min && (cmdctx->id < dom->id_min)) ||
            (dom->id_max && (cmdctx->id > dom->id_max))) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Uid [%"PRIu32"] does not exist in domain [%s]! "
                      "(id out of range)\n",
                      cmdctx->id, dom->name);
            if (cmdctx->check_next) {
                dom = get_next_domain(dom, SSS_GND_DESCEND);
                continue;
            }
            ret = ENOENT;
            goto done;
        }

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        DEBUG(SSSDBG_CONF_SETTINGS,
              "Requesting info for [%"PRIu32"@%s]\n", cmdctx->id, dom->name);

        if (dom->sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Fatal: Sysdb CTX not found for this domain!\n");
            ret = EIO;
            goto done;
        }

        ret = sysdb_getpwuid_with_views(cmdctx, dom, cmdctx->id, &dctx->res);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to make request to our cache!\n");
            ret = EIO;
            goto done;
        }

        if (dctx->res->count > 1) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "getpwuid call returned more than one result !?!\n");
            sss_log(SSS_LOG_ERR,
                    "More users have the same UID [%"PRIu32"] in directory "
                    "server. SSSD will not work correctly.\n", cmdctx->id);
            ret = ENOENT;
            goto done;
        }

        if (dctx->res->count == 0 && !dctx->check_provider) {
            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = get_next_domain(dom, SSS_GND_DESCEND);
                continue;
            }

            /* set negative cache only if not result of cache check */
            DEBUG(SSSDBG_MINOR_FAILURE, "No results for getpwuid call\n");
            ret = ENOENT;
            goto done;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (dctx->check_provider) {

            if (DOM_HAS_VIEWS(dom) && (dctx->res->count == 0
                    || ldb_msg_find_attr_as_uint64(dctx->res->msgs[0],
                                                   OVERRIDE_PREFIX SYSDB_UIDNUM,
                                                   0) != 0)) {
                extra_flag = EXTRA_INPUT_MAYBE_WITH_VIEW;
            } else {
                extra_flag = NULL;
            }

            ret = check_cache(dctx, nctx, dctx->res, SSS_DP_USER, NULL,
                              cmdctx->id, extra_flag, nss_cmd_getby_dp_callback,
                              dctx);
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                goto done;
            }
        }

        /* One result found */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Returning info for uid [%"PRIu32"@%s]\n", cmdctx->id, dom->name);

        ret = EOK;
        goto done;
    }

    /* All domains were tried and none had the entry. */
    ret = ENOENT;
done:
    if (ret == ENOENT) {
        /* The entry was not found, need to set result in negative cache */
        err = sss_ncache_set_uid(nctx->rctx->ncache, false, NULL, cmdctx->id);
        if (err != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                "Cannot set negative cache for UID %"PRIu32"\n", cmdctx->id);
        }
        DEBUG(SSSDBG_MINOR_FAILURE,
              "No matching domain found for [%"PRIu32"]\n", cmdctx->id);
    }

    return ret;
}

static int nss_cmd_getgrgid_search(struct nss_dom_ctx *dctx);
static int nss_cmd_getbyid(enum sss_cli_command cmd, struct cli_ctx *cctx);
static void nss_cmd_getbyid_done(struct tevent_req *req);
static int nss_cmd_getpwuid(struct cli_ctx *cctx)
{
    return nss_cmd_getbyid(SSS_NSS_GETPWUID, cctx);
}

static int nss_cmd_getbyid(enum sss_cli_command cmd, struct cli_ctx *cctx)
{
    struct cli_protocol *pctx;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    struct nss_ctx *nctx;
    uint8_t *body;
    size_t blen;
    int ret;
    struct tevent_req *req;

    switch (cmd) {
    case SSS_NSS_GETPWUID:
    case SSS_NSS_GETGRGID:
    case SSS_NSS_GETSIDBYID:
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid command type [%d][%s].\n",
              cmd, sss_cmd2str(cmd));
        return EINVAL;
    }

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;
    cmdctx->cmd = cmd;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmdctx = cmdctx;

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);

    /* get id to query */
    sss_packet_get_body(pctx->creq->in, &body, &blen);

    if (blen != sizeof(uint32_t)) {
        ret = EINVAL;
        goto done;
    }
    SAFEALIGN_COPY_UINT32(&cmdctx->id, body, NULL);

    DEBUG(SSSDBG_TRACE_FUNC, "Running command [%d][%s] with id [%"PRIu32"].\n",
          dctx->cmdctx->cmd, sss_cmd2str(dctx->cmdctx->cmd), cmdctx->id);

    switch(dctx->cmdctx->cmd) {
    case SSS_NSS_GETPWUID:
        ret = sss_ncache_check_uid(nctx->rctx->ncache, NULL, cmdctx->id);
        if (ret == EEXIST) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Uid [%"PRIu32"] does not exist! (negative cache)\n",
                   cmdctx->id);
            ret = ENOENT;
            goto done;
        }
        break;
    case SSS_NSS_GETGRGID:
        ret = sss_ncache_check_gid(nctx->rctx->ncache, NULL, cmdctx->id);
        if (ret == EEXIST) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Gid [%"PRIu32"] does not exist! (negative cache)\n",
                   cmdctx->id);
            ret = ENOENT;
            goto done;
        }
        break;
    case SSS_NSS_GETSIDBYID:
        ret = sss_ncache_check_uid(nctx->rctx->ncache, NULL, cmdctx->id);
        if (ret != EEXIST) {
            ret = sss_ncache_check_gid(nctx->rctx->ncache, NULL, cmdctx->id);
        }
        if (ret == EEXIST) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Id [%"PRIu32"] does not exist! (negative cache)\n",
                   cmdctx->id);
            ret = ENOENT;
            goto done;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid command [%d][%s].\n",
              dctx->cmdctx->cmd, sss_cmd2str(dctx->cmdctx->cmd));
        ret = EINVAL;
        goto done;
    }

    /* id searches are always multidomain */
    dctx->domain = cctx->rctx->domains;
    cmdctx->check_next = true;

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    if (cctx->rctx->get_domains_last_call.tv_sec == 0) {
        req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, false, NULL);
        if (req == NULL) {
            ret = ENOMEM;
        } else {
            tevent_req_set_callback(req, nss_cmd_getbyid_done, dctx);
            ret = EAGAIN;
        }
        goto done;
    }

    /* ok, find it ! */
    switch(dctx->cmdctx->cmd) {
    case SSS_NSS_GETPWUID:
        ret = nss_cmd_getpwuid_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_getpw_send_reply(dctx, true);
        }
        break;
    case SSS_NSS_GETGRGID:
        ret = nss_cmd_getgrgid_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_getgr_send_reply(dctx, true);
        }
        break;
    case SSS_NSS_GETSIDBYID:
        ret = nss_cmd_getsidby_search(dctx);
        if (ret == EOK) {
            ret = nss_cmd_getbysid_send_reply(dctx);
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid command [%d][%s].\n",
              dctx->cmdctx->cmd, sss_cmd2str(dctx->cmdctx->cmd));
        ret = EINVAL;
    }

done:
    return nss_cmd_done(cmdctx, ret);
}

static void nss_cmd_getbyid_done(struct tevent_req *req)
{
    struct nss_dom_ctx *dctx = tevent_req_callback_data(req, struct nss_dom_ctx);
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    errno_t ret;

    ret = sss_dp_get_domains_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        goto done;
    }

    ret = nss_reset_negcache(cmdctx->cctx->rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot reset negcache records\n");
        /* Not fatal */
    }

    /* ok, find it ! */
    switch(dctx->cmdctx->cmd) {
    case SSS_NSS_GETPWUID:
        ret = nss_cmd_getpwuid_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_getpw_send_reply(dctx, true);
        }
        break;
    case SSS_NSS_GETGRGID:
        ret = nss_cmd_getgrgid_search(dctx);
        if (ret == EOK) {
            /* we have results to return */
            ret = nss_cmd_getgr_send_reply(dctx, true);
        }
        break;
    case SSS_NSS_GETNAMEBYSID:
    case SSS_NSS_GETIDBYSID:
        ret = responder_get_domain_by_id(cmdctx->cctx->rctx, cmdctx->secid,
                                         &dctx->domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot find domain for SID [%s].\n",
                                      cmdctx->secid);
            ret = ENOENT;
            goto done;
        }

        dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

        ret = nss_cmd_getbysid_search(dctx);
        if (ret == EOK) {
            ret = nss_cmd_getbysid_send_reply(dctx);
        }
        break;
    case SSS_NSS_GETSIDBYID:
        ret = nss_cmd_getsidby_search(dctx);
        if (ret == EOK) {
            ret = nss_cmd_getbysid_send_reply(dctx);
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid command [%d][%s].\n",
              dctx->cmdctx->cmd, sss_cmd2str(dctx->cmdctx->cmd));
        ret = EINVAL;
    }

done:
    nss_cmd_done(cmdctx, ret);
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
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Fatal error calling nss_cmd_setpwent_send\n");
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
    struct nss_state_ctx *state_ctx;
    struct tevent_req *req;
    struct setent_ctx *state;
    struct sss_domain_info *dom;
    struct setent_step_ctx *step_ctx;

    DEBUG(SSSDBG_CONF_SETTINGS, "Received setpwent request\n");
    nctx = talloc_get_type(client->rctx->pvt_ctx, struct nss_ctx);
    state_ctx = talloc_get_type(client->state_ctx, struct nss_state_ctx);

    /* Reset the read pointers */
    state_ctx->pwent.dom_idx = 0;
    state_ctx->pwent.cur = 0;

    req = tevent_req_create(mem_ctx, &state, struct setent_ctx);
    if (!req) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not create tevent request for setpwent\n");
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
    for (dom = client->rctx->domains; dom;
            dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        if (dom->enumerate == true) break;
    }
    state->dctx->domain = dom;

    if (state->dctx->domain == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Enumeration disabled on all domains!\n");
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
    struct ldb_result *res;
    struct timeval tv;
    struct tevent_timer *te;
    struct tevent_req *dpreq;
    struct dp_callback_ctx *cb_ctx;

    while (dom) {
        while (dom && dom->enumerate == false) {
            dom = get_next_domain(dom, SSS_GND_DESCEND);
        }

        if (!dom) break;

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        DEBUG(SSSDBG_TRACE_FUNC,
              "Requesting info for domain [%s]\n", dom->name);

        if (dom->sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Fatal: Sysdb CTX not found for this domain!\n");
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
                      "Enum Cache refresh for domain [%s] failed."
                       " Trying to return what we have in cache!\n",
                       dom->name);
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

        ret = sysdb_enumpwent_with_views(dctx, dom, &res);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Enum from cache failed, skipping domain [%s]\n",
                      dom->name);
            dom = get_next_domain(dom, SSS_GND_DESCEND);
            continue;
        }

        if (res->count == 0) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Domain [%s] has no users, skipping.\n", dom->name);
            dom = get_next_domain(dom, SSS_GND_DESCEND);
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
        dom = get_next_domain(dom, SSS_GND_DESCEND);
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
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not set up life timer for setpwent result object. "
                  "Entries may become stale.\n");
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

    DEBUG(SSSDBG_CRIT_FAILURE,
          "setpwent result object has expired. Cleaning up.\n");

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
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg);
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
    struct cli_protocol *pctx;
    errno_t ret;
    struct nss_cmd_ctx *cmdctx =
            tevent_req_callback_data(req, struct nss_cmd_ctx);

    pctx = talloc_get_type(cmdctx->cctx->protocol_ctx, struct cli_protocol);
    ret = nss_cmd_setpwent_recv(req);
    talloc_zfree(req);
    if (ret == EOK || ret == ENOENT) {
        /* Either we succeeded or no domains were eligible */
        ret = sss_packet_new(pctx->creq, 0,
                             sss_packet_get_cmd(pctx->creq->in),
                             &pctx->creq->out);
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
    struct nss_state_ctx *state_ctx;
    struct nss_cmd_ctx *cmdctx;
    struct tevent_req *req;

    DEBUG(SSSDBG_CONF_SETTINGS, "Requesting info for all accounts\n");

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;
    state_ctx = talloc_get_type(cctx->state_ctx, struct nss_state_ctx);

    /* Save the current index and cursor locations
     * If we end up calling setpwent implicitly, because the response object
     * expired and has to be recreated, we want to resume from the same
     * location.
     */
    cmdctx->saved_dom_idx = state_ctx->pwent.dom_idx;
    cmdctx->saved_cur = state_ctx->pwent.cur;

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
    struct cli_protocol *pctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    int ret;

    pctx = talloc_get_type(cmdctx->cctx->protocol_ctx, struct cli_protocol);

    /* get max num of entries to return in one call */
    sss_packet_get_body(pctx->creq->in, &body, &blen);
    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }
    SAFEALIGN_COPY_UINT32(&num, body, NULL);

    /* create response packet */
    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    ret = nss_cmd_retpwent(cmdctx->cctx, num);

    sss_packet_set_error(pctx->creq->out, ret);
    sss_cmd_done(cmdctx->cctx, cmdctx);

    return EOK;
}

static int nss_cmd_retpwent(struct cli_ctx *cctx, int num)
{
    struct cli_protocol *pctx;
    struct nss_state_ctx *state_ctx;
    struct nss_ctx *nctx;
    struct getent_ctx *gctx;
    struct ldb_message **msgs = NULL;
    struct dom_ctx *pdom = NULL;
    int n = 0;
    int ret = ENOENT;

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);
    state_ctx = talloc_get_type(cctx->state_ctx, struct nss_state_ctx);
    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    if (!nctx->pctx) goto none;

    gctx = nctx->pctx;

    while (ret == ENOENT) {
        if (state_ctx->pwent.dom_idx >= gctx->num) break;

        pdom = &gctx->doms[state_ctx->pwent.dom_idx];

        n = pdom->res->count - state_ctx->pwent.cur;
        if (n <= 0 && (state_ctx->pwent.dom_idx+1 < gctx->num)) {
            state_ctx->pwent.dom_idx++;
            pdom = &gctx->doms[state_ctx->pwent.dom_idx];
            n = pdom->res->count;
            state_ctx->pwent.cur = 0;
        }

        if (!n) break;

        if (n < 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "BUG: Negative difference[%d - %d = %d]\n",
                  pdom->res->count, state_ctx->pwent.cur, n);
            DEBUG(SSSDBG_CRIT_FAILURE, "Domain: %d (total %d)\n",
                                        state_ctx->pwent.dom_idx, gctx->num);
            break;
        }

        if (n > num) n = num;

        msgs = &(pdom->res->msgs[state_ctx->pwent.cur]);

        ret = fill_pwent(pctx->creq->out, pdom->domain, nctx,
                         true, false, msgs, &n);

        state_ctx->pwent.cur += n;
    }

none:
    if (ret == ENOENT) {
        ret = sss_cmd_empty_packet(pctx->creq->out);
    }
    return ret;
}

static void nss_cmd_implicit_setpwent_done(struct tevent_req *req)
{
    errno_t ret;
    struct nss_cmd_ctx *cmdctx =
            tevent_req_callback_data(req, struct nss_cmd_ctx);
    struct nss_state_ctx *state_ctx;
    ret = nss_cmd_setpwent_recv(req);
    talloc_zfree(req);

    /* ENOENT is acceptable, as it just means that there were no entries
     * to be returned. This will be handled gracefully in nss_cmd_retpwent
     * later.
     */
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Implicit setpwent failed with unexpected error [%d][%s]\n",
                  ret, strerror(ret));
        NSS_CMD_FATAL_ERROR(cmdctx);
    }

    /* Restore the saved index and cursor locations */
    state_ctx = talloc_get_type(cmdctx->cctx->state_ctx, struct nss_state_ctx);
    state_ctx->pwent.dom_idx = cmdctx->saved_dom_idx;
    state_ctx->pwent.cur = cmdctx->saved_cur;

    ret = nss_cmd_getpwent_immediate(cmdctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Immediate retrieval failed with unexpected error "
                  "[%d][%s]\n", ret, strerror(ret));
        NSS_CMD_FATAL_ERROR(cmdctx);
    }
}

static int nss_cmd_endpwent(struct cli_ctx *cctx)
{
    struct cli_protocol *pctx;
    struct nss_state_ctx *state_ctx;
    struct nss_ctx *nctx;
    int ret;

    DEBUG(SSSDBG_CONF_SETTINGS, "Terminating request info for all accounts\n");

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);
    state_ctx = talloc_get_type(cctx->state_ctx, struct nss_state_ctx);
    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    /* create response packet */
    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);

    if (ret != EOK) {
        return ret;
    }
    if (nctx->pctx == NULL) goto done;

    /* Reset the indices so that subsequent requests start at zero */
    state_ctx->pwent.dom_idx = 0;
    state_ctx->pwent.cur = 0;

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
                        struct resp_ctx *rctx,
                        struct sss_domain_info *dom,
                        struct nss_ctx *nctx,
                        struct ldb_message_element *el,
                        size_t *_rzero,
                        size_t *_rsize,
                        int *_memnum)
{
    int ret = EOK;
    int memnum = *_memnum;
    size_t rzero= *_rzero;
    size_t rsize = *_rsize;
    struct sized_string *name;
    TALLOC_CTX *tmp_ctx = NULL;

    const char *fqname;
    uint8_t *body;
    size_t blen;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    sss_packet_get_body(packet, &body, &blen);
    for (unsigned i = 0; i < el->num_values; i++) {
        fqname = (const char *)el->values[i].data;

        if (nctx->filter_users_in_groups) {
            ret = sss_ncache_check_user(nctx->rctx->ncache, dom, fqname);
            if (ret == EEXIST) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "Group [%s] member [%s] filtered out!"
                       " (negative cache)\n",
                       (char *)&body[rzero+STRS_ROFFSET], fqname);
                continue;
            }
        }

        ret = sized_member_name(tmp_ctx, rctx, fqname, &name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sized_member_name failed: %d\n", ret);
            goto done;
        }

        ret = sss_packet_grow(packet, name->len);
        if (ret != EOK) {
            goto done;
        }
        sss_packet_get_body(packet, &body, &blen);

        memcpy(&body[rzero + rsize], name->str, name->len);
        rsize += name->len;
        memnum++;
    }

    ret = 0;

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
    const char *orig_name = NULL;
    struct sized_string *name;
    struct sized_string pwfield;
    int i = 0;
    int ret, num, memnum;
    size_t rzero, rsize;
    const char *domain = dom->name;
    TALLOC_CTX *tmp_ctx = NULL;

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
            DEBUG(SSSDBG_CRIT_FAILURE, "Wrong object (%s) found on stack!\n",
                      ldb_dn_get_linearized(msg->dn));
            continue;
        }

        /* new result starts at end of previous result */
        rzero += rsize;
        rsize = 0;

        /* find group name/gid */

        /* start with an empty name for each iteration */
        orig_name = NULL;
        if (DOM_HAS_VIEWS(dom)) {
            orig_name = ldb_msg_find_attr_as_string(msg,
                                                    OVERRIDE_PREFIX SYSDB_NAME,
                                                    NULL);
        }
        if (orig_name == NULL) {
            orig_name = ldb_msg_find_attr_as_string(msg,
                                                    SYSDB_DEFAULT_OVERRIDE_NAME,
                                                    NULL);
            if (orig_name == NULL) {
                orig_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
            }
        }

        gid = sss_view_ldb_msg_find_attr_as_uint64(dom, msg, SYSDB_GIDNUM, 0);
        if (!orig_name || !gid) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Incomplete group object for %s[%llu]! Skipping\n",
                      orig_name?orig_name:"<NULL>", (unsigned long long int)gid);
            continue;
        }

        if (filter_groups) {
            ret = sss_ncache_check_group(nctx->rctx->ncache, dom, orig_name);
            if (ret == EEXIST) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "Group [%s] filtered out! (negative cache)\n", orig_name);
                continue;
            }
        }

        ret = sized_output_name(tmp_ctx, nctx->rctx, orig_name, dom, &name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sized_output_name failed, skipping\n");
            continue;
        }

        /* fill in gid and name and set pointer for number of members */
        rsize = STRS_ROFFSET + name->len + pwfield.len; /* name\0x\0 */

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
        memcpy(&body[rzero+STRS_ROFFSET], name->str, name->len);

        /* group passwd field */
        memcpy(&body[rzero+STRS_ROFFSET + name->len],
                                            pwfield.str, pwfield.len);

        memnum = 0;
        if (!dom->ignore_group_members) {
            /* unconditionally prefer OVERRIDE_PREFIX SYSDB_MEMBERUID, it
             * might contain override names from the default view */
            el = ldb_msg_find_element(msg, OVERRIDE_PREFIX SYSDB_MEMBERUID);
            if (el == NULL) {
                el = ldb_msg_find_element(msg, SYSDB_MEMBERUID);
            }
            if (el) {
                ret = fill_members(packet, nctx->rctx, dom, nctx, el,
                                   &rzero, &rsize, &memnum);
                if (ret != EOK) {
                    num = 0;
                    goto done;
                }
                sss_packet_get_body(packet, &body, &blen);
            }
            el = ldb_msg_find_element(msg, SYSDB_GHOST);
            if (el) {
                if (DOM_HAS_VIEWS(dom) && !is_local_view(dom->view_name)
                        && el->num_values != 0) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Domain has a view [%s] but group [%s] still has " \
                          "ghost members.\n", dom->view_name, orig_name);
                    num = 0;
                    goto done;
                }
                ret = fill_members(packet, nctx->rctx, dom, nctx, el,
                                   &rzero, &rsize, &memnum);
                if (ret != EOK) {
                    num = 0;
                    goto done;
                }
                sss_packet_get_body(packet, &body, &blen);
            }
        }
        if (memnum) {
            /* set num of members */
            SAFEALIGN_SET_UINT32(&body[rzero+MNUM_ROFFSET], memnum, NULL);
        }

        num++;

        if (gr_mmap_cache && nctx->grp_mc_ctx) {
            /* body was reallocated, so fullname might be pointing to
             * where body used to be, not where it is */
            ret = sss_mmap_cache_gr_store(&nctx->grp_mc_ctx,
                                          name, &pwfield, gid, memnum,
                                          (char *)&body[rzero] + STRS_ROFFSET +
                                            name->len + pwfield.len,
                                          rsize - STRS_ROFFSET -
                                            name->len - pwfield.len);
            if (ret != EOK && ret != ENOMEM) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to store group %s(%s) in mmap cache!\n",
                      name->str, domain);
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

    SAFEALIGN_COPY_UINT32(body, &num, NULL); /* num results */
    SAFEALIGN_SETMEM_UINT32(body + sizeof(uint32_t), 0, NULL); /* reserved */

    return EOK;
}

static int nss_cmd_getgr_send_reply(struct nss_dom_ctx *dctx, bool filter)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_protocol *pctx;
    struct nss_ctx *nctx;
    int ret;
    int i;

    pctx = talloc_get_type(cmdctx->cctx->protocol_ctx, struct cli_protocol);
    nctx = talloc_get_type(cmdctx->cctx->rctx->pvt_ctx, struct nss_ctx);

    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        return EFAULT;
    }
    i = dctx->res->count;
    ret = fill_grent(pctx->creq->out,
                     dctx->domain,
                     nctx, filter, true,
                     dctx->res->msgs, &i);
    if (ret) {
        return ret;
    }
    sss_packet_set_error(pctx->creq->out, EOK);
    sss_cmd_done(cmdctx->cctx, cmdctx);
    return EOK;
}

/* search for a group.
 * Returns:
 *   ENOENT, if group is definitely not found
 *   EAGAIN, if group is being fetched from backend via async operations
 *   EOK, if found
 *   anything else on a fatal error
 */

static int nss_cmd_getgrnam_search(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct sss_domain_info *dom = dctx->domain;
    struct cli_ctx *cctx = cmdctx->cctx;
    char *name = NULL;
    struct nss_ctx *nctx;
    int ret;
    const char *extra_flag = NULL;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    while (dom) {
       /* if it is a domainless search, skip domains that require fully
         * qualified names instead */
        while (dom && cmdctx->check_next && dom->fqnames) {
            dom = get_next_domain(dom, 0);
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
        name = sss_resp_create_fqname(dctx, nctx->rctx, dctx->domain,
                                      cmdctx->name_is_upn, cmdctx->name);
        if (name == NULL) {
            return ENOMEM;
        }

        /* verify this group has not yet been negatively cached,
        * or has been permanently filtered */
        ret = sss_ncache_check_group(nctx->rctx->ncache, dom, name);

        /* if neg cached, return we didn't find it */
        if (ret == EEXIST) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Group [%s] does not exist in [%s]! (negative cache)\n",
                   name, dom->name);
            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = get_next_domain(dom, 0);
                continue;
            }
            /* There are no further domains or this was a
             * fully-qualified user request.
             */
            return ENOENT;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Requesting info for [%s]\n", name);

        if (dom->sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Fatal: Sysdb CTX not found for this domain!\n");
            return EIO;
        }

        ret = sysdb_getgrnam_with_views(cmdctx, dom, name, &dctx->res);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to make request to our cache!\n");
            return EIO;
        }

        if (dctx->res->count > 1) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "getgrnam call returned more than one result !?!\n");
            sss_log(SSS_LOG_ERR,
                    "More groups have the same name [%s] in SSSD cache. "
                    "SSSD will not work correctly.\n",
                    name);
            return ENOENT;
        }

        if (dctx->res->count == 0 && !dctx->check_provider) {
            /* set negative cache only if not result of cache check */
            ret = sss_ncache_set_group(nctx->rctx->ncache, false, dom, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Cannot set negcache for %s\n", name);
            }

            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = get_next_domain(dom, 0);
                if (dom) continue;
            }

            DEBUG(SSSDBG_OP_FAILURE, "No results for getgrnam call\n");

            /* Group not found in ldb -> delete group from memory cache. */
            ret = delete_entry_from_memcache(dctx->domain, name, nctx->rctx,
                                             nctx->grp_mc_ctx, SSS_MC_GROUP);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Deleting group from memcache failed.\n");
            }


            return ENOENT;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (dctx->check_provider) {

            if (DOM_HAS_VIEWS(dom) && (dctx->res->count == 0
                    || ldb_msg_find_attr_as_string(dctx->res->msgs[0],
                                                   OVERRIDE_PREFIX SYSDB_NAME,
                                                   NULL) != NULL)) {
                extra_flag = EXTRA_INPUT_MAYBE_WITH_VIEW;
            } else {
                extra_flag = NULL;
            }

            ret = check_cache(dctx, nctx, dctx->res, SSS_DP_GROUP, name, 0,
                              extra_flag, nss_cmd_getby_dp_callback, dctx);
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                return ret;
            }
        }

        /* One result found */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Returning info for group [%s]\n", name);

        return EOK;
    }

    DEBUG(SSSDBG_MINOR_FAILURE,
          "No matching domain found for [%s], fail!\n", cmdctx->name);
    return ENOENT;
}

static int nss_cmd_getgrnam(struct cli_ctx *cctx)
{
    return nss_cmd_getbynam(SSS_NSS_GETGRNAM, cctx);
}

/* search for a gid.
 * Returns:
 *   ENOENT, if gid is definitely not found
 *   EAGAIN, if gid is being fetched from backend via async operations
 *   EOK, if found
 *   anything else on a fatal error
 */

static int nss_cmd_getgrgid_search(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct sss_domain_info *dom = dctx->domain;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct nss_ctx *nctx;
    int ret;
    int err;
    const char *extra_flag = NULL;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    while (dom) {

        /* check that the gid is valid for this domain */
        if ((dom->id_min && (cmdctx->id < dom->id_min)) ||
            (dom->id_max && (cmdctx->id > dom->id_max))) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Gid [%"PRIu32"] does not exist in domain [%s]! "
                      "(id out of range)\n",
                      cmdctx->id, dom->name);
            if (cmdctx->check_next) {
                dom = get_next_domain(dom, SSS_GND_DESCEND);
                continue;
            }
            ret = ENOENT;
            goto done;
        }

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        DEBUG(SSSDBG_CONF_SETTINGS,
              "Requesting info for [%"PRIu32"@%s]\n", cmdctx->id, dom->name);

        if (dom->sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Fatal: Sysdb CTX not found for this domain!\n");
            ret = EIO;
            goto done;
        }

        ret = sysdb_getgrgid_with_views(cmdctx, dom, cmdctx->id, &dctx->res);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to make request to our cache!\n");
            ret = EIO;
            goto done;
        }

        if (dctx->res->count > 1) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "getgrgid call returned more than one result !?!\n");
            sss_log(SSS_LOG_ERR,
                    "More groups have the same GID [%"PRIu32"] in directory "
                    "server. SSSD will not work correctly.\n", cmdctx->id);
            ret = ENOENT;
            goto done;
        }

        if (dctx->res->count == 0 && !dctx->check_provider) {
            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = get_next_domain(dom, SSS_GND_DESCEND);
                continue;
            }

            /* set negative cache only if not result of cache check */
            DEBUG(SSSDBG_MINOR_FAILURE, "No results for getgrgid call\n");
            ret = ENOENT;
            goto done;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (dctx->check_provider) {

            if (DOM_HAS_VIEWS(dom) && (dctx->res->count == 0
                    || ldb_msg_find_attr_as_uint64(dctx->res->msgs[0],
                                                   OVERRIDE_PREFIX SYSDB_GIDNUM,
                                                   0) != 0)) {
                extra_flag = EXTRA_INPUT_MAYBE_WITH_VIEW;
            } else {
                extra_flag = NULL;
            }

            ret = check_cache(dctx, nctx, dctx->res, SSS_DP_GROUP, NULL,
                              cmdctx->id, extra_flag, nss_cmd_getby_dp_callback,
                              dctx);
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                goto done;
            }
        }

        /* One result found */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Returning info for gid [%"PRIu32"@%s]\n", cmdctx->id, dom->name);

        /* Success. Break from the loop and return EOK */
        ret = EOK;
        goto done;
    }

    /* All domains were tried and none had the entry. */
    ret = ENOENT;
done:
    if (ret == ENOENT) {
        /* The entry was not found, need to set result in negative cache */
        err = sss_ncache_set_gid(nctx->rctx->ncache, false, NULL, cmdctx->id);
        if (err != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                "Cannot set negative cache for GID %"PRIu32"\n", cmdctx->id);
        }
        DEBUG(SSSDBG_MINOR_FAILURE,
              "No matching domain found for [%"PRIu32"]\n", cmdctx->id);
    }

    return ret;
}

static int nss_cmd_getgrgid(struct cli_ctx *cctx)
{
    return nss_cmd_getbyid(SSS_NSS_GETGRGID, cctx);
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
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Fatal error calling nss_cmd_setgrent_send\n");
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
    struct nss_state_ctx *state_ctx;
    struct tevent_req *req;
    struct setent_ctx *state;
    struct sss_domain_info *dom;
    struct setent_step_ctx *step_ctx;

    DEBUG(SSSDBG_CONF_SETTINGS, "Received setgrent request\n");
    nctx = talloc_get_type(client->rctx->pvt_ctx, struct nss_ctx);
    state_ctx = talloc_get_type(client->state_ctx, struct nss_state_ctx);

    /* Reset the read pointers */
    state_ctx->grent.dom_idx = 0;
    state_ctx->grent.cur = 0;

    req = tevent_req_create(mem_ctx, &state, struct setent_ctx);
    if (!req) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not create tevent request for setgrent\n");
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
    for (dom = client->rctx->domains; dom;
            dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        if (dom->enumerate == true) break;
    }
    state->dctx->domain = dom;

    if (state->dctx->domain == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Enumeration disabled on all domains!\n");
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
    struct ldb_result *res;
    struct timeval tv;
    struct tevent_timer *te;
    struct tevent_req *dpreq;
    struct dp_callback_ctx *cb_ctx;

    while (dom) {
        while (dom && dom->enumerate == false) {
            dom = get_next_domain(dom, SSS_GND_DESCEND);
        }

        if (!dom) break;

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        DEBUG(SSSDBG_TRACE_FUNC,
              "Requesting info for domain [%s]\n", dom->name);

        if (dom->sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Fatal: Sysdb CTX not found for this domain!\n");
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
                      "Enum Cache refresh for domain [%s] failed."
                       " Trying to return what we have in cache!\n",
                       dom->name);
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

        ret = sysdb_enumgrent_with_views(dctx, dom, &res);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Enum from cache failed, skipping domain [%s]\n",
                      dom->name);
            dom = get_next_domain(dom, SSS_GND_DESCEND);
            continue;
        }

        if (res->count == 0) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Domain [%s] has no groups, skipping.\n", dom->name);
            dom = get_next_domain(dom, SSS_GND_DESCEND);
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
        dom = get_next_domain(dom, SSS_GND_DESCEND);
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
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not set up life timer for setgrent result object. "
                  "Entries may become stale.\n");
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

    DEBUG(SSSDBG_CRIT_FAILURE,
          "setgrent result object has expired. Cleaning up.\n");

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
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg);
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
    struct cli_protocol *pctx;

    pctx = talloc_get_type(cmdctx->cctx->protocol_ctx, struct cli_protocol);
    ret = nss_cmd_setgrent_recv(req);
    talloc_zfree(req);
    if (ret == EOK || ret == ENOENT) {
        /* Either we succeeded or no domains were eligible */
        ret = sss_packet_new(pctx->creq, 0,
                             sss_packet_get_cmd(pctx->creq->in),
                             &pctx->creq->out);
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
    struct cli_protocol *pctx;
    struct nss_state_ctx *state_ctx;
    struct nss_ctx *nctx;
    struct getent_ctx *gctx;
    struct ldb_message **msgs = NULL;
    struct dom_ctx *gdom = NULL;
    int n = 0;
    int ret = ENOENT;

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);
    state_ctx = talloc_get_type(cctx->state_ctx, struct nss_state_ctx);
    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    if (!nctx->gctx) goto none;

    gctx = nctx->gctx;

    while (ret == ENOENT) {
        if (state_ctx->grent.dom_idx >= gctx->num) break;

        gdom = &gctx->doms[state_ctx->grent.dom_idx];

        n = gdom->res->count - state_ctx->grent.cur;
        if (n <= 0 && (state_ctx->grent.dom_idx+1 < gctx->num)) {
            state_ctx->grent.dom_idx++;
            gdom = &gctx->doms[state_ctx->grent.dom_idx];
            n = gdom->res->count;
            state_ctx->grent.cur = 0;
        }

        if (!n) break;

        if (n > num) n = num;

        msgs = &(gdom->res->msgs[state_ctx->grent.cur]);

        ret = fill_grent(pctx->creq->out,
                         gdom->domain,
                         nctx, true, false, msgs, &n);

        state_ctx->grent.cur += n;
    }

none:
    if (ret == ENOENT) {
        ret = sss_cmd_empty_packet(pctx->creq->out);
    }
    return ret;
}

static int nss_cmd_getgrent_immediate(struct nss_cmd_ctx *cmdctx)
{
    struct cli_protocol *pctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    int ret;

    pctx = talloc_get_type(cmdctx->cctx->protocol_ctx, struct cli_protocol);

    /* get max num of entries to return in one call */
    sss_packet_get_body(pctx->creq->in, &body, &blen);
    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }
    SAFEALIGN_COPY_UINT32(&num, body, NULL);

    /* create response packet */
    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    ret = nss_cmd_retgrent(cmdctx->cctx, num);

    sss_packet_set_error(pctx->creq->out, ret);
    sss_cmd_done(cmdctx->cctx, cmdctx);

    return EOK;
}

static void nss_cmd_implicit_setgrent_done(struct tevent_req *req);
static int nss_cmd_getgrent(struct cli_ctx *cctx)
{
    struct nss_ctx *nctx;
    struct nss_state_ctx *state_ctx;
    struct nss_cmd_ctx *cmdctx;
    struct tevent_req *req;

    DEBUG(SSSDBG_CONF_SETTINGS, "Requesting info for all groups\n");

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
    state_ctx = talloc_get_type(cctx->state_ctx, struct nss_state_ctx);
    cmdctx->saved_dom_idx = state_ctx->grent.dom_idx;
    cmdctx->saved_cur = state_ctx->grent.cur;

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

static void nss_cmd_implicit_setgrent_done(struct tevent_req *req)
{
    errno_t ret;
    struct nss_cmd_ctx *cmdctx =
            tevent_req_callback_data(req, struct nss_cmd_ctx);
    struct nss_state_ctx *state_ctx;

    ret = nss_cmd_setgrent_recv(req);
    talloc_zfree(req);

    /* ENOENT is acceptable, as it just means that there were no entries
     * to be returned. This will be handled gracefully in nss_cmd_retpwent
     * later.
     */
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Implicit setgrent failed with unexpected error [%d][%s]\n",
                  ret, strerror(ret));
        NSS_CMD_FATAL_ERROR(cmdctx);
    }

    /* Restore the saved index and cursor locations */
    state_ctx = talloc_get_type(cmdctx->cctx->state_ctx, struct nss_state_ctx);
    state_ctx->grent.dom_idx = cmdctx->saved_dom_idx;
    state_ctx->grent.cur = cmdctx->saved_cur;

    ret = nss_cmd_getgrent_immediate(cmdctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Immediate retrieval failed with unexpected error "
                  "[%d][%s]\n", ret, strerror(ret));
        NSS_CMD_FATAL_ERROR(cmdctx);
    }
}

static int nss_cmd_endgrent(struct cli_ctx *cctx)
{
    struct cli_protocol *pctx;
    struct nss_state_ctx *state_ctx;
    struct nss_ctx *nctx;
    int ret;

    DEBUG(SSSDBG_CONF_SETTINGS, "Terminating request info for all groups\n");

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);
    state_ctx = talloc_get_type(cctx->state_ctx, struct nss_state_ctx);
    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    /* create response packet */
    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);

    if (ret != EOK) {
        return ret;
    }
    if (nctx->gctx == NULL) goto done;

    /* Reset the indices so that subsequent requests start at zero */
    state_ctx->grent.dom_idx = 0;
    state_ctx->grent.cur = 0;

done:
    sss_cmd_done(cctx, NULL);
    return EOK;
}

void nss_update_initgr_memcache(struct nss_ctx *nctx,
                                const char *fq_name, const char *domain,
                                int gnum, uint32_t *groups)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sss_domain_info *dom;
    struct ldb_result *res;
    struct sized_string *delete_name;
    bool changed = false;
    uint32_t id;
    uint32_t gids[gnum];
    int ret;
    int i, j;

    for (dom = nctx->rctx->domains; dom; dom = get_next_domain(dom, 0)) {
        if (strcasecmp(dom->name, domain) == 0) {
            break;
        }
    }

    if (dom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unknown domain (%s) requested by provider\n", domain);
        return;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return;
    }

    ret = sized_output_name(tmp_ctx, nctx->rctx, fq_name, dom, &delete_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sized_output_name failed for '%s': %d [%s]\n",
              fq_name, ret, sss_strerror(ret));
        goto done;
    }

    ret = sysdb_initgroups(tmp_ctx, dom, fq_name, &res);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to make request to our cache! [%d][%s]\n",
               ret, strerror(ret));
        goto done;
    }

    /* copy, we need the original intact in case we need to invalidate
     * all the original groups */
    memcpy(gids, groups, gnum * sizeof(uint32_t));

    if (ret == ENOENT || res->count == 0) {
        /* The user is gone. Invalidate the mc record */
        ret = sss_mmap_cache_pw_invalidate(nctx->pwd_mc_ctx, delete_name);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Internal failure in memory cache code: %d [%s]\n",
                  ret, strerror(ret));
        }

        /* Also invalidate his groups */
        changed = true;
    } else {
        /* we skip the first entry, it's the user itself */
        for (i = 0; i < res->count; i++) {
            id = ldb_msg_find_attr_as_uint(res->msgs[i], SYSDB_GIDNUM, 0);
            if (id == 0) {
                /* probably non-posix group, skip */
                continue;
            }
            for (j = 0; j < gnum; j++) {
                if (gids[j] == id) {
                    gids[j] = 0;
                    break;
                }
            }
            if (j >= gnum) {
                /* we couldn't find a match, this means the groups have
                 * changed after the refresh */
                changed = true;
                break;
            }
        }

        if (!changed) {
            for (j = 0; j < gnum; j++) {
                if (gids[j] != 0) {
                    /* we found an un-cleared groups, this means the groups
                     * have changed after the refresh (some got deleted) */
                    changed = true;
                    break;
                }
            }
        }
    }

    if (changed) {
        for (i = 0; i < gnum; i++) {
            id = groups[i];

            ret = sss_mmap_cache_gr_invalidate_gid(nctx->grp_mc_ctx, id);
            if (ret != EOK && ret != ENOENT) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Internal failure in memory cache code: %d [%s]\n",
                       ret, strerror(ret));
            }
        }

        to_sized_string(delete_name, fq_name);
        ret = sss_mmap_cache_initgr_invalidate(nctx->initgr_mc_ctx,
                                               delete_name);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Internal failure in memory cache code: %d [%s]\n",
                  ret, strerror(ret));
        }
    }

done:
    talloc_free(tmp_ctx);
}

/* FIXME: what about mpg, should we return the user's GID ? */
/* FIXME: should we filter out GIDs ? */
static int fill_initgr(struct sss_packet *packet,
                       struct sss_domain_info *dom,
                       struct ldb_result *res,
                       struct nss_ctx *nctx,
                       const char *mc_name,
                       const char *name)
{
    uint8_t *body;
    size_t blen;
    gid_t gid;
    int ret, i;
    uint32_t num;
    size_t bindex;
    int skipped = 0;
    const char *posix;
    gid_t orig_primary_gid;
    struct sized_string rawname;
    uint8_t *gids;

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

    orig_primary_gid = sss_view_ldb_msg_find_attr_as_uint64(dom, res->msgs[0],
                                                     SYSDB_PRIMARY_GROUP_GIDNUM,
                                                     0);

    /* If the GID of the original primary group is available but equal to the
    * current primary GID it must not be added. */
    if (orig_primary_gid != 0) {
        gid = sss_view_ldb_msg_find_attr_as_uint64(dom, res->msgs[0],
                                                   SYSDB_GIDNUM, 0);

        if (orig_primary_gid == gid) {
            orig_primary_gid = 0;
        }
    }

    /* 0-3: 32bit unsigned number of results
     * 4-7: 32bit unsigned (reserved/padding) */
    bindex = 2 * sizeof(uint32_t);
    gids = body + bindex;

    /* skip first entry, it's the user entry */
    for (i = 0; i < num; i++) {
        gid = sss_view_ldb_msg_find_attr_as_uint64(dom, res->msgs[i + 1],
                                                   SYSDB_GIDNUM, 0);
        posix = ldb_msg_find_attr_as_string(res->msgs[i + 1],
                                            SYSDB_POSIX, NULL);
        if (!gid) {
            if (posix && strcmp(posix, "FALSE") == 0) {
                skipped++;
                continue;
            } else {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Incomplete group object for initgroups! Aborting\n");
                return EFAULT;
            }
        }
        SAFEALIGN_COPY_UINT32(body + bindex, &gid, &bindex);

        /* do not add the GID of the original primary group is the user is
         * already and explicit member of the group. */
        if (orig_primary_gid == gid) {
            orig_primary_gid = 0;
        }
    }

    if (orig_primary_gid != 0) {
        SAFEALIGN_COPY_UINT32(body + bindex, &orig_primary_gid, &bindex);
        num++;
    }

    SAFEALIGN_SETMEM_UINT32(body, num - skipped, NULL); /* num results */
    SAFEALIGN_SETMEM_UINT32(body + sizeof(uint32_t), 0, NULL); /* reserved */
    blen = bindex;
    ret = sss_packet_set_size(packet, blen);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set packet size to value:%zu\n", blen);
        return ret;
    }

    if (nctx->initgr_mc_ctx) {
        struct sized_string unique_name;

        to_sized_string(&rawname, mc_name);
        to_sized_string(&unique_name, name);
        ret = sss_mmap_cache_initgr_store(&nctx->initgr_mc_ctx, &rawname,
                                          &unique_name, num - skipped, gids);
        if (ret != EOK && ret != ENOMEM) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to store user %s(%s) in mmap cache!\n",
                  rawname.str, dom->name);
        }
    }

    return EOK;
}

static int nss_cmd_initgr_send_reply(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_protocol *pctx;
    struct nss_ctx *nctx;
    int ret;

    pctx = talloc_get_type(cmdctx->cctx->protocol_ctx, struct cli_protocol);
    nctx = talloc_get_type(cmdctx->cctx->rctx->pvt_ctx, struct nss_ctx);

    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        return EFAULT;
    }

    ret = fill_initgr(pctx->creq->out, dctx->domain, dctx->res, nctx,
                      dctx->mc_name, cmdctx->normalized_name);
    if (ret) {
        return ret;
    }
    sss_packet_set_error(pctx->creq->out, EOK);
    sss_cmd_done(cmdctx->cctx, cmdctx);
    return EOK;
}

static int nss_cmd_initgroups_search(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct sss_domain_info *dom = dctx->domain;
    struct cli_ctx *cctx = cmdctx->cctx;
    char *name = NULL;
    struct nss_ctx *nctx;
    int ret;
    static const char *user_attrs[] = SYSDB_PW_ATTRS;
    struct ldb_message *msg;
    const char *sysdb_name;
    size_t c;
    const char *extra_flag = NULL;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    while (dom) {
       /* if it is a domainless search, skip domains that require fully
         * qualified names instead */
        while (dom && cmdctx->check_next && dom->fqnames
                && !cmdctx->name_is_upn) {
            dom = get_next_domain(dom, 0);
        }

        if (!dom) break;

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        talloc_zfree(cmdctx->normalized_name);

        name = sss_resp_create_fqname(dctx, nctx->rctx, dctx->domain,
                                      cmdctx->name_is_upn, cmdctx->name);
        if (name == NULL) {
            return ENOMEM;
        }

        /* save name so it can be used in initgr reply */
        cmdctx->normalized_name = name;

        /* verify this user has not yet been negatively cached,
        * or has been permanently filtered */
        ret = sss_ncache_check_user(nctx->rctx->ncache, dom, name);

        /* if neg cached, return we didn't find it */
        if (ret == EEXIST) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "User [%s] does not exist in [%s]! (negative cache)\n",
                   name, dom->name);
            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = get_next_domain(dom, 0);
                continue;
            }
            /* There are no further domains or this was a
             * fully-qualified user request.
             */
            return ENOENT;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Requesting info for [%s]\n", name);

        if (dom->sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Fatal: Sysdb CTX not found for this domain!\n");
            return EIO;
        }

        if (cmdctx->name_is_upn) {
            ret = sysdb_search_user_by_upn(cmdctx, dom, name, user_attrs, &msg);
            if (ret == ENOENT) {
                dctx->res = talloc_zero(cmdctx, struct ldb_result);
                if (dctx->res == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
                    return ENOMEM;
                }

                dctx->res->count = 0;
                dctx->res->msgs = NULL;
                ret = EOK;
            } else if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_user_by_upn failed.\n");
                return ret;
            } else {
                sysdb_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
                if (sysdb_name == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE,
                        "Sysdb entry does not have a name.\n");
                    return EINVAL;
                }

                /* Since sysdb_search_user_by_upn() searches the whole cache we
                 * have to set the domain so that it matches the result. */
                dctx->domain = find_domain_by_object_name(get_domains_head(dom),
                                                          sysdb_name);
                if (dctx->domain == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Cannot find matching domain for [%s].\n",
                          sysdb_name);
                    return EINVAL;
                }

                ret = sysdb_initgroups(cmdctx, dom, sysdb_name, &dctx->res);
                if (ret == EOK && DOM_HAS_VIEWS(dom)) {
                    for (c = 0; c < dctx->res->count; c++) {
                        ret = sysdb_add_overrides_to_object(dom, dctx->res->msgs[c],
                                                            NULL, NULL);
                        if (ret != EOK) {
                            DEBUG(SSSDBG_OP_FAILURE,
                                "sysdb_add_overrides_to_object failed.\n");
                            return ret;
                        }
                    }
                }
            }
        } else {
            ret = sysdb_initgroups_with_views(cmdctx, dom, name, &dctx->res);
        }
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to make request to our cache! [%d][%s]\n",
                      ret, strerror(ret));
            return EIO;
        }

        if (dctx->res->count == 0 && !dctx->check_provider) {
            /* set negative cache only if not result of cache check */
            ret = sss_ncache_set_user(nctx->rctx->ncache, false, dom, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Cannot set negcache for %s\n",
                      name);
            }

            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = get_next_domain(dom, 0);
                if (dom) continue;
            }

            DEBUG(SSSDBG_OP_FAILURE, "No results for initgroups call\n");

            return ENOENT;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (dctx->check_provider) {

            if (cmdctx->name_is_upn) {
                extra_flag = EXTRA_NAME_IS_UPN;
            } else if (DOM_HAS_VIEWS(dom) && (dctx->res->count == 0
                    || ldb_msg_find_attr_as_string(dctx->res->msgs[0],
                                                   OVERRIDE_PREFIX SYSDB_NAME,
                                                   NULL) != NULL)) {
                extra_flag = EXTRA_INPUT_MAYBE_WITH_VIEW;
            } else {
                extra_flag = NULL;
            }

            ret = check_cache(dctx, nctx, dctx->res, SSS_DP_INITGROUPS, name, 0,
                              extra_flag, nss_cmd_getby_dp_callback, dctx);
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                return ret;
            }
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Initgroups for [%s] completed\n", name);
        return EOK;
    }

    DEBUG(SSSDBG_MINOR_FAILURE,
          "No matching domain found for [%s], fail!\n", cmdctx->name);
    return ENOENT;
}

/* for now, if we are online, try to always query the backend */
static int nss_cmd_initgroups(struct cli_ctx *cctx)
{
    return nss_cmd_getbynam(SSS_NSS_INITGR, cctx);
}

static errno_t nss_cmd_getsidby_search(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct sss_domain_info *dom = dctx->domain;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    int ret;
    int err;
    const char *default_attrs[] = {SYSDB_NAME, SYSDB_OBJECTCLASS, SYSDB_SID_STR,
                                   ORIGINALAD_PREFIX SYSDB_NAME,
                                   ORIGINALAD_PREFIX SYSDB_UIDNUM,
                                   ORIGINALAD_PREFIX SYSDB_GIDNUM,
                                   ORIGINALAD_PREFIX SYSDB_GECOS,
                                   ORIGINALAD_PREFIX SYSDB_HOMEDIR,
                                   ORIGINALAD_PREFIX SYSDB_SHELL,
                                   SYSDB_UPN,
                                   SYSDB_DEFAULT_OVERRIDE_NAME,
                                   SYSDB_AD_ACCOUNT_EXPIRES,
                                   SYSDB_AD_USER_ACCOUNT_CONTROL,
                                   SYSDB_SSH_PUBKEY,
                                   SYSDB_USER_CERT,
                                   SYSDB_USER_EMAIL,
                                   SYSDB_ORIG_DN,
                                   SYSDB_ORIG_MEMBEROF,
                                   SYSDB_DEFAULT_ATTRS, NULL};
    const char **attrs;
    bool user_found = false;
    bool group_found = false;
    struct ldb_message *msg = NULL;
    char *name = NULL;
    char *req_name;
    uint32_t req_id;
    enum sss_dp_acct_type req_type;
    const char *extra_flag = NULL;
    char *neg_cache_name = NULL;
    const char *sysdb_name;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    while (dom) {

        if (cmdctx->cmd == SSS_NSS_GETSIDBYID) {
            /* check that the uid is valid for this domain */
            if ((dom->id_min && (cmdctx->id < dom->id_min)) ||
                (dom->id_max && (cmdctx->id > dom->id_max))) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "Uid [%"PRIu32"] does not exist in domain [%s]! "
                       "(id out of range)\n",
                       cmdctx->id, dom->name);
                if (cmdctx->check_next) {
                    dom = get_next_domain(dom, SSS_GND_DESCEND);
                    continue;
                }
                ret = ENOENT;
                goto done;
            }
        } else {
           /* if it is a domainless search, skip domains that require fully
            * qualified names instead */
            while (dom && cmdctx->check_next && dom->fqnames
                    && !cmdctx->name_is_upn) {
                dom = get_next_domain(dom, 0);
            }

            if (!dom) break;
        }

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        if (cmdctx->cmd == SSS_NSS_GETSIDBYID) {
            DEBUG(SSSDBG_TRACE_FUNC, "Requesting info for [%"PRIu32"@%s]\n",
                                      cmdctx->id, dom->name);

            ret = sss_ncache_check_uid(nctx->rctx->ncache, dom, cmdctx->id);
            if (ret == EEXIST) {
                ret = sss_ncache_check_gid(nctx->rctx->ncache, dom, cmdctx->id);
                if (ret == EEXIST) {
                    DEBUG(SSSDBG_TRACE_FUNC,
                          "ID [%"PRIu32"] does not exist in [%s]! (negative cache)\n",
                           cmdctx->id, dom->name);
                    /* if a multidomain search, try with next, including
                     * sub-domains */
                    if (cmdctx->check_next) {
                        dom = get_next_domain(dom, SSS_GND_DESCEND);
                        continue;
                    }
                    /* There are no further domains. */
                    ret = ENOENT;
                    goto done;
                }
            }

        } else {
            talloc_free(name);

            name = sss_resp_create_fqname(cmdctx, nctx->rctx, dom,
                                          cmdctx->name_is_upn, cmdctx->name);
            if (name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "sss_get_cased_name failed.\n");
                ret = ENOMEM;
                goto done;
            }

            if (cmdctx->name_is_upn) {
                neg_cache_name = talloc_asprintf(name, "@%s", name);
            } else {
                neg_cache_name = name;
            }

            /* verify this name has not yet been negatively cached, as user
             * and groupm, or has been permanently filtered */
            ret = sss_ncache_check_user(nctx->rctx->ncache, dom,
                                        neg_cache_name);

            if (ret == EEXIST) {
                ret = sss_ncache_check_group(nctx->rctx->ncache,
                                             dom, neg_cache_name);
                if (ret == EEXIST) {
                    /* if neg cached, return we didn't find it */
                    DEBUG(SSSDBG_TRACE_FUNC,
                          "SID [%s] does not exist in [%s]! (negative cache)\n",
                           name, dom->name);
                    /* if a multidomain search, try with next */
                    if (cmdctx->check_next) {
                        if (cmdctx->name_is_upn) {
                            dom = get_next_domain(dom, SSS_GND_DESCEND);
                        } else {
                            dom = get_next_domain(dom, 0);
                        }
                        continue;
                    }
                    /* There are no further domains or this was a
                     * fully-qualified user request.
                     */
                    ret = ENOENT;
                    goto done;
                }
            }

            DEBUG(SSSDBG_TRACE_FUNC, "Requesting info for [%s]\n", name);
        }


        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Fatal: Sysdb CTX not found for this domain!\n");
            ret = EIO;
            goto done;
        }

        attrs = default_attrs;
        if (cmdctx->cmd == SSS_NSS_GETORIGBYNAME
                && nctx->extra_attributes != NULL) {
            ret = add_strings_lists(cmdctx, default_attrs,
                                    nctx->extra_attributes, false,
                                    discard_const(&attrs));
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "add_strings_lists failed.\n");
                goto done;
            }
        }

        if (cmdctx->cmd == SSS_NSS_GETSIDBYID) {
            ret = sysdb_search_user_by_uid(cmdctx, dom, cmdctx->id, attrs,
                                           &msg);
            if (ret != EOK && ret != ENOENT) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to make request to our cache!\n");
                ret = EIO;
                goto done;
            }

            if (ret == EOK) {
                user_found = true;
            } else {
                talloc_free(msg);
                ret = sysdb_search_group_by_gid(cmdctx, dom, cmdctx->id, attrs,
                                                &msg);
                if (ret != EOK && ret != ENOENT) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Failed to make request to our cache!\n");
                    ret = EIO;
                    goto done;
                }

                if (ret == EOK) {
                    group_found = true;
                }
            }
        } else {
            if (cmdctx->name_is_upn) {
                ret = sysdb_search_user_by_upn(cmdctx, dom, name, attrs, &msg);
            } else {
                ret = sysdb_search_user_by_name(cmdctx, dom, name, attrs, &msg);
            }
            if (ret != EOK && ret != ENOENT) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to make request to our cache!\n");
                ret = EIO;
                goto done;
            }

            if (ret == EOK) {
                user_found = true;

                if (cmdctx->name_is_upn) {
                    /* Since sysdb_search_user_by_upn() searches the whole
                     * cache we have to set the domain so that it matches the
                     * result. */
                    sysdb_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME,
                                                             NULL);
                    if (sysdb_name == NULL) {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                              "Cached entry has no name.\n");
                        return EINVAL;
                    }
                    dctx->domain =
                            find_domain_by_object_name(get_domains_head(dom),
                                                       sysdb_name);
                    if (dctx->domain == NULL) {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                              "Cannot find matching domain for [%s].\n",
                              sysdb_name);
                        return EINVAL;
                    }
                }
            } else {
                talloc_free(msg);
                ret = sysdb_search_group_by_name(cmdctx, dom, name,
                                                 attrs, &msg);
                if (ret != EOK && ret != ENOENT) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Failed to make request to our cache!\n");
                    ret = EIO;
                    goto done;
                }

                if (ret == EOK) {
                    group_found = true;
                }
            }
        }

        dctx->res = talloc_zero(cmdctx, struct ldb_result);
        if (dctx->res == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
            ret = ENOMEM;
            goto done;
        }

        if (user_found || group_found) {
            dctx->res->count = 1;
            dctx->res->msgs = talloc_array(dctx->res, struct ldb_message *, 1);
            if (dctx->res->msgs == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
                ret = ENOMEM;
                goto done;
            }
            dctx->res->msgs[0] = talloc_steal(dctx->res, msg);
        }

        if (dctx->res->count == 0 && !dctx->check_provider) {
            if (cmdctx->cmd == SSS_NSS_GETSIDBYNAME
                    || cmdctx->cmd == SSS_NSS_GETORIGBYNAME) {
                ret = sss_ncache_set_user(nctx->rctx->ncache, false,
                                          dom, neg_cache_name);
                if (ret != EOK) {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                          "Cannot set negcache for %s\n", name);
                }

                ret = sss_ncache_set_group(nctx->rctx->ncache, false,
                                           dom, neg_cache_name);
                if (ret != EOK) {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                          "Cannot set negcache for %s\n", name);
                }
            }
            /* if a multidomain search, try with next */
            if (cmdctx->check_next) {
                dom = get_next_domain(dom, SSS_GND_DESCEND);
                continue;
            }

            DEBUG(SSSDBG_OP_FAILURE, "No matching user or group found.\n");
            ret = ENOENT;
            goto done;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (dctx->check_provider) {
            if (cmdctx->cmd == SSS_NSS_GETSIDBYID) {
                req_name = NULL;
                req_id = cmdctx->id;
            } else {
                req_name = name;
                req_id = 0;
            }
            if (user_found) {
                req_type = SSS_DP_USER;
            } else if (group_found) {
                req_type = SSS_DP_GROUP;
            } else {
                req_type = SSS_DP_USER_AND_GROUP;
            }

            if (cmdctx->name_is_upn) {
                extra_flag = EXTRA_NAME_IS_UPN;
            } else {
                extra_flag = NULL;
            }

            ret = check_cache(dctx, nctx, dctx->res,
                              req_type, req_name, req_id, extra_flag,
                              nss_cmd_getby_dp_callback,
                              dctx);
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                goto done;
            }
        }

        /* One result found */
        if (cmdctx->cmd == SSS_NSS_GETSIDBYID) {
            DEBUG(SSSDBG_TRACE_FUNC, "Returning info for id [%"PRIu32"@%s]\n",
                                     cmdctx->id, dom->name);
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "Returning info for user/group [%s]\n",
                                      name);
        }

        /* Success. Break from the loop and return EOK */
        ret = EOK;
        goto done;
    }

    /* All domains were tried and none had the entry. */
    ret = ENOENT;
done:
    if (ret == ENOENT) {
        /* The entry was not found, need to set result in negative cache */
        if (cmdctx->cmd == SSS_NSS_GETSIDBYID) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                "No matching domain found for [%"PRIu32"], fail!\n", cmdctx->id);
            err = sss_ncache_set_uid(nctx->rctx->ncache, false, NULL, cmdctx->id);
            if (err != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                    "Cannot set negative cache for UID %"PRIu32"\n", cmdctx->id);
            }

            err = sss_ncache_set_gid(nctx->rctx->ncache, false, NULL, cmdctx->id);
            if (err != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                    "Cannot set negative cache for GID %"PRIu32"\n", cmdctx->id);
            }
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "No matching domain found for [%s], fail!\n", cmdctx->name);
        }
    }
    return ret;
}

static errno_t nss_cmd_getbysid_search(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct sss_domain_info *dom = dctx->domain;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct sysdb_ctx *sysdb;
    struct nss_ctx *nctx;
    int ret;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    DEBUG(SSSDBG_TRACE_FUNC, "Requesting info for [%s]\n", cmdctx->secid);

    sysdb = dom->sysdb;
    if (sysdb == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Fatal: Sysdb CTX not found for this " \
                                     "domain!\n");
        return EIO;
    }

    /* verify this user has not yet been negatively cached,
        * or has been permanently filtered */
    ret = sss_ncache_check_sid(nctx->rctx->ncache, cmdctx->secid);
    if (ret == EEXIST) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "SID [%s] does not exist! (negative cache)\n", cmdctx->secid);
        return ENOENT;
    }

    ret = sysdb_search_object_by_sid(cmdctx, dom, cmdctx->secid, NULL,
                                     &dctx->res);
    if (ret == ENOENT) {
        if (!dctx->check_provider) {
            DEBUG(SSSDBG_OP_FAILURE, "No results for getbysid call.\n");

            /* set negative cache only if not result of cache check */
            ret = sss_ncache_set_sid(nctx->rctx->ncache, false, cmdctx->secid);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Cannot set negative cache for %s\n", cmdctx->secid);
            }

            return ENOENT;
        }

        dctx->res = talloc_zero(cmdctx, struct ldb_result);
        if (dctx->res == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
            return ENOMEM;
        }
        /* Fall through and call the backend */
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to make request to our cache!\n");
        return EIO;
    }

    if (dctx->res->count > 1) {
        DEBUG(SSSDBG_FATAL_FAILURE, "getbysid call returned more than one " \
                                     "result !?!\n");
        return ENOENT;
    }

    /* if this is a caching provider (or if we haven't checked the cache
     * yet) then verify that the cache is uptodate */
    if (dctx->check_provider) {
        ret = check_cache(dctx, nctx, dctx->res,
                          SSS_DP_SECID, cmdctx->secid, 0, NULL,
                          nss_cmd_getby_dp_callback,
                          dctx);
        if (ret != EOK) {
            /* Anything but EOK means we should reenter the mainloop
             * because we may be refreshing the cache
             */
            return ret;
        }
    }

    /* One result found */
    DEBUG(SSSDBG_TRACE_FUNC, "Returning info for sid [%s]\n", cmdctx->secid);
    return EOK;
}

static errno_t find_sss_id_type(struct ldb_message *msg,
                                bool mpg,
                                enum sss_id_type *id_type)
{
    size_t c;
    struct ldb_message_element *el;
    struct ldb_val *val = NULL;

    el = ldb_msg_find_element(msg, SYSDB_OBJECTCLASS);
    if (el == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Objectclass attribute not found.\n");
        return EINVAL;
    }

    for (c = 0; c < el->num_values; c++) {
        val = &(el->values[c]);
        if (strncasecmp(SYSDB_USER_CLASS,
                        (char *)val->data, val->length) == 0) {
            break;
        }
    }

    if (c == el->num_values) {
        *id_type = SSS_ID_TYPE_GID;
    } else {
        if (mpg) {
            *id_type = SSS_ID_TYPE_BOTH;
        } else {
            *id_type = SSS_ID_TYPE_UID;
        }
    }

    return EOK;
}

static errno_t fill_sid(struct sss_packet *packet,
                        enum sss_id_type id_type,
                        struct ldb_message *msg)
{
    int ret;
    const char *sid_str;
    struct sized_string sid;
    uint8_t *body;
    size_t blen;
    size_t pctr = 0;

    sid_str = ldb_msg_find_attr_as_string(msg, SYSDB_SID_STR, NULL);
    if (sid_str == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing SID.\n");
        return EINVAL;
    }

    to_sized_string(&sid, sid_str);

    ret = sss_packet_grow(packet, sid.len +  3* sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
        return ret;
    }

    sss_packet_get_body(packet, &body, &blen);
    SAFEALIGN_SETMEM_UINT32(body, 1, &pctr); /* Num results */
    SAFEALIGN_SETMEM_UINT32(body + pctr, 0, &pctr); /* reserved */
    SAFEALIGN_COPY_UINT32(body + pctr, &id_type, &pctr);
    memcpy(&body[pctr], sid.str, sid.len);

    return EOK;
}

static errno_t process_attr_list(TALLOC_CTX *mem_ctx, struct ldb_message *msg,
                                 const char **attr_list,
                                 struct sized_string **_keys,
                                 struct sized_string **_vals,
                                 size_t *array_size, size_t *sum, size_t *found)
{
    size_t c;
    size_t d;
    struct sized_string *keys;
    struct sized_string *vals;
    struct ldb_val val;
    struct ldb_message_element *el;
    bool use_base64;

    keys = *_keys;
    vals = *_vals;

    for (c = 0; attr_list[c] != NULL; c++) {
        el = ldb_msg_find_element(msg, attr_list[c]);
        if (el != NULL &&  el->num_values > 0) {
            if (el->num_values > 1) {
                *array_size += el->num_values;
                keys = talloc_realloc(mem_ctx, keys, struct sized_string,
                                      *array_size);
                vals = talloc_realloc(mem_ctx, vals, struct sized_string,
                                      *array_size);
                if (keys == NULL || vals == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
                    return ENOMEM;
                }
            }

            use_base64 = false;
            if (strcmp(attr_list[c], SYSDB_USER_CERT) == 0) {
                use_base64 = true;
            }

            for (d = 0; d < el->num_values; d++) {
                to_sized_string(&keys[*found], attr_list[c]);
                *sum += keys[*found].len;
                if (use_base64) {
                    val.data = (uint8_t *) sss_base64_encode(vals,
                                                          el->values[d].data,
                                                          el->values[d].length);
                    if (val.data != NULL) {
                        val.length = strlen((char *)val.data);
                    }
                } else {
                    val = el->values[d];
                }

                if (val.data == NULL || val.data[val.length] != '\0') {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Unexpected attribute value found for [%s].\n",
                          attr_list[c]);
                    return EINVAL;
                }
                to_sized_string(&vals[*found], (const char *)val.data);
                *sum += vals[*found].len;

                (*found)++;
            }
        }
    }

    *_keys = keys;
    *_vals = vals;

    return EOK;
}

static errno_t fill_orig(struct sss_packet *packet,
                         struct resp_ctx *rctx,
                         enum sss_id_type id_type,
                         struct ldb_message *msg)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    uint8_t *body;
    size_t blen;
    size_t pctr = 0;
    size_t c;
    size_t sum;
    size_t found;
    size_t array_size;
    size_t extra_attrs_count = 0;
    const char **extra_attrs_list = NULL;
    const char *orig_attr_list[] = {SYSDB_SID_STR,
                                    ORIGINALAD_PREFIX SYSDB_NAME,
                                    ORIGINALAD_PREFIX SYSDB_UIDNUM,
                                    ORIGINALAD_PREFIX SYSDB_GIDNUM,
                                    ORIGINALAD_PREFIX SYSDB_HOMEDIR,
                                    ORIGINALAD_PREFIX SYSDB_GECOS,
                                    ORIGINALAD_PREFIX SYSDB_SHELL,
                                    SYSDB_UPN,
                                    SYSDB_DEFAULT_OVERRIDE_NAME,
                                    SYSDB_AD_ACCOUNT_EXPIRES,
                                    SYSDB_AD_USER_ACCOUNT_CONTROL,
                                    SYSDB_SSH_PUBKEY,
                                    SYSDB_USER_CERT,
                                    SYSDB_USER_EMAIL,
                                    SYSDB_ORIG_DN,
                                    SYSDB_ORIG_MEMBEROF,
                                    NULL};
    struct sized_string *keys;
    struct sized_string *vals;
    struct nss_ctx *nctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    nctx = talloc_get_type(rctx->pvt_ctx, struct nss_ctx);
    if (nctx->extra_attributes != NULL) {
        extra_attrs_list = nctx->extra_attributes;
            for(extra_attrs_count = 0;
                extra_attrs_list[extra_attrs_count] != NULL;
                extra_attrs_count++);
    }

    array_size = sizeof(orig_attr_list) + extra_attrs_count;
    keys = talloc_array(tmp_ctx, struct sized_string, array_size);
    vals = talloc_array(tmp_ctx, struct sized_string, array_size);
    if (keys == NULL || vals == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    sum = 0;
    found = 0;

    ret = process_attr_list(tmp_ctx, msg, orig_attr_list, &keys, &vals,
                            &array_size, &sum, &found);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "process_attr_list failed.\n");
        goto done;
    }

    if (extra_attrs_count != 0) {
        ret = process_attr_list(tmp_ctx, msg, extra_attrs_list, &keys, &vals,
                                &array_size, &sum, &found);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "process_attr_list failed.\n");
            goto done;
        }
    }

    ret = sss_packet_grow(packet, sum +  3 * sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
        goto done;
    }

    sss_packet_get_body(packet, &body, &blen);
    SAFEALIGN_SETMEM_UINT32(body, 1, &pctr); /* Num results */
    SAFEALIGN_SETMEM_UINT32(body + pctr, 0, &pctr); /* reserved */
    SAFEALIGN_COPY_UINT32(body + pctr, &id_type, &pctr);
    for (c = 0; c < found; c++) {
        memcpy(&body[pctr], keys[c].str, keys[c].len);
        pctr+= keys[c].len;
        memcpy(&body[pctr], vals[c].str, vals[c].len);
        pctr+= vals[c].len;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t fill_name(struct sss_packet *packet,
                         struct resp_ctx *rctx,
                         struct sss_domain_info *dom,
                         enum sss_id_type id_type,
                         bool apply_no_view,
                         struct ldb_message *msg)
{
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *orig_name = NULL;
    struct sized_string *name;
    uint8_t *body;
    size_t blen;
    size_t pctr = 0;

    if (apply_no_view) {
        orig_name = ldb_msg_find_attr_as_string(msg,
                                                ORIGINALAD_PREFIX SYSDB_NAME,
                                                NULL);
    } else {
        if (DOM_HAS_VIEWS(dom)) {
            orig_name = ldb_msg_find_attr_as_string(msg,
                                                    OVERRIDE_PREFIX SYSDB_NAME,
                                                    NULL);
        }
    }

    if (orig_name == NULL) {
        orig_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    }
    if (orig_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing name.\n");
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = sized_output_name(tmp_ctx, rctx, orig_name, dom, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
             "sized_output_name failed for %s: (%d): %s\n",
             orig_name, ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_packet_grow(packet, name->len + 3 * sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
        goto done;
    }

    sss_packet_get_body(packet, &body, &blen);
    SAFEALIGN_SETMEM_UINT32(body, 1, &pctr); /* Num results */
    SAFEALIGN_SETMEM_UINT32(body + pctr, 0, &pctr); /* reserved */
    SAFEALIGN_COPY_UINT32(body + pctr, &id_type, &pctr);
    memcpy(&body[pctr], name->str, name->len);


    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t fill_id(struct sss_packet *packet,
                       enum sss_id_type id_type,
                       struct ldb_message *msg)
{
    int ret;
    uint8_t *body;
    size_t blen;
    size_t pctr = 0;
    uint64_t tmp_id;
    uint32_t id;

    if (id_type == SSS_ID_TYPE_GID) {
        tmp_id = ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);
    } else {
        tmp_id = ldb_msg_find_attr_as_uint64(msg, SYSDB_UIDNUM, 0);
    }

    if (tmp_id == 0 || tmp_id >= UINT32_MAX) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid POSIX ID.\n");
        return EINVAL;
    }
    id = (uint32_t) tmp_id;

    ret = sss_packet_grow(packet, 4 * sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
        return ret;
    }

    sss_packet_get_body(packet, &body, &blen);
    SAFEALIGN_SETMEM_UINT32(body, 1, &pctr); /* Num results */
    SAFEALIGN_SETMEM_UINT32(body + pctr, 0, &pctr); /* reserved */
    SAFEALIGN_COPY_UINT32(body + pctr, &id_type, &pctr);
    SAFEALIGN_COPY_UINT32(body + pctr, &id, &pctr);

    return EOK;
}

static errno_t nss_cmd_getbysid_send_reply(struct nss_dom_ctx *dctx)
{
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    struct cli_ctx *cctx = cmdctx->cctx;
    struct cli_protocol *pctx;
    int ret;
    enum sss_id_type id_type;

    if (dctx->res->count > 1) {
        return EINVAL;
    } else if (dctx->res->count == 0) {
        return ENOENT;
    }

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);

    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        return EFAULT;
    }

    ret = find_sss_id_type(dctx->res->msgs[0], dctx->domain->mpg, &id_type);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "find_sss_id_type failed.\n");
        return ret;
    }

    switch(cmdctx->cmd) {
    case SSS_NSS_GETNAMEBYSID:
        ret = fill_name(pctx->creq->out,
                        cctx->rctx,
                        dctx->domain,
                        id_type,
                        true,
                        dctx->res->msgs[0]);
        break;
    case SSS_NSS_GETIDBYSID:
        ret = fill_id(pctx->creq->out, id_type, dctx->res->msgs[0]);
        break;
    case SSS_NSS_GETSIDBYNAME:
    case SSS_NSS_GETSIDBYID:
        ret = fill_sid(pctx->creq->out, id_type, dctx->res->msgs[0]);
        break;
    case SSS_NSS_GETORIGBYNAME:
        ret = fill_orig(pctx->creq->out, cctx->rctx, id_type,
                        dctx->res->msgs[0]);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported request type.\n");
        return EINVAL;
    }
    if (ret != EOK) {
        return ret;
    }

    sss_packet_set_error(pctx->creq->out, EOK);
    sss_cmd_done(cctx, cmdctx);
    return EOK;
}

static int nss_check_well_known_sid(struct nss_cmd_ctx *cmdctx)
{
    const char *wk_name;
    const char *wk_dom_name;
    int ret;
    char *fq_name = NULL;
    struct sized_string name;
    uint8_t *body;
    size_t blen;
    struct cli_protocol *pctx;
    size_t pctr = 0;

    pctx = talloc_get_type(cmdctx->cctx->protocol_ctx, struct cli_protocol);

    ret = well_known_sid_to_name(cmdctx->secid, &wk_dom_name, &wk_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_ALL, "SID [%s] is not a Well-Known SID.\n",
                                 cmdctx->secid);
        return ret;
    }

    if (cmdctx->cmd != SSS_NSS_GETNAMEBYSID) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Well-Known SIDs can only be translated to names.\n");
        return EINVAL;
    }

    if (wk_dom_name != NULL) {
        fq_name = sss_tc_fqname2(cmdctx, cmdctx->cctx->rctx->global_names,
                                 wk_dom_name, wk_dom_name, wk_name);
        if (fq_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_tc_fqname2 failed.\n");
            return ENOMEM;
        }
        to_sized_string(&name, fq_name);
    } else {
        to_sized_string(&name, wk_name);
    }

    ret = sss_packet_new(pctx->creq, name.len + 3 * sizeof(uint32_t),
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        talloc_free(fq_name);
        return ENOMEM;
    }

    sss_packet_get_body(pctx->creq->out, &body, &blen);
    SAFEALIGN_SETMEM_UINT32(body, 1, &pctr); /* num results */
    SAFEALIGN_SETMEM_UINT32(body + pctr, 0, &pctr); /* reserved */
    SAFEALIGN_SETMEM_UINT32(body + pctr, SSS_ID_TYPE_GID, &pctr);
    memcpy(&body[pctr], name.str, name.len);

    sss_packet_set_error(pctx->creq->out, EOK);
    sss_cmd_done(cmdctx->cctx, cmdctx);
    return EOK;
}

static int nss_cmd_getbysid(enum sss_cli_command cmd, struct cli_ctx *cctx)
{

    struct tevent_req *req;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    const char *sid_str;
    uint8_t *body;
    size_t blen;
    int ret;
    struct cli_protocol *pctx;
    struct nss_ctx *nctx;
    enum idmap_error_code err;
    uint8_t *bin_sid = NULL;
    size_t bin_sid_length;

    if (cmd != SSS_NSS_GETNAMEBYSID && cmd != SSS_NSS_GETIDBYSID) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid command type [%d][%s].\n",
              cmd, sss_cmd2str(cmd));
        return EINVAL;
    }

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);

    cmdctx = talloc_zero(cctx, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = cctx;
    cmdctx->cmd = cmd;

    dctx = talloc_zero(cmdctx, struct nss_dom_ctx);
    if (!dctx) {
        ret = ENOMEM;
        goto done;
    }
    dctx->cmdctx = cmdctx;

    /* get SID to query */
    sss_packet_get_body(pctx->creq->in, &body, &blen);

    /* if not terminated fail */
    if (body[blen -1] != '\0') {
        ret = EINVAL;
        goto done;
    }

    sid_str = (const char *) body;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);

    /* If the body isn't a SID, fail */
    err = sss_idmap_sid_to_bin_sid(nctx->idmap_ctx, sid_str,
                                   &bin_sid, &bin_sid_length);
    sss_idmap_free_bin_sid(nctx->idmap_ctx, bin_sid);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_idmap_sid_to_bin_sid failed for [%s].\n",
                                  body);
        ret = EINVAL;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Running command [%d][%s] with SID [%s].\n",
          dctx->cmdctx->cmd, sss_cmd2str(dctx->cmdctx->cmd), sid_str);

    cmdctx->secid = talloc_strdup(cmdctx, sid_str);
    if (cmdctx->secid == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = nss_check_well_known_sid(cmdctx);
    switch (ret) {
    case EOK:
        DEBUG(SSSDBG_TRACE_ALL, "SID [%s] is a Well-Known SID.\n", sid_str);
        /* message is already send and cmdctx is freed, we can just return */
        return EOK;
        break;
    case ENOENT:
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "nss_check_well_known_sid failed.\n");
        goto done;
    }

    ret = responder_get_domain_by_id(cctx->rctx, cmdctx->secid, &dctx->domain);
    if (ret == EAGAIN || ret == ENOENT) {
        req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, true, NULL);
        if (req == NULL) {
            ret = ENOMEM;
        } else {
            dctx->rawname = sid_str;
            tevent_req_set_callback(req, nss_cmd_getbyid_done, dctx);
            ret = EAGAIN;
        }
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "responder_get_domain_by_id failed.\n");
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Requesting info for [%s] from [%s]\n",
              cmdctx->secid, dctx->domain->name);

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    /* ok, find it ! */
    ret = nss_cmd_getbysid_search(dctx);
    if (ret == EOK) {
        ret = nss_cmd_getbysid_send_reply(dctx);
    }

done:
    return nss_cmd_done(cmdctx, ret);
}

static void users_find_by_cert_done(struct tevent_req *req);

static int nss_cmd_getbycert(enum sss_cli_command cmd, struct cli_ctx *cctx)
{

    struct tevent_req *req;
    uint8_t *body;
    size_t blen;
    int ret;
    const char *derb64;
    char *pem_cert = NULL;
    size_t pem_size;
    struct nss_ctx *nctx;
    struct cli_protocol *pctx;

    nctx = talloc_get_type(cctx->rctx->pvt_ctx, struct nss_ctx);
    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);

    if (cmd != SSS_NSS_GETNAMEBYCERT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid command type [%d][%s].\n",
              cmd, sss_cmd2str(cmd));
        return EINVAL;
    }

    /* get certificate to query */
    sss_packet_get_body(pctx->creq->in, &body, &blen);

    /* if not terminated fail */
    if (body[blen - 1] != '\0') {
        return EINVAL;
    }

    derb64 = (const char *)body;
    DEBUG(SSSDBG_TRACE_ALL, "cert [%s]\n", derb64);

    /* check input */
    ret = sss_cert_derb64_to_pem(cctx, derb64, &pem_cert, &pem_size);
    talloc_free(pem_cert);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_cert_pem_to_derb64 failed.\n");
        return ret;
    }

    req = cache_req_user_by_cert_send(cctx, cctx->rctx->ev, cctx->rctx,
                                      nctx->rctx->ncache, 0, NULL, derb64);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, users_find_by_cert_done, cctx);

    return EOK;
}

static void users_find_by_cert_done(struct tevent_req *req)
{
    struct cli_ctx *cctx;
    struct cache_req_result *result;
    struct cli_protocol *pctx;
    errno_t ret;

    cctx = tevent_req_callback_data(req, struct cli_ctx);
    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);

    ret = cache_req_user_by_cert_recv(cctx, req, &result);
    talloc_zfree(req);
    if (ret == ENOENT || result->count == 0) {
        ret = ENOENT;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    if (result->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Found more than 1 result with certficate search.\n");

        ret = EINVAL;
        goto done;
    }

    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_new failed.\n");
        ret = EFAULT;
        goto done;
    }

    ret = fill_name(pctx->creq->out, cctx->rctx, result->domain,
                    SSS_ID_TYPE_UID, true, result->msgs[0]);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "fill_name failed.\n");
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        sss_packet_set_error(pctx->creq->out, EOK);
        sss_cmd_done(cctx, NULL);
    } else if (ret == ENOENT) {
        sss_cmd_send_empty(cctx, NULL);
    } else {
        sss_cmd_send_error(cctx, ret);
    }

    return;
}

static int nss_cmd_getsidbyname(struct cli_ctx *cctx)
{
    return nss_cmd_getbynam(SSS_NSS_GETSIDBYNAME, cctx);
}

static int nss_cmd_getsidbyid(struct cli_ctx *cctx)
{
    return nss_cmd_getbyid(SSS_NSS_GETSIDBYID, cctx);
}

static int nss_cmd_getnamebysid(struct cli_ctx *cctx)
{
    return nss_cmd_getbysid(SSS_NSS_GETNAMEBYSID, cctx);
}

static int nss_cmd_getidbysid(struct cli_ctx *cctx)
{
    return nss_cmd_getbysid(SSS_NSS_GETIDBYSID, cctx);
}

static int nss_cmd_getorigbyname(struct cli_ctx *cctx)
{
    return nss_cmd_getbynam(SSS_NSS_GETORIGBYNAME, cctx);
}

static int nss_cmd_getnamebycert(struct cli_ctx *cctx)
{
    return nss_cmd_getbycert(SSS_NSS_GETNAMEBYCERT, cctx);
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
    {SSS_NSS_GETSIDBYNAME, nss_cmd_getsidbyname},
    {SSS_NSS_GETSIDBYID, nss_cmd_getsidbyid},
    {SSS_NSS_GETNAMEBYSID, nss_cmd_getnamebysid},
    {SSS_NSS_GETIDBYSID, nss_cmd_getidbysid},
    {SSS_NSS_GETORIGBYNAME, nss_cmd_getorigbyname},
    {SSS_NSS_GETNAMEBYCERT, nss_cmd_getnamebycert},
    {SSS_CLI_NULL, NULL}
};

struct sss_cmd_table *get_nss_cmds(void) {
    return nss_cmds;
}

int nss_connection_setup(struct cli_ctx *cctx)
{
    int ret;

    ret = sss_connection_setup(cctx);
    if (ret != EOK) return ret;

    cctx->state_ctx = talloc_zero(cctx, struct nss_state_ctx);
    if (!cctx->state_ctx) {
        return ENOMEM;
    }

    return EOK;
}
