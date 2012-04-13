/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2011 Red Hat

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

#include "config.h"

#include <stdint.h>
#include <string.h>
#include <talloc.h>

#include "util/util.h"
#include "db/sysdb_sudo.h"
#include "responder/sudo/sudosrv_private.h"

static errno_t sudosrv_get_user(struct sudo_dom_ctx *dctx);

errno_t sudosrv_get_sudorules(struct sudo_dom_ctx *dctx)
{
    errno_t ret;

    dctx->check_provider = true;
    ret = sudosrv_get_user(dctx);
    if (ret == EAGAIN) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              ("Looking up the user info from Data Provider\n"));
        return EAGAIN;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Error looking up user information [%d]: %s\n", ret, strerror(ret)));
        return ret;
    }

    /* OK, got the user from cache. Try to get the rules. */
    ret = sudosrv_get_rules(dctx->cmd_ctx);
    if (ret == EAGAIN) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              ("Looking up the sudo rules from Data Provider\n"));
        return EAGAIN;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Error looking up sudo rules [%d]: %s\n", ret, strerror(ret)));
        return ret;
    }

    return EOK;
}

static void sudosrv_dp_send_acct_req_done(struct tevent_req *req);
static void sudosrv_check_user_dp_callback(uint16_t err_maj, uint32_t err_min,
                                           const char *err_msg, void *ptr);

static errno_t sudosrv_get_user(struct sudo_dom_ctx *dctx)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sss_domain_info *dom = dctx->domain;
    struct sudo_cmd_ctx *cmd_ctx = dctx->cmd_ctx;
    struct cli_ctx *cli_ctx = dctx->cmd_ctx->cli_ctx;
    struct sysdb_ctx *sysdb;
    struct ldb_result *user;
    time_t cache_expire = 0;
    struct tevent_req *dpreq;
    struct dp_callback_ctx *cb_ctx;
    const char *original_name = NULL;
    char *name = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        return ENOMEM;
    }

    while (dom) {
       /* if it is a domainless search, skip domains that require fully
        * qualified names instead */
        while (dom && cmd_ctx->check_next && dom->fqnames) {
            dom = dom->next;
        }

        if (!dom) break;

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        talloc_free(name);
        name = sss_get_cased_name(tmp_ctx, cmd_ctx->username,
                                  dom->case_sensitive);
        if (name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory\n"));
            ret = ENOMEM;
            goto done;
        }

        DEBUG(SSSDBG_FUNC_DATA, ("Requesting info about [%s@%s]\n",
              name, dom->name));

        sysdb = dctx->domain->sysdb;
        if (sysdb == NULL) {
             DEBUG(SSSDBG_CRIT_FAILURE,
                   ("sysdb context not found for this domain!\n"));
             ret = EIO;
             goto done;
        }

        ret = sysdb_getpwnam(dctx, sysdb, name, &user);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Failed to make request to our cache!\n"));
            ret = EIO;
            goto done;
        }

        if (user->count > 1) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("getpwnam call returned more than one result !?!\n"));
            ret = EIO;
            goto done;
        }

        if (user->count == 0 && !dctx->check_provider) {
            /* if a multidomain search, try with next */
            if (cmd_ctx->check_next) {
                dctx->check_provider = true;
                dom = dom->next;
                if (dom) continue;
            }

            DEBUG(SSSDBG_MINOR_FAILURE, ("No results for getpwnam call\n"));
            ret = ENOENT;
            goto done;
        }

        /* One result found, check cache expiry */
        if (user->count == 1) {
            cache_expire = ldb_msg_find_attr_as_uint64(user->msgs[0],
                                                       SYSDB_CACHE_EXPIRE, 0);
        }

        /* If cache miss and we haven't checked DP yet OR the entry is
         * outdated, go to DP */
        if ((user->count == 0 || cache_expire < time(NULL))
            && dctx->check_provider) {
            dpreq = sss_dp_get_account_send(cli_ctx, cli_ctx->rctx,
                                            dom, false, SSS_DP_INITGROUPS,
                                            cmd_ctx->username, 0, NULL);
            if (!dpreq) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      ("Out of memory sending data provider request\n"));
                ret = ENOMEM;
                goto done;
            }

            cb_ctx = talloc_zero(cli_ctx, struct dp_callback_ctx);
            if(!cb_ctx) {
                talloc_zfree(dpreq);
                ret = ENOMEM;
                goto done;
            }

            cb_ctx->callback = sudosrv_check_user_dp_callback;
            cb_ctx->ptr = dctx;
            cb_ctx->cctx = cli_ctx;
            cb_ctx->mem_ctx = cli_ctx;

            tevent_req_set_callback(dpreq, sudosrv_dp_send_acct_req_done, cb_ctx);

            /* tell caller we are in an async call */
            ret = EAGAIN;
            goto done;
        }

        /* user is stored in cache, remember cased and original name */
        original_name = ldb_msg_find_attr_as_string(user->msgs[0],
                                                    SYSDB_NAME, NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("A user with no name?\n"));
            ret = EFAULT;
            goto done;
        }

        cmd_ctx->cased_username = talloc_move(cmd_ctx, &name);
        cmd_ctx->orig_username = talloc_strdup(cmd_ctx, original_name);
        if (cmd_ctx->orig_username == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory\n"));
            ret = ENOMEM;
            goto done;
        }

        /* and set domain */
        cmd_ctx->domain = dom;

        DEBUG(SSSDBG_TRACE_FUNC, ("Returning info for user [%s@%s]\n",
              cmd_ctx->username, dctx->domain->name));
        ret = EOK;
        goto done;
    }

    ret = ENOENT;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static void sudosrv_dp_send_acct_req_done(struct tevent_req *req)
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
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Fatal error, killing connection!\n"));
        talloc_free(cb_ctx->cctx);
        return;
    }

    cb_ctx->callback(err_maj, err_min, err_msg, cb_ctx->ptr);
}

static void sudosrv_check_user_dp_callback(uint16_t err_maj, uint32_t err_min,
                                           const char *err_msg, void *ptr)
{
    errno_t ret;
    struct sudo_dom_ctx *dctx = talloc_get_type(ptr, struct sudo_dom_ctx);

    if (err_maj) {
        DEBUG(SSSDBG_CRIT_FAILURE,
             ("Unable to get information from Data Provider\n"
              "Error: %u, %u, %s\n",
              (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          ("Data Provider returned, check the cache again\n"));
    dctx->check_provider = false;
    ret = sudosrv_get_user(dctx);
    if (ret == EAGAIN) {
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not look up the user [%d]: %s\n",
              ret, strerror(ret)));
        sudosrv_cmd_done(dctx->cmd_ctx, EIO);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Looking up sudo rules..\n"));
    ret = sudosrv_get_rules(dctx->cmd_ctx);
    if (ret == EAGAIN) {
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Error getting sudo rules [%d]: %s\n",
              ret, strerror(ret)));
        sudosrv_cmd_done(dctx->cmd_ctx, EIO);
        return;
    }

done:
    sudosrv_cmd_done(dctx->cmd_ctx, ret);
}

static errno_t sudosrv_get_sudorules_from_cache(struct sudo_cmd_ctx *cmd_ctx);
static void
sudosrv_get_sudorules_dp_callback(uint16_t err_maj, uint32_t err_min,
                                  const char *err_msg, void *ptr);
static void
sudosrv_dp_req_done(struct tevent_req *req);

errno_t sudosrv_get_rules(struct sudo_cmd_ctx *cmd_ctx)
{
    struct tevent_req *dpreq;
    struct dp_callback_ctx *cb_ctx = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, ("getting rules for %s\n",
          cmd_ctx->username ? cmd_ctx->username : "default options"));

    dpreq = sss_dp_get_sudoers_send(cmd_ctx->cli_ctx,
                                    cmd_ctx->cli_ctx->rctx,
                                    cmd_ctx->domain, false,
                                    cmd_ctx->type,
                                    cmd_ctx->orig_username);
    if (dpreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Cannot issue DP request.\n"));
        return EIO;
    }

    cb_ctx = talloc_zero(cmd_ctx, struct dp_callback_ctx);
    if (!cb_ctx) {
        talloc_zfree(dpreq);
        return ENOMEM;
    }

    cb_ctx->callback = sudosrv_get_sudorules_dp_callback;
    cb_ctx->ptr = cmd_ctx;
    cb_ctx->cctx = cmd_ctx->cli_ctx;
    cb_ctx->mem_ctx = cmd_ctx;

    tevent_req_set_callback(dpreq, sudosrv_dp_req_done, cb_ctx);
    return EAGAIN;
}

static void
sudosrv_dp_req_done(struct tevent_req *req)
{
    struct dp_callback_ctx *cb_ctx =
        tevent_req_callback_data(req, struct dp_callback_ctx);
    struct cli_ctx *cli_ctx = talloc_get_type(cb_ctx->cctx, struct cli_ctx);

    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;

    ret = sss_dp_get_sudoers_recv(cb_ctx->mem_ctx, req,
                                  &err_maj, &err_min,
                                  &err_msg);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Fatal error, killing connection!\n"));
        talloc_free(cli_ctx);
        return;
    }

    cb_ctx->callback(err_maj, err_min, err_msg, cb_ctx->ptr);
}

static void
sudosrv_get_sudorules_dp_callback(uint16_t err_maj, uint32_t err_min,
                                  const char *err_msg, void *ptr)
{
    struct sudo_cmd_ctx *cmd_ctx = talloc_get_type(ptr, struct sudo_cmd_ctx);
    errno_t ret;

    if (err_maj) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unable to get information from Data Provider\n"
               "Error: %u, %u, %s\n"
               "Will try to return what we have in cache\n",
               (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, ("About to get sudo rules from cache\n"));
    ret = sudosrv_get_sudorules_from_cache(cmd_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Failed to make a request to our cache [%d]: %s\n",
              ret, strerror(ret)));
        sudosrv_cmd_done(cmd_ctx, EIO);
        return;
    }

    sudosrv_cmd_done(cmd_ctx, ret);
}

static errno_t sudosrv_get_sudorules_query_cache(TALLOC_CTX *mem_ctx,
                                                 struct sysdb_ctx *sysdb,
                                                 enum sss_dp_sudo_type type,
                                                 const char *username,
                                                 uid_t uid,
                                                 char **groupnames,
                                                 struct sysdb_attrs ***_rules,
                                                 size_t *_count);

static errno_t sudosrv_get_sudorules_from_cache(struct sudo_cmd_ctx *cmd_ctx)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    struct sysdb_ctx *sysdb;
    struct sudo_ctx *sudo_ctx = cmd_ctx->sudo_ctx;
    uid_t uid = 0;
    char **groupnames = NULL;
    const char *debug_name = NULL;

    if (cmd_ctx->domain == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Domain is not set!\n"));
        return EFAULT;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        return ENOMEM;
    }

    sysdb = cmd_ctx->domain->sysdb;
    if (sysdb == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("sysdb context not found for this domain!\n"));
        ret = EIO;
        goto done;
    }

    switch (cmd_ctx->type) {
    case SSS_DP_SUDO_USER:
        debug_name = cmd_ctx->cased_username;
        ret = sysdb_get_sudo_user_info(tmp_ctx, cmd_ctx->orig_username, sysdb,
                                       &uid, &groupnames);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                 ("Unable to retrieve user info [%d]: %s\n", strerror(ret)));
            goto done;
        }
        break;
    case SSS_DP_SUDO_DEFAULTS:
        debug_name = "<default options>";
        break;
    }

    ret = sudosrv_get_sudorules_query_cache(cmd_ctx, sysdb, cmd_ctx->type,
                                            cmd_ctx->orig_username,
                                            uid, groupnames,
                                            &cmd_ctx->rules, &cmd_ctx->num_rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
             ("Unable to retrieve sudo rules [%d]: %s\n", strerror(ret)));
        goto done;
    }

    /* Store result in in-memory cache */
    ret = sudosrv_cache_set_entry(sudo_ctx->rctx->ev, sudo_ctx, sudo_ctx->cache,
                                  cmd_ctx->domain, cmd_ctx->cased_username,
                                  cmd_ctx->num_rules, cmd_ctx->rules,
                                  sudo_ctx->cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Unable to store rules in cache for "
              "[%s@%s]\n", debug_name, cmd_ctx->domain->name));
    } else {
        DEBUG(SSSDBG_FUNC_DATA, ("Rules for [%s@%s] stored in in-memory cache\n",
                                 debug_name, cmd_ctx->domain->name));
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Returning rules for [%s@%s]\n",
          debug_name, cmd_ctx->domain->name));

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sort_sudo_rules(struct sysdb_attrs **rules, size_t count);

static errno_t sudosrv_get_sudorules_query_cache(TALLOC_CTX *mem_ctx,
                                                 struct sysdb_ctx *sysdb,
                                                 enum sss_dp_sudo_type type,
                                                 const char *username,
                                                 uid_t uid,
                                                 char **groupnames,
                                                 struct sysdb_attrs ***_rules,
                                                 size_t *_count)
{
    TALLOC_CTX *tmp_ctx;
    char *filter;
    errno_t ret;
    size_t count;
    struct sysdb_attrs **rules;
    struct ldb_message **msgs;
    unsigned int flags = SYSDB_SUDO_FILTER_NONE;
    const char *attrs[] = { SYSDB_OBJECTCLASS
                            SYSDB_SUDO_CACHE_AT_OC,
                            SYSDB_SUDO_CACHE_AT_CN,
                            SYSDB_SUDO_CACHE_AT_USER,
                            SYSDB_SUDO_CACHE_AT_HOST,
                            SYSDB_SUDO_CACHE_AT_COMMAND,
                            SYSDB_SUDO_CACHE_AT_OPTION,
                            SYSDB_SUDO_CACHE_AT_RUNASUSER,
                            SYSDB_SUDO_CACHE_AT_RUNASGROUP,
                            SYSDB_SUDO_CACHE_AT_NOTBEFORE,
                            SYSDB_SUDO_CACHE_AT_NOTAFTER,
                            SYSDB_SUDO_CACHE_AT_ORDER,
                            NULL };

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    switch (type) {
    case SSS_DP_SUDO_DEFAULTS:
        flags = SYSDB_SUDO_FILTER_INCLUDE_DFL;
        break;
    case SSS_DP_SUDO_USER:
        flags =   SYSDB_SUDO_FILTER_USERINFO | SYSDB_SUDO_FILTER_INCLUDE_ALL;
        break;
    }
    ret = sysdb_get_sudo_filter(tmp_ctx, username, uid, groupnames,
                                flags, &filter);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not construct the search filter [%d]: %s\n",
               ret, strerror(ret)));
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, ("Searching sysdb with [%s]\n", filter));

    ret = sysdb_search_custom(tmp_ctx, sysdb, filter,
                              SUDORULE_SUBDIR, attrs,
                              &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Error looking up SUDO rules"));
        goto done;
    } if (ret == ENOENT) {
       *_rules = NULL;
       *_count = 0;
       ret = EOK;
       goto done;
    }

    ret = sysdb_msg2attrs(tmp_ctx, count, msgs, &rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not convert ldb message to sysdb_attrs\n"));
        goto done;
    }

    ret = sort_sudo_rules(rules, count);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not sort rules by sudoOrder\n"));
        goto done;
    }

    *_rules = talloc_steal(mem_ctx, rules);
    *_count = count;

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static int
sudo_order_cmp_fn(const void *a, const void *b)
{
    struct sysdb_attrs *r1, *r2;
    uint32_t o1, o2;
    int ret;

    r1 = * (struct sysdb_attrs * const *) a;
    r2 = * (struct sysdb_attrs * const *) b;
    if (!r1 || !r2) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("BUG: Wrong data?\n"));
        return 0;
    }

    ret = sysdb_attrs_get_uint32_t(r1, SYSDB_SUDO_CACHE_AT_ORDER, &o1);
    if (ret == ENOENT) {
        /* man sudoers-ldap: If the sudoOrder attribute is not present,
         * a value of 0 is assumed */
        o1 = 0;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Cannot get sudoOrder value\n"));
        return 0;
    }

    ret = sysdb_attrs_get_uint32_t(r2, SYSDB_SUDO_CACHE_AT_ORDER, &o2);
    if (ret == ENOENT) {
        /* man sudoers-ldap: If the sudoOrder attribute is not present,
         * a value of 0 is assumed */
        o2 = 0;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Cannot get sudoOrder value\n"));
        return 0;
    }

    if (o1 > o2) {
        return 1;
    } else if (o1 < o2) {
        return -1;
    }

    return 0;
}

static errno_t
sort_sudo_rules(struct sysdb_attrs **rules, size_t count)
{
    qsort(rules, count, sizeof(struct sysdb_attrs *),
          sudo_order_cmp_fn);
    return EOK;
}
