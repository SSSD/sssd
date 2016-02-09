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
#include <tevent.h>

#include "util/util.h"
#include "db/sysdb_sudo.h"
#include "responder/sudo/sudosrv_private.h"
#include "providers/data_provider.h"

errno_t sudosrv_get_sudorules(struct sudo_cmd_ctx *cmd_ctx)
{
    errno_t ret;

    ret = sudosrv_get_rules(cmd_ctx);
    if (ret == EAGAIN) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Looking up the sudo rules from Data Provider\n");
        return EAGAIN;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Error looking up sudo rules [%d]: %s\n", ret, strerror(ret));
        return ret;
    }

    return EOK;
}

static errno_t sudosrv_get_sudorules_from_cache(TALLOC_CTX *mem_ctx,
                                                struct sudo_cmd_ctx *cmd_ctx,
                                                struct sysdb_attrs ***_rules,
                                                uint32_t *_num_rules);
static void
sudosrv_get_sudorules_dp_callback(uint16_t err_maj, uint32_t err_min,
                                  const char *err_msg, void *ptr);
static void
sudosrv_dp_req_done(struct tevent_req *req);

static errno_t sudosrv_get_sudorules_query_cache(TALLOC_CTX *mem_ctx,
                                                 struct sss_domain_info *domain,
                                                 const char **attrs,
                                                 unsigned int flags,
                                                 const char *username,
                                                 uid_t uid,
                                                 char **groupnames,
                                                 bool inverse_order,
                                                 struct sysdb_attrs ***_rules,
                                                 uint32_t *_count);

errno_t sudosrv_get_rules(struct sudo_cmd_ctx *cmd_ctx)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct tevent_req *dpreq = NULL;
    struct dp_callback_ctx *cb_ctx = NULL;
    char **groupnames = NULL;
    uint32_t expired_rules_num = 0;
    struct sysdb_attrs **expired_rules = NULL;
    errno_t ret;
    unsigned int flags = SYSDB_SUDO_FILTER_NONE;
    const char *attrs[] = { SYSDB_NAME,
                            NULL };

    if (cmd_ctx->domain == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Domain is not set!\n");
        return EFAULT;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    switch (cmd_ctx->type) {
        case SSS_SUDO_DEFAULTS:
            DEBUG(SSSDBG_TRACE_FUNC, "Retrieving default options "
                  "for [%s] from [%s]\n", cmd_ctx->username,
                  cmd_ctx->domain->name);
            break;
        case SSS_SUDO_USER:
            DEBUG(SSSDBG_TRACE_FUNC, "Retrieving rules "
                  "for [%s] from [%s]\n", cmd_ctx->username,
                  cmd_ctx->domain->name);
            break;
    }

    /* Fetch all expired rules:
     * sudo asks sssd twice - for defaults and for rules. If we refresh all
     * expired rules for this user and defaults at once we will save one
     * provider call
     */
    ret = sysdb_get_sudo_user_info(tmp_ctx, cmd_ctx->domain,
                                   cmd_ctx->username, NULL, &groupnames);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
             "Unable to retrieve user info [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    flags =   SYSDB_SUDO_FILTER_INCLUDE_ALL
            | SYSDB_SUDO_FILTER_INCLUDE_DFL
            | SYSDB_SUDO_FILTER_ONLY_EXPIRED
            | SYSDB_SUDO_FILTER_USERINFO;
    ret = sudosrv_get_sudorules_query_cache(tmp_ctx,
                                            cmd_ctx->domain, attrs, flags,
                                            cmd_ctx->username,
                                            cmd_ctx->uid, groupnames,
                                            cmd_ctx->sudo_ctx->inverse_order,
                                            &expired_rules, &expired_rules_num);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to retrieve expired sudo rules "
                                    "[%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    cmd_ctx->expired_rules_num = expired_rules_num;
    if (expired_rules_num > 0) {
        /* refresh expired rules then continue */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Refreshing %d expired rules\n",
                                      expired_rules_num);
        dpreq = sss_dp_get_sudoers_send(tmp_ctx, cmd_ctx->cli_ctx->rctx,
                                        cmd_ctx->domain, false,
                                        SSS_DP_SUDO_REFRESH_RULES,
                                        cmd_ctx->username,
                                        expired_rules_num, expired_rules);
        if (dpreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot issue DP request.\n");
            ret = EIO;
            goto done;
        }

        cb_ctx = talloc_zero(tmp_ctx, struct dp_callback_ctx);
        if (!cb_ctx) {
            talloc_zfree(dpreq);
            ret = ENOMEM;
            goto done;
        }

        cb_ctx->callback = sudosrv_get_sudorules_dp_callback;
        cb_ctx->ptr = cmd_ctx;
        cb_ctx->cctx = cmd_ctx->cli_ctx;
        cb_ctx->mem_ctx = cmd_ctx;

        tevent_req_set_callback(dpreq, sudosrv_dp_req_done, cb_ctx);
        ret = EAGAIN;

    } else {
        /* nothing is expired return what we have in the cache */
        DEBUG(SSSDBG_TRACE_INTERNAL, "About to get sudo rules from cache\n");
        ret = sudosrv_get_sudorules_from_cache(cmd_ctx, cmd_ctx,
                                               &cmd_ctx->rules,
                                               &cmd_ctx->num_rules);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to make a request to our cache [%d]: %s\n",
                   ret, strerror(ret));
            goto done;
        }
    }

    if (dpreq != NULL) {
        talloc_steal(cmd_ctx->cli_ctx, dpreq);
    }

    if (cb_ctx != NULL) {
        talloc_steal(cmd_ctx, cb_ctx);
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void
sudosrv_dp_req_done(struct tevent_req *req)
{
    struct dp_callback_ctx *cb_ctx =
        tevent_req_callback_data(req, struct dp_callback_ctx);
    struct cli_ctx *cli_ctx;

    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;

    cli_ctx = talloc_get_type(cb_ctx->cctx, struct cli_ctx);

    ret = sss_dp_get_sudoers_recv(cb_ctx->mem_ctx, req,
                                  &err_maj, &err_min,
                                  &err_msg);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Fatal error, killing connection!\n");
        talloc_free(cli_ctx);
        return;
    }

    cb_ctx->callback(err_maj, err_min, err_msg, cb_ctx->ptr);
}

static void
sudosrv_dp_oob_req_done(struct tevent_req *req)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Out of band refresh finished\n");
    talloc_free(req);
}

static void
sudosrv_get_sudorules_dp_callback(uint16_t err_maj, uint32_t err_min,
                                  const char *err_msg, void *ptr)
{
    struct sudo_cmd_ctx *cmd_ctx = talloc_get_type(ptr, struct sudo_cmd_ctx);
    struct tevent_req *dpreq = NULL;
    errno_t ret;

    if (err_maj) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to get information from Data Provider\n"
               "Error: %u, %u, %s\n"
               "Will try to return what we have in cache\n",
               (unsigned int)err_maj, (unsigned int)err_min, err_msg);
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "About to get sudo rules from cache\n");
    ret = sudosrv_get_sudorules_from_cache(cmd_ctx, cmd_ctx, &cmd_ctx->rules,
                                           &cmd_ctx->num_rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to make a request to our cache [%d]: %s\n",
              ret, strerror(ret));
        sudosrv_cmd_done(cmd_ctx, EIO);
        return;
    }

    if (cmd_ctx->expired_rules_num > 0
        && err_min == ENOENT) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Some expired rules were removed from the server, "
               "scheduling full refresh out of band\n");
        dpreq = sss_dp_get_sudoers_send(cmd_ctx->cli_ctx->rctx,
                                        cmd_ctx->cli_ctx->rctx,
                                        cmd_ctx->domain, false,
                                        SSS_DP_SUDO_FULL_REFRESH,
                                        cmd_ctx->username,
                                        0, NULL);
        if (dpreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot issue DP request.\n");
        } else {
            tevent_req_set_callback(dpreq, sudosrv_dp_oob_req_done, NULL);
        }
    }

    sudosrv_cmd_done(cmd_ctx, ret);
}

static errno_t sudosrv_get_sudorules_from_cache(TALLOC_CTX *mem_ctx,
                                                struct sudo_cmd_ctx *cmd_ctx,
                                                struct sysdb_attrs ***_rules,
                                                uint32_t *_num_rules)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    char **groupnames = NULL;
    const char *debug_name = NULL;
    unsigned int flags = SYSDB_SUDO_FILTER_NONE;
    struct sysdb_attrs **rules = NULL;
    uint32_t num_rules = 0;
    const char *attrs[] = { SYSDB_OBJECTCLASS,
                            SYSDB_SUDO_CACHE_AT_CN,
                            SYSDB_SUDO_CACHE_AT_USER,
                            SYSDB_SUDO_CACHE_AT_HOST,
                            SYSDB_SUDO_CACHE_AT_COMMAND,
                            SYSDB_SUDO_CACHE_AT_OPTION,
                            SYSDB_SUDO_CACHE_AT_RUNAS,
                            SYSDB_SUDO_CACHE_AT_RUNASUSER,
                            SYSDB_SUDO_CACHE_AT_RUNASGROUP,
                            SYSDB_SUDO_CACHE_AT_NOTBEFORE,
                            SYSDB_SUDO_CACHE_AT_NOTAFTER,
                            SYSDB_SUDO_CACHE_AT_ORDER,
                            NULL };

    if (cmd_ctx->domain == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Domain is not set!\n");
        return EFAULT;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    switch (cmd_ctx->type) {
    case SSS_SUDO_USER:
        debug_name = cmd_ctx->username;
        ret = sysdb_get_sudo_user_info(tmp_ctx,
                                       cmd_ctx->domain,
                                       cmd_ctx->username,
                                       NULL, &groupnames);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                 "Unable to retrieve user info [%d]: %s\n",
                  ret, strerror(ret));
            goto done;
        }
        flags = SYSDB_SUDO_FILTER_USERINFO | SYSDB_SUDO_FILTER_INCLUDE_ALL;
        break;
    case SSS_SUDO_DEFAULTS:
        debug_name = "<default options>";
        flags = SYSDB_SUDO_FILTER_INCLUDE_DFL;
        break;
    }

    ret = sudosrv_get_sudorules_query_cache(tmp_ctx,
                                            cmd_ctx->domain, attrs, flags,
                                            cmd_ctx->username,
                                            cmd_ctx->uid, groupnames,
                                            cmd_ctx->sudo_ctx->inverse_order,
                                            &rules, &num_rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
             "Unable to retrieve sudo rules [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Returning %d rules for [%s@%s]\n",
                              num_rules, debug_name, cmd_ctx->domain->name);

    if (_rules != NULL) {
        *_rules = talloc_steal(mem_ctx, rules);
    }

    if (_num_rules != NULL) {
        *_num_rules = num_rules;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sort_sudo_rules(struct sysdb_attrs **rules, size_t count, bool higher_wins);

static errno_t sudosrv_get_sudorules_query_cache(TALLOC_CTX *mem_ctx,
                                                 struct sss_domain_info *domain,
                                                 const char **attrs,
                                                 unsigned int flags,
                                                 const char *username,
                                                 uid_t uid,
                                                 char **groupnames,
                                                 bool inverse_order,
                                                 struct sysdb_attrs ***_rules,
                                                 uint32_t *_count)
{
    TALLOC_CTX *tmp_ctx;
    char *filter;
    errno_t ret;
    size_t count;
    struct sysdb_attrs **rules;
    struct ldb_message **msgs;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    ret = sysdb_get_sudo_filter(tmp_ctx, username, uid, groupnames,
                                flags, &filter);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not construct the search filter [%d]: %s\n",
               ret, strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Searching sysdb with [%s]\n", filter);

    if (IS_SUBDOMAIN(domain)) {
        /* rules are stored inside parent domain tree */
        domain = domain->parent;
    }

    ret = sysdb_search_custom(tmp_ctx, domain, filter,
                              SUDORULE_SUBDIR, attrs,
                              &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error looking up SUDO rules\n");
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
              "Could not convert ldb message to sysdb_attrs\n");
        goto done;
    }

    ret = sort_sudo_rules(rules, count, inverse_order);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not sort rules by sudoOrder\n");
        goto done;
    }

    *_rules = talloc_steal(mem_ctx, rules);
    *_count = (uint32_t)count;

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static int
sudo_order_cmp(const void *a, const void *b, bool lower_wins)
{
    struct sysdb_attrs *r1, *r2;
    uint32_t o1, o2;
    int ret;

    r1 = * (struct sysdb_attrs * const *) a;
    r2 = * (struct sysdb_attrs * const *) b;
    if (!r1 || !r2) {
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: Wrong data?\n");
        return 0;
    }

    ret = sysdb_attrs_get_uint32_t(r1, SYSDB_SUDO_CACHE_AT_ORDER, &o1);
    if (ret == ENOENT) {
        /* man sudoers-ldap: If the sudoOrder attribute is not present,
         * a value of 0 is assumed */
        o1 = 0;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get sudoOrder value\n");
        return 0;
    }

    ret = sysdb_attrs_get_uint32_t(r2, SYSDB_SUDO_CACHE_AT_ORDER, &o2);
    if (ret == ENOENT) {
        /* man sudoers-ldap: If the sudoOrder attribute is not present,
         * a value of 0 is assumed */
        o2 = 0;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get sudoOrder value\n");
        return 0;
    }

    if (lower_wins) {
        /* The lowest value takes priority. Original wrong SSSD behaviour. */
        if (o1 > o2) {
            return 1;
        } else if (o1 < o2) {
            return -1;
        }
    } else {
        /* The higher value takes priority. Standard LDAP behaviour. */
        if (o1 < o2) {
            return 1;
        } else if (o1 > o2) {
            return -1;
        }
    }

    return 0;
}

static int
sudo_order_low_cmp_fn(const void *a, const void *b)
{
    return sudo_order_cmp(a, b, true);
}

static int
sudo_order_high_cmp_fn(const void *a, const void *b)
{
    return sudo_order_cmp(a, b, false);
}

static errno_t
sort_sudo_rules(struct sysdb_attrs **rules, size_t count, bool lower_wins)
{
    if (lower_wins) {
        DEBUG(SSSDBG_TRACE_FUNC, "Sorting rules with lower-wins logic\n");
        qsort(rules, count, sizeof(struct sysdb_attrs *),
              sudo_order_low_cmp_fn);
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Sorting rules with higher-wins logic\n");
        qsort(rules, count, sizeof(struct sysdb_attrs *),
              sudo_order_high_cmp_fn);
    }

    return EOK;
}
