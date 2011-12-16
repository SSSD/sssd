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

#include <stdint.h>
#include <string.h>
#include <talloc.h>

#include "util/util.h"
#include "db/sysdb_sudo.h"
#include "responder/sudo/sudosrv_private.h"

static errno_t sudosrv_get_user(struct sudo_dom_ctx *dctx);
static errno_t sudosrv_get_rules(struct sudo_dom_ctx *dctx);

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
    ret = sudosrv_get_rules(dctx);
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
    struct sss_domain_info *dom = dctx->domain;
    struct sudo_cmd_ctx *cmd_ctx = dctx->cmd_ctx;
    struct cli_ctx *cli_ctx = dctx->cmd_ctx->cli_ctx;
    struct sysdb_ctx *sysdb;
    time_t cache_expire = 0;
    struct tevent_req *dpreq;
    struct dp_callback_ctx *cb_ctx;
    errno_t ret;

    while (dom) {
       /* if it is a domainless search, skip domains that require fully
        * qualified names instead */
        while (dom && cmd_ctx->check_next && dom->fqnames) {
            dom = dom->next;
        }

        if (!dom) break;

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        DEBUG(SSSDBG_FUNC_DATA, ("Requesting info about [%s@%s]\n",
              cmd_ctx->username, dom->name));

        ret = sysdb_get_ctx_from_list(cli_ctx->rctx->db_list,
                                      dctx->domain, &sysdb);
        if (ret != EOK) {
             DEBUG(SSSDBG_CRIT_FAILURE,
                   ("sysdb context not found for this domain!\n"));
             return EIO;
        }

        ret = sysdb_getpwnam(dctx, sysdb, cmd_ctx->username, &dctx->user);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Failed to make request to our cache!\n"));
            return EIO;
        }

        if (dctx->user->count > 1) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("getpwnam call returned more than one result !?!\n"));
            return EIO;
        }

        if (dctx->user->count == 0 && !dctx->check_provider) {
            /* if a multidomain search, try with next */
            if (cmd_ctx->check_next) {
                dctx->check_provider = true;
                dom = dom->next;
                if (dom) continue;
            }

            DEBUG(SSSDBG_MINOR_FAILURE, ("No results for getpwnam call\n"));
            return ENOENT;
        }

        /* One result found, check cache expiry */
        if (dctx->user->count == 1) {
            cache_expire = ldb_msg_find_attr_as_uint64(dctx->user->msgs[0],
                                                       SYSDB_CACHE_EXPIRE, 0);
        }

        /* If cache miss and we haven't checked DP yet OR the entry is
         * outdated, go to DP */
        if ((dctx->user->count == 0 && dctx->check_provider) ||
             cache_expire < time(NULL)) {
            dpreq = sss_dp_get_account_send(cli_ctx, cli_ctx->rctx,
                                            dom, false, SSS_DP_INITGROUPS,
                                            cmd_ctx->username, 0);
            if (!dpreq) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      ("Out of memory sending data provider request\n"));
                return ENOMEM;
            }

            cb_ctx = talloc_zero(cli_ctx, struct dp_callback_ctx);
            if(!cb_ctx) {
                talloc_zfree(dpreq);
                return ENOMEM;
            }

            cb_ctx->callback = sudosrv_check_user_dp_callback;
            cb_ctx->ptr = dctx;
            cb_ctx->cctx = cli_ctx;
            cb_ctx->mem_ctx = cli_ctx;

            tevent_req_set_callback(dpreq, sudosrv_dp_send_acct_req_done, cb_ctx);

            /* tell caller we are in an async call */
            return EAGAIN;
        }

        DEBUG(SSSDBG_TRACE_FUNC, ("Returning info for user [%s@%s]\n",
              cmd_ctx->username, dctx->domain->name));
        return EOK;
    }

    return ENOENT;
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

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Data Provider returned, check the cache again\n"));
    dctx->check_provider = false;
    ret = sudosrv_get_user(dctx);
    /* FIXME - set entry into cache so that we don't perform initgroups too often */
    if (ret == EAGAIN) {
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not look up the user [%d]: %s\n",
              ret, strerror(ret)));
        sudosrv_cmd_done(dctx, EIO);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Looking up sudo rules..\n"));
    ret = sudosrv_get_rules(dctx);
    if (ret == EAGAIN) {
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Error getting sudo rules [%d]: %s\n",
              ret, strerror(ret)));
        sudosrv_cmd_done(dctx, EIO);
        return;
    }

done:
    sudosrv_cmd_done(dctx, ret);
}

static errno_t sudosrv_get_sudorules_from_cache(struct sudo_dom_ctx *dctx);
static void sudosrv_get_sudorules_dp_callback(struct tevent_req *req);

static errno_t sudosrv_get_rules(struct sudo_dom_ctx *dctx)
{
    struct tevent_req *dpreq;
    struct sudo_cmd_ctx *cmd_ctx = dctx->cmd_ctx;

    /* FIXME - cache logic will be here. For now, just refresh
     * the cache unconditionally */
    dpreq = sudosrv_dp_refresh_send(cmd_ctx->cli_ctx->rctx,
                                    dctx->domain, cmd_ctx->username);
    if (dpreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Fatal: Sysdb CTX not found for this domain!\n"));
        return EIO;
    }
    tevent_req_set_callback(dpreq, sudosrv_get_sudorules_dp_callback, dctx);
    return EAGAIN;
}

static void sudosrv_get_sudorules_dp_callback(struct tevent_req *req)
{
    struct sudo_dom_ctx *dctx;
    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;

    dctx = tevent_req_callback_data(req, struct sudo_dom_ctx);

    ret = sudosrv_dp_refresh_recv(req, &err_maj, &err_min);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Data provider returned an error [%d]: %s "
               "DBus error min: %d maj %d\n",
               ret, strerror(ret), err_maj, err_min));
        sudosrv_cmd_done(dctx, EIO);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, ("About to get sudo rules from cache\n"));
    ret = sudosrv_get_sudorules_from_cache(dctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Failed to make a request to our cache [%d]: %s\n",
              ret, strerror(ret)));
        sudosrv_cmd_done(dctx, EIO);
        return;
    }

    sudosrv_cmd_done(dctx, ret);
}

static errno_t sudosrv_get_sudorules_query_cache(TALLOC_CTX *mem_ctx,
                                                 struct sysdb_ctx *sysdb,
                                                 const char *username,
                                                 uid_t uid,
                                                 char **groupnames,
                                                 struct sysdb_attrs ***_rules,
                                                 size_t *_count);

static errno_t sudosrv_get_sudorules_from_cache(struct sudo_dom_ctx *dctx)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    struct sysdb_ctx *sysdb;
    struct cli_ctx *cli_ctx = dctx->cmd_ctx->cli_ctx;
    uid_t uid;
    char **groupnames;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    ret = sysdb_get_ctx_from_list(cli_ctx->rctx->db_list,
                                  dctx->domain, &sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("sysdb context not found for this domain!\n"));
        ret = EIO;
        goto done;
    }

    ret = sysdb_get_sudo_user_info(tmp_ctx, dctx->cmd_ctx->username,
                                   sysdb, &uid, &groupnames);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
             ("Unable to retrieve user info [%d]: %s\n", strerror(ret)));
        goto done;
    }

    ret = sudosrv_get_sudorules_query_cache(dctx, sysdb,
                                            dctx->cmd_ctx->username,
                                            uid, groupnames,
                                            &dctx->res, &dctx->res_count);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
             ("Unable to retrieve sudo rules [%d]: %s\n", strerror(ret)));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Returning rules for [%s@%s]\n",
          dctx->cmd_ctx->username, dctx->domain->name));

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sort_sudo_rules(struct sysdb_attrs **rules, size_t count);

static errno_t sudosrv_get_sudorules_query_cache(TALLOC_CTX *mem_ctx,
                                                 struct sysdb_ctx *sysdb,
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

    ret = sysdb_get_sudo_filter(tmp_ctx, username, uid, groupnames,
                    (SYSDB_SUDO_FILTER_NGRS | SYSDB_SUDO_FILTER_INCLUDE_ALL |
                    SYSDB_SUDO_FILTER_INCLUDE_DFL), &filter);
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

char * sudosrv_get_sudorules_parse_query(TALLOC_CTX *mem_ctx,
                                         const char *query_body,
                                         int query_len)
{
    if (query_len < 2 || ((query_len - 1) != strlen(query_body))) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid query.\n"));
        return NULL;
    }

    return talloc_strdup(mem_ctx, query_body);
}

/*
 * Response format:
 * <error_code(uint32_t)><num_entries(uint32_t)><rule1><rule2>...
 * <ruleN> = <num_attrs(uint32_t)><attr1><attr2>...
 * <attrN>  = <name(char*)>\0<num_values(uint32_t)><value1(char*)>\0<value2(char*)>\0...
 *
 * if <error_code> is not SSS_SUDO_ERROR_OK, the rest of the data is skipped.
 */
int sudosrv_get_sudorules_build_response(TALLOC_CTX *mem_ctx,
                                         uint32_t error,
                                         int rules_num,
                                         struct sysdb_attrs **rules,
                                         uint8_t **_response_body,
                                         size_t *_response_len)
{
    uint8_t *response_body = NULL;
    size_t response_len = 0;
    TALLOC_CTX *tmp_ctx = NULL;
    int i = 0;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        return ENOMEM;
    }

    /* error code */
    ret = sudosrv_response_append_uint32(tmp_ctx, error,
                                         &response_body, &response_len);
    if (ret != EOK) {
        goto fail;
    }

    if (error != SSS_SUDO_ERROR_OK) {
        goto done;
    }

    /* rules count */
    ret = sudosrv_response_append_uint32(tmp_ctx, (uint32_t)rules_num,
                                         &response_body, &response_len);
    if (ret != EOK) {
        goto fail;
    }

    /* rules */
    for (i = 0; i < rules_num; i++) {
        ret = sudosrv_response_append_rule(tmp_ctx, rules[i]->num, rules[i]->a,
                                           &response_body, &response_len);
        if (ret != EOK) {
            goto fail;
        }
    }

done:
    *_response_body = talloc_steal(mem_ctx, response_body);
    *_response_len = response_len;

    ret = EOK;

fail:
    talloc_free(tmp_ctx);
    return ret;
}
