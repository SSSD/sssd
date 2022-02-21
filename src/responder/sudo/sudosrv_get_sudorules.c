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
#include "responder/common/cache_req/cache_req.h"
#include "responder/sudo/sudosrv_private.h"
#include "providers/data_provider.h"

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

static errno_t sudosrv_format_runas(struct resp_ctx *rctx,
                                    struct sysdb_attrs *rule,
                                    const char *attr)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message_element *el;
    struct sss_domain_info *dom;
    const char *value;
    char *fqname;
    unsigned int i;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    ret = sysdb_attrs_get_el_ext(rule, attr, false, &el);
    if (ret == ENOENT) {
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get %s attribute "
              "[%d]: %s\n", attr, ret, sss_strerror(ret));
        goto done;
    }

    for (i = 0; i < el->num_values; i++) {
        value = (const char *)el->values[i].data;
        if (value == NULL) {
            continue;
        }

        dom = find_domain_by_object_name_ex(rctx->domains, value, true,
                                            SSS_GND_DESCEND);
        if (dom == NULL) {
            continue;
        }

        ret = sss_output_fqname(tmp_ctx, dom, value,
                                rctx->override_space, &fqname);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to convert %s to output fqname "
                  "[%d]: %s\n", value, ret, sss_strerror(ret));
            goto done;
        }

        talloc_free(el->values[i].data);
        el->values[i].data = (uint8_t*)talloc_steal(el->values, fqname);
        el->values[i].length = strlen(fqname);
    }

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t sudosrv_format_rules(struct resp_ctx *rctx,
                                    struct sysdb_attrs **rules,
                                    uint32_t num_rules)
{
    uint32_t i;
    errno_t ret = EOK;


    for (i = 0; i < num_rules; i++) {
        ret = sudosrv_format_runas(rctx, rules[i],
                                   SYSDB_SUDO_CACHE_AT_RUNAS);
        if (ret != EOK) {
            return ret;
        }

        ret = sudosrv_format_runas(rctx, rules[i],
                                   SYSDB_SUDO_CACHE_AT_RUNASUSER);
        if (ret != EOK) {
            return ret;
        }

        ret = sudosrv_format_runas(rctx, rules[i],
                                   SYSDB_SUDO_CACHE_AT_RUNASGROUP);
        if (ret != EOK) {
            return ret;
        }
    }

    return ret;
}

static errno_t sudosrv_query_cache(TALLOC_CTX *mem_ctx,
                                   struct sss_domain_info *domain,
                                   const char **attrs,
                                   const char *filter,
                                   struct sysdb_attrs ***_rules,
                                   uint32_t *_count)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    size_t count;
    struct sysdb_attrs **rules;
    struct ldb_message **msgs;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Searching sysdb with [%s]\n", filter);

    if (IS_SUBDOMAIN(domain)) {
        /* rules are stored inside parent domain tree */
        domain = domain->parent;
    }

    ret = sysdb_search_custom(tmp_ctx, domain, filter, SUDORULE_SUBDIR,
                              attrs, &count, &msgs);
    if (ret == ENOENT) {
        *_rules = NULL;
        *_count = 0;
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error looking up SUDO rules\n");
        goto done;
    }

    ret = sysdb_msg2attrs(tmp_ctx, count, msgs, &rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not convert ldb message to sysdb_attrs\n");
        goto done;
    }

    *_rules = talloc_steal(mem_ctx, rules);
    *_count = (uint32_t)count;

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sudosrv_expired_rules(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     uid_t uid,
                                     const char *username,
                                     char **groups,
                                     struct sysdb_attrs ***_rules,
                                     uint32_t *_num_rules)
{
    const char *attrs[] = { SYSDB_NAME, NULL };
    char *filter;
    errno_t ret;

    filter = sysdb_sudo_filter_expired(NULL, username, groups, uid);
    if (filter == NULL) {
        return ENOMEM;
    }

    ret = sudosrv_query_cache(mem_ctx, domain, attrs, filter,
                              _rules, _num_rules);
    talloc_free(filter);

    return ret;
}

static errno_t sudosrv_cached_rules_by_user(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            uid_t cli_uid,
                                            uid_t orig_uid,
                                            const char *username,
                                            char **groupnames,
                                            struct sysdb_attrs ***_rules,
                                            uint32_t *_num_rules)
{
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs **rules;
    uint32_t num_rules;
    uint32_t i;
    const char *filter;
    const char *val;
    errno_t ret;
    const char *attrs[] = { SYSDB_OBJECTCLASS,
                            SYSDB_SUDO_CACHE_AT_CN,
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

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    filter = sysdb_sudo_filter_user(tmp_ctx, username, groupnames, orig_uid);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sudosrv_query_cache(tmp_ctx, domain, attrs, filter,
                              &rules, &num_rules);
    if (ret != EOK) {
        goto done;
    }

    val = talloc_asprintf(tmp_ctx, "#%"SPRIuid, cli_uid);
    if (val == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Add sudoUser: #uid to prevent conflicts with fqnames. */
    DEBUG(SSSDBG_TRACE_FUNC, "Replacing sudoUser attribute with "
          "sudoUser: %s\n", val);
    for (i = 0; i < num_rules; i++) {
        ret = sysdb_attrs_add_string(rules[i], SYSDB_SUDO_CACHE_AT_USER, val);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to alter sudoUser attribute "
                  "[%d]: %s\n", ret, sss_strerror(ret));
        }
    }

    *_rules = talloc_steal(mem_ctx, rules);
    *_num_rules = num_rules;

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sudosrv_cached_rules_by_ng(TALLOC_CTX *mem_ctx,
                                          struct sss_domain_info *domain,
                                          uid_t uid,
                                          const char *username,
                                          char **groupnames,
                                          struct sysdb_attrs ***_rules,
                                          uint32_t *_num_rules)
{
    char *filter;
    errno_t ret;
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

    filter = sysdb_sudo_filter_netgroups(NULL, username, groupnames, uid);
    if (filter == NULL) {
        return ENOMEM;
    }

    ret = sudosrv_query_cache(mem_ctx, domain, attrs, filter,
                              _rules, _num_rules);
    talloc_free(filter);

    return ret;
}

static errno_t sudosrv_cached_rules(TALLOC_CTX *mem_ctx,
                                    struct resp_ctx *rctx,
                                    struct sss_domain_info *domain,
                                    uid_t cli_uid,
                                    uid_t orig_uid,
                                    const char *username,
                                    char **groups,
                                    bool inverse_order,
                                    struct sysdb_attrs ***_rules,
                                    uint32_t *_num_rules)
{
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs **user_rules;
    struct sysdb_attrs **ng_rules;
    struct sysdb_attrs **rules;
    uint32_t num_user_rules;
    uint32_t num_ng_rules;
    uint32_t num_rules;
    uint32_t rule_iter, i;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sudosrv_cached_rules_by_user(tmp_ctx, domain,
                                       cli_uid, orig_uid, username, groups,
                                       &user_rules, &num_user_rules);
    if (ret != EOK) {
        goto done;
    }

    ret = sudosrv_cached_rules_by_ng(tmp_ctx, domain,
                                     orig_uid, username, groups,
                                     &ng_rules, &num_ng_rules);
    if (ret != EOK) {
        goto done;
    }

    num_rules = num_user_rules + num_ng_rules;
    if (num_rules == 0) {
        *_rules = NULL;
        *_num_rules = 0;
        ret = EOK;
        goto done;
    }

    rules = talloc_array(tmp_ctx, struct sysdb_attrs *, num_rules);
    if (rules == NULL) {
        ret = ENOMEM;
        goto done;
    }

    rule_iter = 0;
    for (i = 0; i < num_user_rules; rule_iter++, i++) {
        rules[rule_iter] = talloc_steal(rules, user_rules[i]);
    }

    for (i = 0; i < num_ng_rules; rule_iter++, i++) {
        rules[rule_iter] = talloc_steal(rules, ng_rules[i]);
    }

    ret = sort_sudo_rules(rules, num_rules, inverse_order);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not sort rules by sudoOrder\n");
        goto done;
    }

    ret = sudosrv_format_rules(rctx, rules, num_rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not format sudo rules\n");
        goto done;
    }

    *_rules = talloc_steal(mem_ctx, rules);
    *_num_rules = num_rules;

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sudosrv_cached_defaults(TALLOC_CTX *mem_ctx,
                                       struct sss_domain_info *domain,
                                       struct sysdb_attrs ***_rules,
                                       uint32_t *_num_rules)
{
    char *filter;
    errno_t ret;
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

    filter = sysdb_sudo_filter_defaults(NULL);
    if (filter == NULL) {
        return ENOMEM;
    }

    ret = sudosrv_query_cache(mem_ctx, domain, attrs, filter,
                              _rules, _num_rules);
    talloc_free(filter);

    return ret;
}

static errno_t sudosrv_fetch_rules(TALLOC_CTX *mem_ctx,
                                   struct resp_ctx *rctx,
                                   enum sss_sudo_type type,
                                   struct sss_domain_info *domain,
                                   uid_t cli_uid,
                                   uid_t orig_uid,
                                   const char *username,
                                   char **groups,
                                   bool inverse_order,
                                   struct sysdb_attrs ***_rules,
                                   uint32_t *_num_rules)
{
    struct sysdb_attrs **rules = NULL;
    const char *debug_name = "unknown";
    uint32_t num_rules;
    errno_t ret;

    switch (type) {
    case SSS_SUDO_USER:
        DEBUG(SSSDBG_TRACE_FUNC, "Retrieving rules for [%s@%s]\n",
              username, domain->name);
        debug_name = "rules";

        ret = sudosrv_cached_rules(mem_ctx, rctx, domain,
                                   cli_uid, orig_uid, username, groups,
                                   inverse_order, &rules, &num_rules);

        break;
    case SSS_SUDO_DEFAULTS:
        debug_name = "default options";
        DEBUG(SSSDBG_TRACE_FUNC, "Retrieving default options for [%s@%s]\n",
              username, domain->name);

        ret = sudosrv_cached_defaults(mem_ctx, domain, &rules, &num_rules);

        break;
    default:
        ret = EINVAL;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to retrieve %s [%d]: %s\n",
              debug_name, ret, sss_strerror(ret));
        return ret;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Returning %u %s for [%s@%s]\n",
          num_rules, debug_name, username, domain->name);

    *_rules = rules;
    *_num_rules = num_rules;

    return EOK;
}

static void
sudosrv_dp_oob_req_done(struct tevent_req *req)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Out of band refresh finished\n");
    talloc_free(req);
}

struct sudosrv_refresh_rules_state {
    struct resp_ctx *rctx;
    struct sss_domain_info *domain;
    const char *username;
};

static void sudosrv_refresh_rules_done(struct tevent_req *subreq);

static struct tevent_req *
sudosrv_refresh_rules_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct resp_ctx *rctx,
                           struct sss_domain_info *domain,
                           int threshold,
                           uid_t uid,
                           const char *username,
                           char **groups)
{
    struct sudosrv_refresh_rules_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sysdb_attrs **rules;
    uint32_t num_rules;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sudosrv_refresh_rules_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->rctx = rctx;
    state->domain = domain;
    state->username = username;

    ret = sudosrv_expired_rules(state, domain, uid, username, groups,
                                &rules, &num_rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to retrieve expired sudo rules [%d]: %s\n",
              ret, strerror(ret));
        goto immediately;
    }

    if (num_rules == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "No expired rules were found for [%s@%s].\n",
              username, domain->name);
        ret = EOK;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Refreshing %d expired rules of [%s@%s]\n",
          num_rules, username, domain->name);

    if (num_rules > threshold) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Rules threshold [%d] is reached, performing full refresh "
              "instead.\n", threshold);

        subreq = sss_dp_get_sudoers_send(state, rctx, domain, false,
                                         SSS_DP_SUDO_FULL_REFRESH,
                                         username, 0, NULL);
    } else {
        subreq = sss_dp_get_sudoers_send(state, rctx, domain, false,
                                         SSS_DP_SUDO_REFRESH_RULES,
                                         username, num_rules, rules);
    }

    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sudosrv_refresh_rules_done, req);

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static void sudosrv_refresh_rules_done(struct tevent_req *subreq)
{
    struct sudosrv_refresh_rules_state *state;
    struct tevent_req *req;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    const char *err_msg;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sudosrv_refresh_rules_state);

    ret = sss_dp_get_sudoers_recv(state, subreq, &err_maj, &err_min, &err_msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to refresh rules [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    } else if (err_maj != 0 || err_min != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to get information from Data Provider, "
              "Error: %u, %u, %s\n",
              (unsigned int)err_maj, (unsigned int)err_min,
              (err_msg == NULL ? "(null)" : err_msg));
        goto done;
    }

    if (err_min == ENOENT) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Some expired rules were removed from the server, scheduling "
              "full refresh out of band\n");
        subreq = sss_dp_get_sudoers_send(state->rctx, state->rctx,
                                         state->domain, false,
                                         SSS_DP_SUDO_FULL_REFRESH,
                                         state->username, 0, NULL);
        if (subreq == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Cannot issue DP request.\n");
            ret = EOK; /* We don't care. */
            goto done;
        }

        tevent_req_set_callback(subreq, sudosrv_dp_oob_req_done, NULL);
    }

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t sudosrv_refresh_rules_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sudosrv_get_rules_state {
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    enum sss_sudo_type type;
    uid_t cli_uid;
    const char *username;
    struct sss_domain_info *domain;
    char **groups;
    bool inverse_order;
    int threshold;

    uid_t orig_uid;
    const char *orig_username;

    struct sysdb_attrs **rules;
    uint32_t num_rules;
};

static void sudosrv_get_rules_initgr_done(struct tevent_req *subreq);
static void sudosrv_get_rules_done(struct tevent_req *subreq);

struct tevent_req *sudosrv_get_rules_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sudo_ctx *sudo_ctx,
                                          enum sss_sudo_type type,
                                          uid_t cli_uid,
                                          const char *username)
{
    struct sudosrv_get_rules_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sudosrv_get_rules_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->rctx = sudo_ctx->rctx;
    state->type = type;
    state->cli_uid = cli_uid;
    state->inverse_order = sudo_ctx->inverse_order;
    state->threshold = sudo_ctx->threshold;

    DEBUG(SSSDBG_TRACE_FUNC, "Running initgroups for [%s]\n", username);

    subreq = cache_req_initgr_by_name_send(state, ev, sudo_ctx->rctx,
                                           sudo_ctx->rctx->ncache, 0,
                                           CACHE_REQ_POSIX_DOM, NULL,
                                           username);
    if (subreq == NULL) {
        ret = ENOMEM;
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    } else {
        tevent_req_set_callback(subreq, sudosrv_get_rules_initgr_done, req);
    }

    return req;
}

static void sudosrv_get_rules_initgr_done(struct tevent_req *subreq)
{
    struct sudosrv_get_rules_state *state;
    struct cache_req_result *result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sudosrv_get_rules_state);

    ret = cache_req_initgr_by_name_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    state->domain = result->domain;
    state->username = talloc_steal(state, result->lookup_name);
    talloc_zfree(result);

    ret = sysdb_get_sudo_user_info(state, state->domain, state->username,
                                   &state->orig_username,
                                   &state->orig_uid,
                                   &state->groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to obtain user groups [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    subreq = sudosrv_refresh_rules_send(state, state->ev, state->rctx,
                                        state->domain, state->threshold,
                                        state->orig_uid,
                                        state->orig_username,
                                        state->groups);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sudosrv_get_rules_done, req);

    ret = EAGAIN;

done:
    if (ret != EOK && ret != EAGAIN) {
        tevent_req_error(req, ret);
        return;
    } else if (ret != EAGAIN) {
        tevent_req_done(req);
    }
}

static void sudosrv_get_rules_done(struct tevent_req *subreq)
{
    struct sudosrv_get_rules_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sudosrv_get_rules_state);

    ret = sudosrv_refresh_rules_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to refresh expired rules, we will return what is "
              "in cache.\n");
    }

    ret = sudosrv_fetch_rules(state, state->rctx, state->type, state->domain,
                              state->cli_uid,
                              state->orig_uid,
                              state->orig_username,
                              state->groups,
                              state->inverse_order,
                              &state->rules, &state->num_rules);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t sudosrv_get_rules_recv(TALLOC_CTX *mem_ctx,
                               struct tevent_req *req,
                               struct sysdb_attrs ***_rules,
                               uint32_t *_num_rules)
{
    struct sudosrv_get_rules_state *state = NULL;
    state = tevent_req_data(req, struct sudosrv_get_rules_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_rules = talloc_steal(mem_ctx, state->rules);
    *_num_rules = state->num_rules;

    return EOK;
}
