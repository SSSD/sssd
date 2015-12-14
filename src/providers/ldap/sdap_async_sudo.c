/*
    SSSD

    Async LDAP Helper routines for sudo

    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include <errno.h>
#include <talloc.h>
#include <tevent.h>

#include "providers/dp_backend.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_sudo.h"
#include "providers/ldap/sdap_sudo_cache.h"
#include "db/sysdb_sudo.h"

struct sdap_sudo_load_sudoers_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;

    int timeout;
    const char **attrs;
    const char *filter;
    size_t base_iter;
    struct sdap_search_base **search_bases;

    struct sysdb_attrs **rules;
    size_t num_rules;
};

static errno_t sdap_sudo_load_sudoers_next_base(struct tevent_req *req);
static void sdap_sudo_load_sudoers_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_sudo_load_sudoers_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sdap_options *opts,
                            struct sdap_handle *sh,
                            const char *ldap_filter)
{
    struct tevent_req *req;
    struct sdap_sudo_load_sudoers_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_sudo_load_sudoers_state);
    if (!req) {
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->base_iter = 0;
    state->search_bases = opts->sdom->sudo_search_bases;
    state->filter = ldap_filter;
    state->timeout = dp_opt_get_int(opts->basic, SDAP_SEARCH_TIMEOUT);
    state->rules = NULL;
    state->num_rules = 0;

    if (state->search_bases == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "SUDOERS lookup request without a search base\n");
        ret = EINVAL;
        goto immediately;
    }

    /* create attrs from map */
    ret = build_attrs_from_map(state, opts->sudorule_map, SDAP_OPTS_SUDO,
                               NULL, &state->attrs, NULL);
    if (ret != EOK) {
        goto immediately;
    }

    /* begin search */
    ret = sdap_sudo_load_sudoers_next_base(req);
    if (ret == EAGAIN) {
        /* asynchronous processing */
        return req;
    }

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t sdap_sudo_load_sudoers_next_base(struct tevent_req *req)
{
    struct sdap_sudo_load_sudoers_state *state;
    struct sdap_search_base *base;
    struct tevent_req *subreq;
    char *filter;

    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);
    base = state->search_bases[state->base_iter];
    if (base == NULL) {
        return EOK;
    }

    /* Combine lookup and search base filters. */
    filter = sdap_get_id_specific_filter(state, state->filter, base->filter);
    if (filter == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Searching for sudo rules with base [%s]\n",
                             base->basedn);

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   base->basedn, base->scope, filter,
                                   state->attrs, state->opts->sudorule_map,
                                   SDAP_OPTS_SUDO, state->timeout, true);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_sudo_load_sudoers_done, req);

    state->base_iter++;
    return EAGAIN;
}

static void sdap_sudo_load_sudoers_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_sudo_load_sudoers_state *state;
    struct sdap_search_base *search_base;
    struct sysdb_attrs **attrs = NULL;
    size_t count;
    int ret;
    size_t i;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);
    search_base = state->search_bases[state->base_iter - 1];

    DEBUG(SSSDBG_TRACE_FUNC, "Receiving sudo rules with base [%s]\n",
                             search_base->basedn);

    ret = sdap_get_generic_recv(subreq, state, &count, &attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Add rules to result. */
    if (count > 0) {
        state->rules = talloc_realloc(state, state->rules,
                                      struct sysdb_attrs *,
                                      state->num_rules + count);
        if (state->rules == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        for (i = 0; i < count; i++) {
            state->rules[state->num_rules + i] = talloc_steal(state->rules,
                                                              attrs[i]);
        }

        state->num_rules += count;
    }

    /* Try next search base. */
    ret = sdap_sudo_load_sudoers_next_base(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static int sdap_sudo_load_sudoers_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       size_t *num_rules,
                                       struct sysdb_attrs ***rules)
{
    struct sdap_sudo_load_sudoers_state *state;

    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *num_rules = state->num_rules;
    *rules = talloc_steal(mem_ctx, state->rules);

    return EOK;
}

static int sdap_sudo_purge_sudoers(struct sss_domain_info *dom,
                                   const char *filter,
                                   struct sdap_attr_map *map,
                                   size_t rules_count,
                                   struct sysdb_attrs **rules)
{
    const char *name;
    size_t i;
    errno_t ret;

    if (filter == NULL) {
        /* removes downloaded rules from the cache */
        if (rules_count == 0 || rules == NULL) {
            return EOK;
        }

        for (i = 0; i < rules_count; i++) {
            ret = sysdb_attrs_get_string(rules[i],
                                         map[SDAP_AT_SUDO_NAME].sys_name,
                                         &name);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to retrieve rule name: [%s]\n", strerror(ret));
                continue;
            }

            ret = sysdb_sudo_purge_byname(dom, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to delete rule %s: [%s]\n",
                      name, strerror(ret));
                continue;
            }
        }

        ret = EOK;
    } else {
        /* purge cache by provided filter */
        ret = sysdb_sudo_purge_byfilter(dom, filter);
        if (ret != EOK) {
            goto done;
        }
    }

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "failed to purge sudo rules [%d]: %s\n",
                                 ret, strerror(ret));
    }

    return ret;
}

static int sdap_sudo_store_sudoers(TALLOC_CTX *mem_ctx,
                                   struct sss_domain_info *domain,
                                   struct sdap_options *opts,
                                   size_t rules_count,
                                   struct sysdb_attrs **rules,
                                   int cache_timeout,
                                   time_t now,
                                   char **_usn)
{
    errno_t ret;

    /* Empty sudoers? Done. */
    if (rules_count == 0 || rules == NULL) {
        *_usn = NULL;
        return EOK;
    }

    ret = sdap_save_native_sudorule_list(mem_ctx, domain,
                                         opts->sudorule_map, rules,
                                         rules_count, cache_timeout, now,
                                         _usn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "failed to save sudo rules [%d]: %s\n",
              ret, strerror(ret));
        return ret;
    }

    return EOK;
}

static void sdap_sudo_set_usn(struct sdap_server_opts *srv_opts, char *usn)
{
    unsigned int usn_number;
    char *endptr = NULL;

    if (srv_opts == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Bug: srv_opts is NULL\n");
        return;
    }

    if (usn == NULL) {
        /* If the USN value is unknown and we don't have max_sudo_value set
         * (possibly first full refresh which did not find any rule) we will
         * set zero so smart refresh can pick up. */
        if (srv_opts->max_sudo_value == NULL) {
            srv_opts->max_sudo_value = talloc_strdup(srv_opts, "0");
            if (srv_opts->max_sudo_value == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            }
            return;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Empty USN, ignoring\n");
        return;
    }

    talloc_zfree(srv_opts->max_sudo_value);
    srv_opts->max_sudo_value = talloc_steal(srv_opts, usn);

    usn_number = strtoul(usn, &endptr, 10);
    if ((endptr == NULL || (*endptr == '\0' && endptr != usn))
         && (usn_number > srv_opts->last_usn)) {
         srv_opts->last_usn = usn_number;
    }

    DEBUG(SSSDBG_FUNC_DATA, "SUDO higher USN value: [%s]\n",
                             srv_opts->max_sudo_value);
}

static char *sdap_sudo_build_host_filter(TALLOC_CTX *mem_ctx,
                                         struct sdap_attr_map *map,
                                         char **hostnames,
                                         char **ip_addr,
                                         bool netgroups,
                                         bool regexp)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *filter = NULL;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return NULL;
    }

    filter = talloc_strdup(tmp_ctx, "(|");
    if (filter == NULL) {
        goto done;
    }

    /* sudoHost is not specified */
    filter = talloc_asprintf_append_buffer(filter, "(!(%s=*))",
                                           map[SDAP_AT_SUDO_HOST].name);
    if (filter == NULL) {
        goto done;
    }

    /* ALL */
    filter = talloc_asprintf_append_buffer(filter, "(%s=ALL)",
                                           map[SDAP_AT_SUDO_HOST].name);
    if (filter == NULL) {
        goto done;
    }

    /* hostnames */
    if (hostnames != NULL) {
        for (i = 0; hostnames[i] != NULL; i++) {
            filter = talloc_asprintf_append_buffer(filter, "(%s=%s)",
                                                   map[SDAP_AT_SUDO_HOST].name,
                                                   hostnames[i]);
            if (filter == NULL) {
                goto done;
            }
        }
    }

    /* ip addresses and networks */
    if (ip_addr != NULL) {
        for (i = 0; ip_addr[i] != NULL; i++) {
            filter = talloc_asprintf_append_buffer(filter, "(%s=%s)",
                                                   map[SDAP_AT_SUDO_HOST].name,
                                                   ip_addr[i]);
            if (filter == NULL) {
                goto done;
            }
        }
    }

    /* sudoHost contains netgroup - will be filtered more by sudo */
    if (netgroups) {
        filter = talloc_asprintf_append_buffer(filter, SDAP_SUDO_FILTER_NETGROUP,
                                               map[SDAP_AT_SUDO_HOST].name,
                                               "*");
        if (filter == NULL) {
            goto done;
        }
    }

    /* sudoHost contains regexp - will be filtered more by sudo */
    /* from sudo match.c :
     * #define has_meta(s)  (strpbrk(s, "\\?*[]") != NULL)
     */
    if (regexp) {
        filter = talloc_asprintf_append_buffer(filter,
                                               "(|(%s=*\\\\*)(%s=*?*)(%s=*\\2A*)"
                                                 "(%s=*[*]*))",
                                               map[SDAP_AT_SUDO_HOST].name,
                                               map[SDAP_AT_SUDO_HOST].name,
                                               map[SDAP_AT_SUDO_HOST].name,
                                               map[SDAP_AT_SUDO_HOST].name);
        if (filter == NULL) {
            goto done;
        }
    }

    filter = talloc_strdup_append_buffer(filter, ")");
    if (filter == NULL) {
        goto done;
    }

    talloc_steal(mem_ctx, filter);

done:
    talloc_free(tmp_ctx);

    return filter;
}

static char *sdap_sudo_get_filter(TALLOC_CTX *mem_ctx,
                                  struct sdap_attr_map *map,
                                  struct sdap_sudo_ctx *sudo_ctx,
                                  const char *rule_filter)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *host_filter = NULL;
    char *filter = NULL;

    if (!sudo_ctx->use_host_filter) {
        return talloc_strdup(mem_ctx, rule_filter);
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return NULL;
    }

    host_filter = sdap_sudo_build_host_filter(tmp_ctx, map,
                                              sudo_ctx->hostnames,
                                              sudo_ctx->ip_addr,
                                              sudo_ctx->include_netgroups,
                                              sudo_ctx->include_regexp);
    if (host_filter == NULL) {
        goto done;
    }

    filter = sdap_get_id_specific_filter(tmp_ctx, rule_filter, host_filter);
    if (filter == NULL) {
        goto done;
    }

    talloc_steal(mem_ctx, filter);

done:
    talloc_free(tmp_ctx);
    return filter;
}

struct sdap_sudo_refresh_state {
    struct sdap_sudo_ctx *sudo_ctx;
    struct tevent_context *ev;
    struct sdap_server_opts *srv_opts;
    struct sdap_options *opts;
    struct sdap_id_op *sdap_op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *search_filter;
    const char *delete_filter;

    int dp_error;
    size_t num_rules;
};

static errno_t sdap_sudo_refresh_retry(struct tevent_req *req);
static void sdap_sudo_refresh_connect_done(struct tevent_req *subreq);
static void sdap_sudo_refresh_hostinfo_done(struct tevent_req *subreq);
static errno_t sdap_sudo_refresh_sudoers(struct tevent_req *req);
static void sdap_sudo_refresh_done(struct tevent_req *subreq);

struct tevent_req *sdap_sudo_refresh_send(TALLOC_CTX *mem_ctx,
                                          struct sdap_sudo_ctx *sudo_ctx,
                                          const char *search_filter,
                                          const char *delete_filter)
{
    struct tevent_req *req;
    struct sdap_sudo_refresh_state *state;
    struct sdap_id_ctx *id_ctx = sudo_ctx->id_ctx;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_refresh_state);
    if (!req) {
        return NULL;
    }

    /* if we don't have a search filter, this request is meaningless */
    if (search_filter == NULL) {
        ret = EINVAL;
        goto immediately;
    }

    state->sudo_ctx = sudo_ctx;
    state->ev = id_ctx->be->ev;
    state->opts = id_ctx->opts;
    state->domain = id_ctx->be->domain;
    state->sysdb = id_ctx->be->domain->sysdb;
    state->dp_error = DP_ERR_FATAL;

    state->sdap_op = sdap_id_op_create(state, id_ctx->conn->conn_cache);
    if (!state->sdap_op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create() failed\n");
        ret = ENOMEM;
        goto immediately;
    }

    state->search_filter = talloc_strdup(state, search_filter);
    if (state->search_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    state->delete_filter = talloc_strdup(state, delete_filter);
    if (delete_filter != NULL && state->delete_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    ret = sdap_sudo_refresh_retry(req);
    if (ret == EAGAIN) {
        /* asynchronous processing */
        return req;
    }

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, id_ctx->be->ev);

    return req;
}

static errno_t sdap_sudo_refresh_retry(struct tevent_req *req)
{
    struct sdap_sudo_refresh_state *state;
    struct tevent_req *subreq;
    int ret;

    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_connect_send() failed: "
                                   "%d(%s)\n", ret, strerror(ret));
        return ret;
    }

    tevent_req_set_callback(subreq, sdap_sudo_refresh_connect_done, req);

    return EAGAIN;
}

static void sdap_sudo_refresh_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_sudo_refresh_state *state;
    int dp_error;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "SUDO LDAP connection failed "
                                   "[%d]: %s\n", ret, strerror(ret));
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "SUDO LDAP connection successful\n");

    /* Obtain srv_opts here in case of first connection. */
    state->srv_opts = state->sudo_ctx->id_ctx->srv_opts;

    /* Renew host information if needed. */
    if (state->sudo_ctx->run_hostinfo) {
        subreq = sdap_sudo_get_hostinfo_send(state, state->opts,
                                             state->sudo_ctx->id_ctx->be);
        if (subreq == NULL) {
            state->dp_error = DP_ERR_FATAL;
            tevent_req_error(req, ENOMEM);
            return;
        }

        tevent_req_set_callback(subreq, sdap_sudo_refresh_hostinfo_done, req);
        state->sudo_ctx->run_hostinfo = false;
        return;
    }

    ret = sdap_sudo_refresh_sudoers(req);
    if (ret != EAGAIN) {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
    }
}

static void sdap_sudo_refresh_hostinfo_done(struct tevent_req *subreq)
{
    struct sdap_sudo_ctx *sudo_ctx;
    struct sdap_sudo_refresh_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    sudo_ctx = state->sudo_ctx;

    ret = sdap_sudo_get_hostinfo_recv(sudo_ctx, subreq, &sudo_ctx->hostnames,
                                      &sudo_ctx->ip_addr);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve host information, "
                                 "host filter will be disabled [%d]: %s\n",
                                 ret, sss_strerror(ret));
        sudo_ctx->use_host_filter = false;
    } else {
        sudo_ctx->use_host_filter = true;
    }

    ret = sdap_sudo_refresh_sudoers(req);
    if (ret != EAGAIN) {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
    }
}

static errno_t sdap_sudo_refresh_sudoers(struct tevent_req *req)
{
    struct sdap_sudo_refresh_state *state;
    struct tevent_req *subreq;
    char *filter;

    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    /* We are connected. Host information may have changed during transition
     * from offline to online state. At this point we can combine search
     * and host filter. */
    filter = sdap_sudo_get_filter(state, state->opts->sudorule_map,
                                  state->sudo_ctx, state->search_filter);
    if (filter == NULL) {
        return ENOMEM;
    }

    subreq = sdap_sudo_load_sudoers_send(state, state->ev,
                                         state->opts,
                                         sdap_id_op_handle(state->sdap_op),
                                         filter);
    if (subreq == NULL) {
        talloc_free(filter);
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_sudo_refresh_done, req);

    return EAGAIN;
}

static void sdap_sudo_refresh_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_sudo_refresh_state *state;
    struct sysdb_attrs **rules = NULL;
    size_t rules_count = 0;
    char *usn = NULL;
    int dp_error;
    int ret;
    errno_t sret;
    bool in_transaction = false;
    time_t now;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    ret = sdap_sudo_load_sudoers_recv(subreq, state, &rules_count, &rules);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = sdap_sudo_refresh_retry(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Received %zu rules\n", rules_count);

    /* start transaction */
    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    /* purge cache */
    ret = sdap_sudo_purge_sudoers(state->domain, state->delete_filter,
                                  state->opts->sudorule_map, rules_count, rules);
    if (ret != EOK) {
        goto done;
    }

    /* store rules */
    now = time(NULL);
    ret = sdap_sudo_store_sudoers(state, state->domain,
                                  state->opts, rules_count, rules,
                                  state->domain->sudo_timeout, now, &usn);
    if (ret != EOK) {
        goto done;
    }

    /* commit transaction */
    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

    DEBUG(SSSDBG_TRACE_FUNC, "Sudoers is successfuly stored in cache\n");

    /* remember new usn */
    sdap_sudo_set_usn(state->srv_opts, usn);

    ret = EOK;
    state->num_rules = rules_count;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(state->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not cancel transaction\n");
        }
    }

    state->dp_error = dp_error;
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

int sdap_sudo_refresh_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           int *dp_error,
                           size_t *num_rules)
{
    struct sdap_sudo_refresh_state *state;

    state = tevent_req_data(req, struct sdap_sudo_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;

    if (num_rules != NULL) {
        *num_rules = state->num_rules;
    }

    return EOK;
}
