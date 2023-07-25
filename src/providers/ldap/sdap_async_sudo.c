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

#include "providers/backend.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_ops.h"
#include "providers/ldap/sdap_sudo.h"
#include "providers/ldap/sdap_sudo_shared.h"
#include "db/sysdb_sudo.h"

struct sdap_sudo_load_sudoers_state {
    struct sysdb_attrs **rules;
    size_t num_rules;
};

static void sdap_sudo_load_sudoers_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_sudo_load_sudoers_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sdap_options *opts,
                            struct sdap_handle *sh,
                            const char *ldap_filter)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_sudo_load_sudoers_state *state;
    struct sdap_search_base **sb;
    int ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_sudo_load_sudoers_state);
    if (!req) {
        return NULL;
    }

    state->rules = NULL;
    state->num_rules = 0;

    sb = opts->sdom->sudo_search_bases;
    if (sb == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "SUDOERS lookup request without a search base\n");
        ret = EINVAL;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "About to fetch sudo rules\n");

    subreq = sdap_search_bases_send(state, ev, opts, sh, sb,
                                    opts->sudorule_map, true, 0,
                                    ldap_filter, NULL, NULL);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_sudo_load_sudoers_done, req);

    ret = EOK;

immediately:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sdap_sudo_load_sudoers_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_sudo_load_sudoers_state *state;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);

    ret = sdap_search_bases_recv(subreq, state, &state->num_rules,
                                 &state->rules);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Received %zu sudo rules\n",
          state->num_rules);

    tevent_req_done(req);

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

    /* sudoHost is not specified and it is a cn=defaults rule */
    filter = talloc_asprintf_append_buffer(filter, "(&(!(%s=*))(%s=defaults))",
                                           map[SDAP_AT_SUDO_HOST].name,
                                           map[SDAP_AT_SUDO_NAME].name);
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

    filter = sdap_combine_filters(tmp_ctx, rule_filter, host_filter);
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
    struct sdap_options *opts;
    struct sdap_id_op *sdap_op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *search_filter;
    const char *delete_filter;
    bool update_usn;

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
                                          const char *delete_filter,
                                          bool update_usn)
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
    state->update_usn = update_usn;

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

static errno_t sdap_sudo_qualify_names(struct sss_domain_info *dom,
                                       struct sysdb_attrs **rules,
                                       size_t rules_count)
{
    errno_t ret;
    bool qualify;
    struct ldb_message_element *el;
    char *domain;
    char *name;
    const char *orig_name;
    struct ldb_message_element unique_el;

    for (size_t i = 0; i < rules_count; i++) {
        ret = sysdb_attrs_get_el_ext(rules[i], SYSDB_SUDO_CACHE_AT_USER,
                                     false, &el);
        if (ret != EOK) {
            continue;
        }

        unique_el.values = talloc_zero_array(rules, struct ldb_val, el->num_values);
        if (unique_el.values == NULL) {
            return ENOMEM;
        }
        unique_el.num_values = 0;

        for (size_t ii = 0; ii < el->num_values; ii++) {
            orig_name = (const char *) el->values[ii].data;

            qualify = is_user_or_group_name(orig_name);
            if (qualify) {
                struct ldb_val fqval;
                struct ldb_val *dup;

                ret = sss_parse_name(rules, dom->names, orig_name,
                                     &domain, &name);
                if (ret != EOK) {
                    continue;
                }

                if (domain == NULL) {
                    domain = talloc_strdup(rules, dom->name);
                    if (domain == NULL) {
                        talloc_zfree(name);
                        return ENOMEM;
                    }
                }

                fqval.data = (uint8_t * ) sss_create_internal_fqname(rules,
                                                                     name,
                                                                     domain);
                talloc_zfree(domain);
                talloc_zfree(name);
                if (fqval.data == NULL) {
                    return ENOMEM;
                }
                fqval.length = strlen((const char *) fqval.data);

                /* Prevent saving duplicates in case the sudo rule contains
                 * e.g. foo and foo@domain
                 */
                dup = ldb_msg_find_val(&unique_el, &fqval);
                if (dup != NULL) {
                    DEBUG(SSSDBG_TRACE_FUNC,
                          "Discarding duplicate value %s\n", (const char *) fqval.data);
                    talloc_free(fqval.data);
                    continue;
                }
                unique_el.values[unique_el.num_values].data = talloc_steal(unique_el.values, fqval.data);
                unique_el.values[unique_el.num_values].length = fqval.length;
                unique_el.num_values++;
            } else {
                unique_el.values[unique_el.num_values] = ldb_val_dup(unique_el.values,
                                                                     &el->values[ii]);
                unique_el.num_values++;
            }
        }

        talloc_zfree(el->values);
        el->values = unique_el.values;
        el->num_values = unique_el.num_values;
    }

    return EOK;
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
    } else if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Received %zu rules\n", rules_count);

    /* Save users and groups fully qualified */
    ret = sdap_sudo_qualify_names(state->domain, rules, rules_count);
    if (ret != EOK) {
        goto done;
    }

    /* start transaction */
    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    /* purge cache */
    ret = sysdb_sudo_purge(state->domain, state->delete_filter,
                           rules, rules_count);
    if (ret != EOK) {
        goto done;
    }

    /* store rules */
    ret = sysdb_sudo_store(state->domain, rules, rules_count);
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

    DEBUG(SSSDBG_TRACE_FUNC, "Sudoers is successfully stored in cache\n");

    if (state->update_usn) {
        /* remember new usn */
        ret = sysdb_get_highest_usn(state, rules, rules_count, &usn);
        if (ret == EOK) {
            sdap_sudo_set_usn(state->sudo_ctx->id_ctx->srv_opts, usn);
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, "Unable to get highest USN [%d]: %s\n",
                  ret, sss_strerror(ret));
        }
    }

    ret = EOK;
    state->num_rules = rules_count;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(state->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
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
