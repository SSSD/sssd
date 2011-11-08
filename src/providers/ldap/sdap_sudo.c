/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#include <errno.h>
#include <string.h>
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
    struct sdap_sudo_ctx *sudo_ctx;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sysdb_attrs **ldap_rules; /* search result will be stored here */
    size_t ldap_rules_count; /* search result will be stored here */

    const char **attrs;
    const char *filter;
    size_t base_iter;
    struct sdap_search_base **search_bases;
    int timeout;
};

static int sdap_sudo_connect(struct sdap_sudo_ctx *sudo_ctx);
static void sdap_sudo_connect_done(struct tevent_req *req);

static struct tevent_req * sdap_sudo_load_sudoers_send(TALLOC_CTX *mem_ctx,
                                                       struct sdap_sudo_ctx *sudo_ctx);
static errno_t sdap_sudo_load_sudoers_next_base(struct tevent_req *req);
static void sdap_sudo_load_sudoers_process(struct tevent_req *subreq);
static int sdap_sudo_load_sudoers_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       size_t *rules_count,
                                       struct sysdb_attrs ***rules);
static void sdap_sudo_load_sudoers_done(struct tevent_req *req);

static int sdap_sudo_purge_sudoers(struct sdap_sudo_ctx *sudo_ctx);
static int sdap_sudo_store_sudoers(struct sdap_sudo_ctx *sudo_ctx,
                                   size_t replies_count,
                                   struct sysdb_attrs **replies);

const char *sdap_sudo_build_filter(TALLOC_CTX *mem_ctx,
                                   struct sdap_attr_map *map,
                                   const char *username,
                                   uid_t uid,
                                   char **groups);

static void sdap_sudo_reply(struct sdap_sudo_ctx *sudo_ctx, int errcode)
{
    struct be_req *be_req = sudo_ctx->be_req;

    talloc_zfree(sudo_ctx);

    if (errcode == EOK) {
        sdap_handler_done(be_req, DP_ERR_OK, errcode, strerror(errcode));
    } else {
        sdap_handler_done(be_req, DP_ERR_FATAL, errcode, strerror(errcode));
    }
}

static void sdap_sudo_reply_offline(struct sdap_sudo_ctx *sudo_ctx)
{
    struct  be_req *be_req = sudo_ctx->be_req;

    talloc_zfree(sudo_ctx);

    sdap_handler_done(be_req, DP_ERR_OFFLINE, EAGAIN, "Provider is offline");
}

void sdap_sudo_handler(struct be_req *be_req)
{
    struct sdap_sudo_ctx *sudo_ctx = NULL;
    struct be_sudo_req *sudo_req = NULL;
    struct sdap_id_ctx *id_ctx = NULL;
    int ret = EOK;

    id_ctx = talloc_get_type(be_req->be_ctx->bet_info[BET_SUDO].pvt_bet_data,
                             struct sdap_id_ctx);

    sudo_req = talloc_get_type(be_req->req_data, struct be_sudo_req);

    sudo_ctx = talloc_zero(be_req, struct sdap_sudo_ctx);
    if (!sudo_ctx) {
        ret = ENOMEM;
        goto fail;
    }

    sudo_ctx->be_ctx = id_ctx->be;
    sudo_ctx->be_req = be_req;
    sudo_ctx->req = sudo_req;
    sudo_ctx->sdap_ctx = id_ctx;
    sudo_ctx->sdap_op = NULL;
    sudo_ctx->sdap_conn_cache = id_ctx->conn_cache;

    /* get user info */
    sudo_ctx->username = sudo_req->username;
    if (sudo_ctx->username != NULL) {
        ret = sysdb_get_sudo_user_info(sudo_ctx, sudo_ctx->username,
                                       sudo_ctx->be_ctx->sysdb,
                                       &sudo_ctx->uid, &sudo_ctx->groups);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to get uid and groups of %s\n",
                  sudo_ctx->username));
            goto fail;
        }
    } else {
        sudo_ctx->uid = 0;
        sudo_ctx->groups = NULL;
    }

    DEBUG(SSSDBG_FUNC_DATA, ("Requested refresh for: %s\n",
          sudo_req->username ? sudo_req->username : "<ALL>\n"));

    ret = sdap_sudo_connect(sudo_ctx);
    if (ret != EOK) {
        goto fail;
    }

    return;

fail:
    be_req->fn(be_req, DP_ERR_FATAL, ret, NULL);
}

int sdap_sudo_connect(struct sdap_sudo_ctx *sudo_ctx)
{
    struct tevent_req *req = NULL;
    int ret;

    if (be_is_offline(sudo_ctx->be_ctx)) {
        sdap_sudo_reply_offline(sudo_ctx);
        return EOK;
    }

    if (sudo_ctx->sdap_op == NULL) {
        sudo_ctx->sdap_op = sdap_id_op_create(sudo_ctx,
                                              sudo_ctx->sdap_conn_cache);
        if (sudo_ctx->sdap_op == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("sdap_id_op_create() failed\n"));
            return EIO;
        }
    }

    req = sdap_id_op_connect_send(sudo_ctx->sdap_op, sudo_ctx, &ret);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("sdap_id_op_connect_send() failed: %d(%s)\n", ret, strerror(ret)));
        talloc_zfree(sudo_ctx->sdap_op);
        return ret;
    }

    tevent_req_set_callback(req, sdap_sudo_connect_done, sudo_ctx);

    return EOK;
}

void sdap_sudo_connect_done(struct tevent_req *req)
{
    struct sdap_sudo_ctx *sudo_ctx = NULL;
    int dp_error;
    int ret;

    sudo_ctx = tevent_req_callback_data(req, struct sdap_sudo_ctx);

    ret = sdap_id_op_connect_recv(req, &dp_error);
    talloc_zfree(req);

    if (dp_error == DP_ERR_OFFLINE) {
        talloc_zfree(sudo_ctx->sdap_op);
        sdap_sudo_reply_offline(sudo_ctx);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("SUDO LDAP connection failed - %s\n", strerror(ret)));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("SUDO LDAP connection successful\n"));

    req = sdap_sudo_load_sudoers_send(sudo_ctx, sudo_ctx);
    if (req == NULL) {
        ret = EFAULT;
        goto fail;
    }

    tevent_req_set_callback(req, sdap_sudo_load_sudoers_done, sudo_ctx);

    return;

fail:
    sdap_sudo_reply(sudo_ctx, ret);
}

struct tevent_req * sdap_sudo_load_sudoers_send(TALLOC_CTX *mem_ctx,
                                                struct sdap_sudo_ctx *sudo_ctx)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_load_sudoers_state *state = NULL;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_load_sudoers_state);
    if (!req) {
        return NULL;
    }

    state->ev = sudo_ctx->be_ctx->ev;
    state->sudo_ctx = sudo_ctx;
    state->opts = sudo_ctx->sdap_ctx->opts;
    state->sh = sdap_id_op_handle(sudo_ctx->sdap_op);
    state->base_iter = 0;
    state->search_bases = state->opts->sudo_search_bases;
    state->timeout = dp_opt_get_int(state->opts->basic, SDAP_SEARCH_TIMEOUT);
    state->ldap_rules = NULL;
    state->ldap_rules_count = 0;

    /* create filter */
    state->filter = sdap_sudo_build_filter(state,
                                           state->opts->sudorule_map,
                                           sudo_ctx->username,
                                           sudo_ctx->uid,
                                           sudo_ctx->groups);
    if (state->filter == NULL) {
        goto fail;
    }

    /* create attrs from map */
    ret = build_attrs_from_map(state, state->opts->sudorule_map,
                               SDAP_OPTS_SUDO, &state->attrs);
    if (ret != EOK) {
        goto fail;
    }

    /* begin search */
    ret = sdap_sudo_load_sudoers_next_base(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, sudo_ctx->be_ctx->ev);
    }

    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static errno_t sdap_sudo_load_sudoers_next_base(struct tevent_req *req)
{
    struct tevent_req *subreq = NULL;
    struct sdap_sudo_load_sudoers_state *state = NULL;
    struct sdap_search_base *search_base = NULL;
    char *filter = NULL;

    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);
    search_base = state->search_bases[state->base_iter];
    if (search_base == NULL) {
        /* should not happen */
        DEBUG(SSSDBG_CRIT_FAILURE, ("search_base is null\n"));
        return EFAULT;
    }

    /* create filter */
    filter = sdap_get_id_specific_filter(state, state->filter,
                                         search_base->filter);
    if (filter == NULL) {
        return ENOMEM;
    }

    /* send request */
    DEBUG(SSSDBG_TRACE_FUNC,
          ("Searching for sudo rules with base [%s]\n",
           search_base->basedn));

    subreq = sdap_get_generic_send(state,
                                   state->ev,
                                   state->opts,
                                   state->sh,
                                   search_base->basedn,
                                   search_base->scope,
                                   filter,
                                   state->attrs,
                                   state->opts->sudorule_map,
                                   SDAP_OPTS_SUDO,
                                   state->timeout);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_sudo_load_sudoers_process, req);

    return EOK;
}

static void sdap_sudo_load_sudoers_process(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_load_sudoers_state *state = NULL;
    struct sdap_search_base *search_base = NULL;
    struct sysdb_attrs **attrs = NULL;
    size_t count;
    int ret;
    int i;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);
    search_base = state->search_bases[state->base_iter];

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Receiving sudo rules with base [%s]\n",
           search_base->basedn));

    ret = sdap_get_generic_recv(subreq, state, &count, &attrs);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    /* add rules to result */
    if (count > 0) {
        state->ldap_rules = talloc_realloc(state, state->ldap_rules,
                                           struct sysdb_attrs *,
                                           state->ldap_rules_count + count);
        if (state->ldap_rules == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        for (i = 0; i < count; i++) {
            state->ldap_rules[state->ldap_rules_count + i] = talloc_steal(
                                                   state->ldap_rules, attrs[i]);
        }

        state->ldap_rules_count += count;
    }

    /* go to next base */
    state->base_iter++;
    if (state->search_bases[state->base_iter]) {
        ret = sdap_sudo_load_sudoers_next_base(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }

        return;
    }

    /* we are done */
    tevent_req_done(req);
}

int sdap_sudo_load_sudoers_recv(struct tevent_req *req,
                                TALLOC_CTX *mem_ctx,
                                size_t *rules_count,
                                struct sysdb_attrs ***rules)
{
    struct sdap_sudo_load_sudoers_state *state = NULL;

    state = tevent_req_data(req, struct sdap_sudo_load_sudoers_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *rules_count = state->ldap_rules_count;
    *rules = talloc_steal(mem_ctx, state->ldap_rules);

    return EOK;
}

void sdap_sudo_load_sudoers_done(struct tevent_req *req)
{
    struct sdap_sudo_ctx *sudo_ctx = NULL;
    struct sysdb_attrs **rules = NULL;
    size_t rules_count;
    int ret;

    sudo_ctx = tevent_req_callback_data(req, struct sdap_sudo_ctx);

    ret = sdap_sudo_load_sudoers_recv(req, sudo_ctx, &rules_count, &rules);
    talloc_zfree(req);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Received %d rules\n", rules_count));

    /* purge cache */
    /* TODO purge with filter */
    DEBUG(SSSDBG_TRACE_FUNC, ("Purging sudo cache with filter %s\n", ""));
    ret = sdap_sudo_purge_sudoers(sudo_ctx);
    if (ret != EOK) {
        goto done;
    }

    /* store rules */
    ret = sdap_sudo_store_sudoers(sudo_ctx, rules_count, rules);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Sudoers is successfuly stored in cache\n"));

    ret = EOK;

done:
    sdap_sudo_reply(sudo_ctx, ret);
}

int sdap_sudo_purge_sudoers(struct sdap_sudo_ctx *sudo_ctx)
{
    struct sysdb_ctx *sysdb_ctx = sudo_ctx->be_ctx->sysdb;
    char *filter = NULL;
    int ret;

    if (sudo_ctx->username != NULL) {
        ret = sysdb_get_sudo_filter(sudo_ctx, sudo_ctx->username, sudo_ctx->uid,
                                    sudo_ctx->groups, SYSDB_SUDO_FILTER_NGRS
                                    | SYSDB_SUDO_FILTER_INCLUDE_ALL
                                    | SYSDB_SUDO_FILTER_INCLUDE_DFL, &filter);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to create filter to purge "
                  "sudoers cache [%d]: %s\n", ret, strerror(ret)));
            return ret;
        }
    }

    /* Purge rules */
    ret = sysdb_purge_sudorule_subtree(sysdb_ctx, sudo_ctx->be_ctx->domain,
                                       filter);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to purge sudoers cache [%d]: %s\n",
                                    ret, strerror(ret)));
        return ret;
    }

    return EOK;
}

int sdap_sudo_store_sudoers(struct sdap_sudo_ctx *sudo_ctx,
                            size_t rules_count,
                            struct sysdb_attrs **rules)
{
    struct sysdb_ctx *sysdb_ctx = sudo_ctx->be_ctx->sysdb;
    errno_t ret;

    /* Empty sudoers? Done. */
    if (rules_count == 0 || rules == NULL) {
        return EOK;
    }

    ret = sdap_save_native_sudorule_list(sysdb_ctx,
                                         sudo_ctx->sdap_ctx->opts->sudorule_map,
                                         rules, rules_count);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("failed to save sudo rules [%d]: %s\n",
              ret, strerror(ret)));
        return ret;
    }

    return EOK;
}

/* alway update cn=defaults and sudoUser=ALL */
const char *sdap_sudo_build_filter(TALLOC_CTX *mem_ctx,
                                   struct sdap_attr_map *map,
                                   const char *username,
                                   uid_t uid,
                                   char **groups)
{
    char *filter = NULL;
    char *output = NULL;
    char *sanitized = NULL;
    char **group = NULL;
    int ret;

    if (username == NULL) {
        return talloc_asprintf(mem_ctx, SDAP_SUDO_FILTER_ALL,
                               map[SDAP_OC_SUDORULE].name);
    }

    /* user name */
    ret = sss_filter_sanitize(filter, username, &sanitized);
    if (ret != EOK) {
        goto fail;
    }
    filter = talloc_asprintf_append(filter, SDAP_SUDO_FILTER_USERNAME,
                                    map[SDAP_AT_SUDO_USER].name,
                                    sanitized);
    if (filter == NULL) {
        goto fail;
    }

    /* user uid */
    filter = talloc_asprintf_append(filter, SDAP_SUDO_FILTER_UID,
                                    map[SDAP_AT_SUDO_USER].name,
                                    uid);
    if (filter == NULL) {
        goto fail;
    }

    /* groups */
    if (groups != NULL) {
        for (group = groups; *group != NULL; group++) {
            ret = sss_filter_sanitize(filter, *group, &sanitized);
            if (ret != EOK) {
                goto fail;
            }
            filter = talloc_asprintf_append(filter, SDAP_SUDO_FILTER_GROUP,
                                            map[SDAP_AT_SUDO_USER].name,
                                            sanitized);
            if (filter == NULL) {
                goto fail;
            }
        }
    }

    /* netgroups */
    /*
     * FIXME: load only netgroups user is member of
     * FIXME: add option to disable this filter
     */
    filter = talloc_asprintf_append(filter, SDAP_SUDO_FILTER_NETGROUP,
                                    map[SDAP_AT_SUDO_USER].name,
                                    "*");
    if (filter == NULL) {
        goto fail;
    }


    output = talloc_asprintf(mem_ctx, SDAP_SUDO_FILTER_USER,
                             map[SDAP_OC_SUDORULE].name,
                             map[SDAP_AT_SUDO_NAME].name,
                             SDAP_SUDO_DEFAULTS, /* FIXME: add option for this */
                             map[SDAP_AT_SUDO_USER].name,
                             filter);

    talloc_free(filter);
    return output;

fail:
    talloc_free(filter);
    return NULL;
}
