/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include <talloc.h>
#include <tevent.h>

#include "util/util.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/ldap_common.h"

struct sdap_search_bases_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    const char *filter;
    const char **attrs;
    struct sdap_attr_map *map;
    int map_num_attrs;
    int timeout;
    bool allow_paging;

    size_t base_iter;
    struct sdap_search_base *cur_base;
    struct sdap_search_base **bases;

    size_t reply_count;
    struct sysdb_attrs **reply;
};

static errno_t sdap_search_bases_next_base(struct tevent_req *req);
static void sdap_search_bases_done(struct tevent_req *subreq);

struct tevent_req *sdap_search_bases_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sdap_options *opts,
                                          struct sdap_handle *sh,
                                          struct sdap_search_base **bases,
                                          struct sdap_attr_map *map,
                                          bool allow_paging,
                                          int timeout,
                                          const char *filter,
                                          const char **attrs)
{
    struct tevent_req *req;
    struct sdap_search_bases_state *state;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_search_bases_state);
    if (req == NULL) {
        return NULL;
    }

    if (bases == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No search base specified!\n");
        ret = ERR_INTERNAL;
        goto immediately;
    }

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->bases = bases;
    state->map = map;
    state->filter = filter;
    state->attrs = attrs;
    state->allow_paging = allow_paging;

    state->timeout = timeout == 0
                     ? dp_opt_get_int(opts->basic, SDAP_SEARCH_TIMEOUT)
                     : timeout;

    if (state->map != NULL) {
        for (state->map_num_attrs = 0;
                state->map[state->map_num_attrs].opt_name != NULL;
                state->map_num_attrs++) {
            /* no op */;
        }
    } else {
        state->map_num_attrs = 0;
    }

    if (state->attrs == NULL) {
        ret = build_attrs_from_map(state, state->map, state->map_num_attrs,
                                   NULL, &state->attrs, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Unable to build attrs from map "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto immediately;
        }
    }

    state->base_iter = 0;
    ret = sdap_search_bases_next_base(req);
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

static errno_t sdap_search_bases_next_base(struct tevent_req *req)
{
    struct sdap_search_bases_state *state;
    struct tevent_req *subreq;
    char *filter;

    state = tevent_req_data(req, struct sdap_search_bases_state);
    state->cur_base = state->bases[state->base_iter];
    if (state->cur_base == NULL) {
        return EOK;
    }

    /* Combine lookup and search base filters. */
    filter = sdap_combine_filters(state, state->filter,
                                  state->cur_base->filter);
    if (filter == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing LDAP lookup with base [%s]\n",
                             state->cur_base->basedn);

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   state->cur_base->basedn,
                                   state->cur_base->scope, filter,
                                   state->attrs, state->map,
                                   state->map_num_attrs, state->timeout,
                                   state->allow_paging);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_search_bases_done, req);

    state->base_iter++;
    return EAGAIN;
}

static void sdap_search_bases_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_search_bases_state *state;
    struct sysdb_attrs **attrs;
    size_t count;
    size_t i;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_search_bases_state);

    DEBUG(SSSDBG_TRACE_FUNC, "Receiving data from base [%s]\n",
                             state->cur_base->basedn);

    ret = sdap_get_generic_recv(subreq, state, &count, &attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Add rules to result. */
    if (count > 0) {
        state->reply = talloc_realloc(state, state->reply, struct sysdb_attrs *,
                                      state->reply_count + count);
        if (state->reply == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        for (i = 0; i < count; i++) {
            state->reply[state->reply_count + i] = talloc_steal(state->reply,
                                                                attrs[i]);
        }

        state->reply_count += count;
    }

    /* Try next search base. */
    ret = sdap_search_bases_next_base(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

int sdap_search_bases_recv(struct tevent_req *req,
                              TALLOC_CTX *mem_ctx,
                              size_t *reply_count,
                              struct sysdb_attrs ***reply)
{
    struct sdap_search_bases_state *state =
                tevent_req_data(req, struct sdap_search_bases_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = state->reply_count;
    *reply = talloc_steal(mem_ctx, state->reply);

    return EOK;
}
