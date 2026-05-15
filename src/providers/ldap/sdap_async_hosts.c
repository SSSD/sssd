/*
    SSSD

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

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

#include "util/util.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_common.h"

struct sdap_host_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;
    struct sdap_options *opts;
    const char **attrs;
    struct sdap_attr_map *host_map;

    struct sdap_search_base **search_bases;
    int search_base_iter;

    char *cur_filter;
    char *host_filter;

    const char *hostname;

    /* Return values */
    size_t host_count;
    struct sysdb_attrs **hosts;
};

static void
sdap_host_info_done(struct tevent_req *subreq);

static errno_t
sdap_host_info_next(struct tevent_req *req,
                    struct sdap_host_state *state);

/**
 * hostname == NULL -> look up all hosts / host groups
 * hostname != NULL -> look up only given host and groups
 *                     it's member of
 */
struct tevent_req *
sdap_host_info_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct sdap_handle *sh,
                    struct sdap_options *opts,
                    const char *hostname,
                    struct sdap_attr_map *host_map,
                    struct sdap_search_base **search_bases)
{
    errno_t ret;
    struct sdap_host_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state, struct sdap_host_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->sh = sh;
    state->opts = opts;
    state->hostname = hostname;
    state->search_bases = search_bases;
    state->search_base_iter = 0;
    state->cur_filter = NULL;
    state->host_map = host_map;

    ret = build_attrs_from_map(state, host_map, SDAP_OPTS_HOST,
                               NULL, &state->attrs, NULL);
    if (ret != EOK) {
        goto immediate;
    }

    if (hostname == NULL) {
        state->host_filter = talloc_asprintf(state, "(objectClass=%s)",
                                             host_map[SDAP_OC_HOST].name);
    } else {
        state->host_filter = talloc_asprintf(state, "(&(objectClass=%s)(%s=%s))",
                                             host_map[SDAP_OC_HOST].name,
                                             host_map[SDAP_AT_HOST_FQDN].name,
                                             hostname);
    }
    if (state->host_filter == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    ret = sdap_host_info_next(req, state);
    if (ret == EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No host search base configured?\n");
        ret = EINVAL;
    }

    if (ret != EAGAIN) {
        goto immediate;
    }

    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t sdap_host_info_next(struct tevent_req *req,
                                   struct sdap_host_state *state)
{
    struct sdap_search_base *base;
    struct tevent_req *subreq;

    base = state->search_bases[state->search_base_iter];
    if (base == NULL) {
        return EOK;
    }

    talloc_zfree(state->cur_filter);
    state->cur_filter = sdap_combine_filters(state, state->host_filter,
                                             base->filter);
    if (state->cur_filter == NULL) {
        return ENOMEM;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh, base->basedn,
                                   base->scope, state->cur_filter,
                                   state->attrs, state->host_map,
                                   SDAP_OPTS_HOST,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT),
                                   true);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error requesting host info\n");
        talloc_zfree(state->cur_filter);
        return EIO;
    }
    tevent_req_set_callback(subreq, sdap_host_info_done, req);

    return EAGAIN;
}

static void
sdap_host_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_host_state *state = tevent_req_data(req, struct sdap_host_state);

    ret = sdap_get_generic_recv(subreq, state,
                                &state->host_count,
                                &state->hosts);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->host_count == 0) {
        state->search_base_iter++;
        ret = sdap_host_info_next(req, state);
        if (ret == EOK) {
            /* No more search bases to try */
            tevent_req_error(req, ENOENT);
        } else if (ret != EAGAIN) {
            tevent_req_error(req, ret);
        }
        return;
    }

    /* Nothing else to do, just complete the req */
    tevent_req_done(req);
}

errno_t sdap_host_info_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            size_t *host_count,
                            struct sysdb_attrs ***hosts)
{
    struct sdap_host_state *state = tevent_req_data(req, struct sdap_host_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *host_count = state->host_count;
    *hosts = talloc_steal(mem_ctx, state->hosts);

    return EOK;
}
