/*
    SSSD

    IPA Backend Module -- SELinux user maps (maps retrieval)

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

#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_selinux_maps.h"

struct ipa_selinux_get_maps_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sdap_handle *sh;
    struct sdap_options *opts;
    struct ipa_options *ipa_opts;
    const char **attrs;

    struct sdap_search_base **search_bases;
    int search_base_iter;

    char *cur_filter;
    char *maps_filter;

    size_t map_count;
    struct sysdb_attrs **maps;
};

static errno_t
ipa_selinux_get_maps_next(struct tevent_req *req,
                          struct ipa_selinux_get_maps_state *state);
static void
ipa_selinux_get_maps_done(struct tevent_req *subreq);

struct tevent_req *ipa_selinux_get_maps_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_ctx *sysdb,
                                             struct sdap_handle *sh,
                                             struct sdap_options *opts,
                                             struct ipa_options *ipa_opts,
                                             struct sdap_search_base **search_bases)
{
    struct tevent_req *req;
    struct ipa_selinux_get_maps_state *state;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ipa_selinux_get_maps_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->sysdb = sysdb;
    state->sh = sh;
    state->opts = opts;
    state->ipa_opts = ipa_opts;
    state->search_bases = search_bases;
    state->search_base_iter = 0;
    state->map_count = 0;
    state->maps = NULL;

    ret = build_attrs_from_map(state, ipa_opts->selinuxuser_map,
                               IPA_OPTS_SELINUX_USERMAP, NULL,
                               &state->attrs, NULL);
    if (ret != EOK) goto fail;

    state->cur_filter = NULL;
    state->maps_filter = talloc_asprintf(state,
                        "(&(objectclass=%s)(%s=TRUE))",
                        ipa_opts->selinuxuser_map[IPA_OC_SELINUX_USERMAP].name,
                        ipa_opts->selinuxuser_map[IPA_AT_SELINUX_USERMAP_ENABLED].name);
    if (state->maps_filter == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ret = ipa_selinux_get_maps_next(req, state);
    if (ret == EOK) {
        ret = EINVAL;
    }

    if (ret != EAGAIN) {
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static errno_t
ipa_selinux_get_maps_next(struct tevent_req *req,
                          struct ipa_selinux_get_maps_state *state)
{
    struct sdap_search_base *base;
    struct tevent_req *subreq;

    base = state->search_bases[state->search_base_iter];
    if (base == NULL) {
        return EOK;
    }

    talloc_zfree(state->cur_filter);
    state->cur_filter = sdap_combine_filters(state, state->maps_filter,
                                             base->filter);
    if (state->cur_filter == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Trying to fetch SELinux maps with following "
                              "parameters: [%d][%s][%s]\n", base->scope,
                              state->cur_filter, base->basedn);
    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh, base->basedn,
                                   base->scope, state->cur_filter,
                                   state->attrs,
                                   state->ipa_opts->selinuxuser_map,
                                   IPA_OPTS_SELINUX_USERMAP,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT),
                                   true);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_selinux_get_maps_done, req);
    return EAGAIN;
}

static void ipa_selinux_get_maps_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct ipa_selinux_get_maps_state *state = tevent_req_data(req,
                                                  struct ipa_selinux_get_maps_state);
    struct sysdb_attrs **results;
    size_t total_count;
    size_t count;
    int i;

    ret = sdap_get_generic_recv(subreq, state, &count, &results);
    if (ret != EOK) {
        goto done;
    }

    if (count > 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Found %zu user maps in current search base\n", count);

        total_count = count + state->map_count;
        state->maps = talloc_realloc(state, state->maps, struct sysdb_attrs *, total_count);
        if (state->maps == NULL) {
            ret = ENOMEM;
            goto done;
        }

        i = 0;
        while (state->map_count < total_count) {
            state->maps[state->map_count] = talloc_steal(state->maps, results[i]);
            state->map_count++;
            i++;
        }
    }

    state->search_base_iter++;
    ret = ipa_selinux_get_maps_next(req, state);
    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        goto done;
    }

    if (state->map_count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "No SELinux user maps found!\n");
        ret = ENOENT;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
}

errno_t
ipa_selinux_get_maps_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          size_t *count,
                          struct sysdb_attrs ***maps)
{
    struct ipa_selinux_get_maps_state *state =
            tevent_req_data(req, struct ipa_selinux_get_maps_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *count = state->map_count;
    *maps = talloc_steal(mem_ctx, state->maps);

    return EOK;
}
