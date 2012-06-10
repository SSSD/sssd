/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/ldap_common.h"

struct sdap_ad_match_rule_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;
    const char **attrs;

    struct sdap_options *opts;
    const char *base_filter;
    char *filter;
    int timeout;

    size_t base_iter;
    struct sdap_search_base **search_bases;

    size_t count;
    struct sysdb_attrs **users;
};

static errno_t
sdap_get_ad_match_rule_members_next_base(struct tevent_req *req);
static void
sdap_get_ad_match_rule_members_step(struct tevent_req *subreq);

struct tevent_req *
sdap_get_ad_match_rule_members_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct sdap_options *opts,
                                    struct sdap_handle *sh,
                                    struct sysdb_attrs *group,
                                    int timeout)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_ad_match_rule_state *state;
    const char *group_dn;
    char *sanitized_group_dn;

    req = tevent_req_create(mem_ctx, &state, struct sdap_ad_match_rule_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->timeout = timeout;
    state->count = 0;
    state->base_iter = 0;
    state->search_bases = opts->user_search_bases;

    /* Request all of the user attributes that we know about. */
    ret = build_attrs_from_map(state, opts->user_map, SDAP_OPTS_USER,
                               NULL, &state->attrs, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not build attribute map: [%s]\n",
               strerror(ret)));
        goto immediate;
    }

    /* Get the DN of the group */
    ret = sysdb_attrs_get_string(group, SYSDB_ORIG_DN, &group_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not retrieve originalDN for group: %s\n",
               strerror(ret)));
        goto immediate;
    }

    /* Sanitize it in case we have special characters in DN */
    ret = sss_filter_sanitize(state, group_dn, &sanitized_group_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not sanitize group DN: %s\n",
               strerror(ret)));
        goto immediate;
    }

    /* Craft a special filter according to
     * http://msdn.microsoft.com/en-us/library/windows/desktop/aa746475%28v=vs.85%29.aspx
     */
    state->base_filter =
            talloc_asprintf(state,
                            "(&(%s:%s:=%s)(objectClass=%s))",
                            state->opts->user_map[SDAP_AT_USER_MEMBEROF].name,
                            SDAP_MATCHING_RULE_IN_CHAIN,
                            sanitized_group_dn,
                            state->opts->user_map[SDAP_OC_USER].name);
    talloc_zfree(sanitized_group_dn);
    if (!state->base_filter) {
        ret = ENOMEM;
        goto immediate;
    }

    /* Start the loop through the search bases to get all of the users */
    ret = sdap_get_ad_match_rule_members_next_base(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("sdap_get_ad_match_rule_members_next_base failed: [%s]\n",
               strerror(ret)));
        goto immediate;
    }

    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static errno_t
sdap_get_ad_match_rule_members_next_base(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_ad_match_rule_state *state;

    state = tevent_req_data(req, struct sdap_ad_match_rule_state);

    talloc_zfree(state->filter);
    state->filter = sdap_get_id_specific_filter(state,
                        state->base_filter,
                        state->search_bases[state->base_iter]->filter);
    if (!state->filter) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Searching for users with base [%s]\n",
           state->search_bases[state->base_iter]->basedn));

    subreq = sdap_get_generic_send(
            state, state->ev, state->opts, state->sh,
            state->search_bases[state->base_iter]->basedn,
            state->search_bases[state->base_iter]->scope,
            state->filter, state->attrs,
            state->opts->user_map, SDAP_OPTS_USER,
            state->timeout, true);
    if (!subreq) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_get_ad_match_rule_members_step, req);

    return EOK;
}

static void
sdap_get_ad_match_rule_members_step(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_ad_match_rule_state *state =
            tevent_req_data(req, struct sdap_ad_match_rule_state);
    size_t count, i;
    struct sysdb_attrs **users;

    ret = sdap_get_generic_recv(subreq, state, &count, &users);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("LDAP search failed: [%s]\n", strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          ("Search for users returned %d results\n", count));

    /* Add this batch of users to the list */
    if (count > 0) {
        state->users = talloc_realloc(state, state->users,
                                      struct sysdb_attrs *,
                                      state->count + count + 1);
        if (!state->users) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        /* Copy the new users into the list */
        for (i = 0; i < count; i++) {
            state->users[state->count + i] =
                    talloc_steal(state->users, users[i]);
        }

        state->count += count;
        state->users[state->count] = NULL;
    }

    /* Continue checking other search bases */
    state->base_iter++;
    if (state->search_bases[state->base_iter]) {
        /* There are more search bases to try */
        ret = sdap_get_ad_match_rule_members_next_base(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    }

    /* No more search bases. We're done here. */
    if (state->count == 0) {
        DEBUG(SSSDBG_TRACE_LIBS,
              ("No users matched in any search base\n"));
        tevent_req_error(req, ENOENT);
        return;
    }

    tevent_req_done(req);
}

errno_t
sdap_get_ad_match_rule_members_recv(struct tevent_req *req,
                                    TALLOC_CTX *mem_ctx,
                                    size_t *num_users,
                                    struct sysdb_attrs ***users)
{
    struct sdap_ad_match_rule_state *state =
            tevent_req_data(req, struct sdap_ad_match_rule_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *num_users = state->count;
    *users = talloc_steal(mem_ctx, state->users);
    return EOK;
}
