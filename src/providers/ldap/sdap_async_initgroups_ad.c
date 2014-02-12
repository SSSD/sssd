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
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ad/ad_common.h"
#include "lib/idmap/sss_idmap.h"

struct sdap_ad_match_rule_initgr_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    struct sdap_handle *sh;
    const char *name;
    const char *orig_dn;
    const char **attrs;
    int timeout;
    const char *base_filter;
    char *filter;

    size_t count;
    struct sysdb_attrs **groups;

    size_t base_iter;
    struct sdap_search_base **search_bases;
};

static errno_t
sdap_get_ad_match_rule_initgroups_next_base(struct tevent_req *req);

static void
sdap_get_ad_match_rule_initgroups_step(struct tevent_req *subreq);

struct tevent_req *
sdap_get_ad_match_rule_initgroups_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sdap_options *opts,
                                       struct sysdb_ctx *sysdb,
                                       struct sss_domain_info *domain,
                                       struct sdap_handle *sh,
                                       const char *name,
                                       const char *orig_dn,
                                       int timeout)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_ad_match_rule_initgr_state *state;
    const char **filter_members;
    char *sanitized_user_dn;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_ad_match_rule_initgr_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->domain = domain;
    state->sh = sh;
    state->name = name;
    state->orig_dn = orig_dn;
    state->base_iter = 0;
    state->search_bases = opts->sdom->group_search_bases;

    /* Request all of the group attributes that we know
     * about, except for 'member' because that wastes a
     * lot of bandwidth here and we only really
     * care about a single member (the one we already
     * have).
     */
    filter_members = talloc_array(state, const char *, 2);
    if (!filter_members) {
        ret = ENOMEM;
        goto immediate;
    }
    filter_members[0] = opts->group_map[SDAP_AT_GROUP_MEMBER].name;
    filter_members[1] = NULL;

    ret = build_attrs_from_map(state, opts->group_map,
                               SDAP_OPTS_GROUP,
                               filter_members,
                               &state->attrs, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not build attribute map: [%s]\n",
               strerror(ret));
        goto immediate;
    }

    /* Sanitize the user DN in case we have special characters in DN */
    ret = sss_filter_sanitize(state, state->orig_dn, &sanitized_user_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not sanitize user DN: %s\n",
               strerror(ret));
        goto immediate;
    }

    /* Craft a special filter according to
     * http://msdn.microsoft.com/en-us/library/windows/desktop/aa746475%28v=vs.85%29.aspx
     */
    state->base_filter =
            talloc_asprintf(state,
                            "(&(%s:%s:=%s)(objectClass=%s))",
                            state->opts->group_map[SDAP_AT_GROUP_MEMBER].name,
                            SDAP_MATCHING_RULE_IN_CHAIN,
                            sanitized_user_dn,
                            state->opts->group_map[SDAP_OC_GROUP].name);
    talloc_zfree(sanitized_user_dn);
    if (!state->base_filter) {
        ret = ENOMEM;
        goto immediate;
    }

    /* Start the loop through the search bases to get all of the
     * groups to which this user belongs.
     */
    ret = sdap_get_ad_match_rule_initgroups_next_base(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sdap_get_ad_match_rule_members_next_base failed: [%s]\n",
               strerror(ret));
        goto immediate;
    }

    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static errno_t
sdap_get_ad_match_rule_initgroups_next_base(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_ad_match_rule_initgr_state *state;

    state = tevent_req_data(req, struct sdap_ad_match_rule_initgr_state);

    talloc_zfree(state->filter);
    state->filter = sdap_get_id_specific_filter(state,
                        state->base_filter,
                        state->search_bases[state->base_iter]->filter);
    if (!state->filter) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Searching for groups with base [%s]\n",
           state->search_bases[state->base_iter]->basedn);

    subreq = sdap_get_generic_send(
            state, state->ev, state->opts, state->sh,
            state->search_bases[state->base_iter]->basedn,
            state->search_bases[state->base_iter]->scope,
            state->filter, state->attrs,
            state->opts->group_map, SDAP_OPTS_GROUP,
            state->timeout, true);
    if (!subreq) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq,
                            sdap_get_ad_match_rule_initgroups_step,
                            req);

    return EOK;
}

static void
sdap_get_ad_match_rule_initgroups_step(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_ad_match_rule_initgr_state *state =
            tevent_req_data(req, struct sdap_ad_match_rule_initgr_state);
    size_t count, i;
    struct sysdb_attrs **groups;
    char **sysdb_grouplist;

    ret = sdap_get_generic_recv(subreq, state, &count, &groups);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "LDAP search failed: [%s]\n", sss_strerror(ret));
        goto error;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          "Search for users returned %zu results\n", count);

    /* Add this batch of groups to the list */
    if (count > 0) {
        state->groups = talloc_realloc(state, state->groups,
                                      struct sysdb_attrs *,
                                      state->count + count + 1);
        if (!state->groups) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        /* Copy the new groups into the list */
        for (i = 0; i < count; i++) {
            state->groups[state->count + i] =
                    talloc_steal(state->groups, groups[i]);
        }

        state->count += count;
        state->groups[state->count] = NULL;
    }

    /* Continue checking other search bases */
    state->base_iter++;
    if (state->search_bases[state->base_iter]) {
        /* There are more search bases to try */
        ret = sdap_get_ad_match_rule_initgroups_next_base(req);
        if (ret != EOK) {
            goto error;
        }
        return;
    }

    /* No more search bases. Save the groups. */

    if (state->count == 0) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "User is not a member of any group in the search bases\n");
    }

    /* Get the current sysdb group list for this user
     * so we can update it.
     */
    ret = get_sysdb_grouplist(state, state->sysdb, state->domain,
                              state->name, &sysdb_grouplist);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not get the list of groups for [%s] in the sysdb: "
               "[%s]\n",
               state->name, strerror(ret));
        goto error;
    }

    /* The extensibleMatch search rule eliminates the need for
     * nested group searches, so we can just update the
     * memberships now.
     */
    ret = sdap_initgr_common_store(state->sysdb,
                                   state->domain,
                                   state->opts,
                                   state->name,
                                   SYSDB_MEMBER_USER,
                                   sysdb_grouplist,
                                   state->groups,
                                   state->count);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not store groups for user [%s]: [%s]\n",
               state->name, strerror(ret));
        goto error;
    }

    tevent_req_done(req);
    return;

error:
    tevent_req_error(req, ret);
}

errno_t
sdap_get_ad_match_rule_initgroups_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct sdap_get_ad_tokengroups_state {
    struct tevent_context *ev;
    struct sss_idmap_ctx *idmap_ctx;
    const char *username;

    char **sids;
    size_t num_sids;
};

static void sdap_get_ad_tokengroups_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_get_ad_tokengroups_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sdap_options *opts,
                             struct sdap_handle *sh,
                             const char *name,
                             const char *orig_dn,
                             int timeout)
{
    struct sdap_get_ad_tokengroups_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    const char *attrs[] = {AD_TOKENGROUPS_ATTR, NULL};
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_get_ad_tokengroups_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->idmap_ctx = opts->idmap_ctx->map;
    state->ev = ev;
    state->username = talloc_strdup(state, name);
    if (state->username == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    subreq = sdap_get_generic_send(state, state->ev, opts, sh, orig_dn,
                                   LDAP_SCOPE_BASE, NULL, attrs,
                                   NULL, 0, timeout, false);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_get_ad_tokengroups_done, req);

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

static void sdap_get_ad_tokengroups_done(struct tevent_req *subreq)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sdap_get_ad_tokengroups_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sysdb_attrs **users = NULL;
    struct ldb_message_element *el = NULL;
    enum idmap_error_code err;
    char *sid_str = NULL;
    size_t num_users;
    size_t i;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_get_ad_tokengroups_state);

    ret = sdap_get_generic_recv(subreq, tmp_ctx, &num_users, &users);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "LDAP search failed: [%s]\n", sss_strerror(ret));
        goto done;
    }

    if (num_users != 1) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "More than one result on a base search!\n");
        ret = EINVAL;
        goto done;
    }

    /* get the list of sids from tokengroups */
    ret = sysdb_attrs_get_el_ext(users[0], AD_TOKENGROUPS_ATTR, false, &el);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_LIBS, "No tokenGroups entries for [%s]\n",
                                  state->username);

        state->sids = NULL;
        state->num_sids = 0;
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not read tokenGroups attribute: "
                                     "[%s]\n", strerror(ret));
        goto done;
    }

    state->num_sids = 0;
    state->sids = talloc_zero_array(state, char*, el->num_values);
    if (state->sids == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* convert binary sid to string */
    for (i = 0; i < el->num_values; i++) {
        err = sss_idmap_bin_sid_to_sid(state->idmap_ctx, el->values[i].data,
                                       el->values[i].length, &sid_str);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not convert binary SID to string: [%s]. Skipping\n",
                   idmap_error_string(err));
            continue;
        }

        state->sids[i] = talloc_move(state->sids, &sid_str);
        state->num_sids++;
    }

    /* shrink array to final number of elements */
    state->sids = talloc_realloc(state, state->sids, char*, state->num_sids);
    if (state->sids == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t sdap_get_ad_tokengroups_recv(TALLOC_CTX *mem_ctx,
                                            struct tevent_req *req,
                                            size_t *_num_sids,
                                            char ***_sids)
{
    struct sdap_get_ad_tokengroups_state *state = NULL;
    state = tevent_req_data(req, struct sdap_get_ad_tokengroups_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_num_sids != NULL) {
        *_num_sids = state->num_sids;
    }

    if (_sids != NULL) {
        *_sids = talloc_steal(mem_ctx, state->sids);
    }

    return EOK;
}

static errno_t
sdap_ad_tokengroups_update_members(const char *username,
                                   struct sysdb_ctx *sysdb,
                                   struct sss_domain_info *domain,
                                   char **ldap_groups)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char **sysdb_groups = NULL;
    char **add_groups = NULL;
    char **del_groups = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    /* Get the current sysdb group list for this user so we can update it. */
    ret = get_sysdb_grouplist_dn(tmp_ctx, sysdb, domain,
                                 username, &sysdb_groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not get the list of groups for "
              "[%s] in the sysdb: [%s]\n", username, strerror(ret));
        goto done;
    }

    /* Find the differences between the sysdb and LDAP lists.
     * Groups in the sysdb only must be removed. */
    ret = diff_string_lists(tmp_ctx, ldap_groups, sysdb_groups,
                            &add_groups, &del_groups, NULL);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Updating memberships for [%s]\n", username);

    ret = sysdb_update_members_dn(domain, username, SYSDB_MEMBER_USER,
                                  (const char *const *) add_groups,
                                  (const char *const *) del_groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Membership update failed [%d]: %s\n",
                                     ret, strerror(ret));
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

struct sdap_ad_resolve_sids_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *id_ctx;
    struct sdap_id_conn_ctx *conn;
    struct sdap_options *opts;
    struct sss_domain_info *domain;
    char **sids;

    const char *current_sid;
    int index;
};

static errno_t sdap_ad_resolve_sids_step(struct tevent_req *req);
static void sdap_ad_resolve_sids_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_ad_resolve_sids_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct sdap_id_ctx *id_ctx,
                          struct sdap_id_conn_ctx *conn,
                          struct sdap_options *opts,
                          struct sss_domain_info *domain,
                          char **sids)
{
    struct sdap_ad_resolve_sids_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_ad_resolve_sids_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->id_ctx = id_ctx;
    state->conn = conn;
    state->opts = opts;
    state->domain = get_domains_head(domain);
    state->sids = sids;
    state->index = 0;

    if (state->sids == NULL) {
        ret = EOK;
        goto immediately;
    }

    ret = sdap_ad_resolve_sids_step(req);
    if (ret != EAGAIN) {
        goto immediately;
    }

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

static errno_t sdap_ad_resolve_sids_step(struct tevent_req *req)
{
    struct sdap_ad_resolve_sids_state *state = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_domain *sdap_domain = NULL;
    struct sss_domain_info *domain = NULL;

    state = tevent_req_data(req, struct sdap_ad_resolve_sids_state);

    do {
        state->current_sid = state->sids[state->index];
        if (state->current_sid == NULL) {
            return EOK;
        }
        state->index++;

        domain = find_subdomain_by_sid(state->domain, state->current_sid);
        if (domain == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "SID %s does not belong to any known "
                                         "domain\n", state->current_sid);
        }
    } while (domain == NULL);

    sdap_domain = sdap_domain_get(state->opts, domain);
    if (sdap_domain == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "SDAP domain does not exist?\n");
        return ERR_INTERNAL;
    }

    subreq = groups_get_send(state, state->ev, state->id_ctx, sdap_domain,
                             state->conn, state->current_sid,
                             BE_FILTER_SECID, BE_ATTR_CORE, false);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_ad_resolve_sids_done, req);

    return EAGAIN;
}

static void sdap_ad_resolve_sids_done(struct tevent_req *subreq)
{
    struct sdap_ad_resolve_sids_state *state = NULL;
    struct tevent_req *req = NULL;
    int dp_error;
    int sdap_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_ad_resolve_sids_state);

    ret = groups_get_recv(subreq, &dp_error, &sdap_error);
    talloc_zfree(subreq);
    if (ret != EOK || sdap_error != EOK || dp_error != DP_ERR_OK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to resolve SID %s [dp_error: %d, "
              "sdap_error: %d, ret: %d]: %s\n", state->current_sid, dp_error,
              sdap_error, ret, strerror(ret));
        goto done;
    }

    ret = sdap_ad_resolve_sids_step(req);
    if (ret == EAGAIN) {
        /* continue with next SID */
        return;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t sdap_ad_resolve_sids_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}


struct sdap_ad_tokengroups_initgr_mapping_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sdap_idmap_ctx *idmap_ctx;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    const char *orig_dn;
    int timeout;
    const char *username;

    struct sdap_id_op *op;
};

static void
sdap_ad_tokengroups_initgr_mapping_connect_done(struct tevent_req *subreq);
static void sdap_ad_tokengroups_initgr_mapping_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_ad_tokengroups_initgr_mapping_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sdap_options *opts,
                                        struct sysdb_ctx *sysdb,
                                        struct sss_domain_info *domain,
                                        struct sdap_handle *sh,
                                        const char *name,
                                        const char *orig_dn,
                                        int timeout)
{
    struct sdap_ad_tokengroups_initgr_mapping_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_domain *sdom;
    struct ad_id_ctx *subdom_id_ctx;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_ad_tokengroups_initgr_mapping_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->idmap_ctx = opts->idmap_ctx;
    state->sysdb = sysdb;
    state->domain = domain;
    state->timeout = timeout;
    state->orig_dn = orig_dn;
    state->username = talloc_strdup(state, name);
    if (state->username == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    sdom = sdap_domain_get(opts, domain);
    if (sdom == NULL || sdom->pvt == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No ID ctx available for [%s].\n",
                                    domain->name);
        ret = EINVAL;
        goto immediately;
    }
    subdom_id_ctx = talloc_get_type(sdom->pvt, struct ad_id_ctx);
    state->op = sdap_id_op_create(state, subdom_id_ctx->ldap_ctx->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto immediately;
    }

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq,
                            sdap_ad_tokengroups_initgr_mapping_connect_done,
                            req);

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

static void
sdap_ad_tokengroups_initgr_mapping_connect_done(struct tevent_req *subreq)
{
    struct sdap_ad_tokengroups_initgr_mapping_state *state = NULL;
    struct tevent_req *req = NULL;
    int ret;
    int dp_error = DP_ERR_FATAL;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req,
                            struct sdap_ad_tokengroups_initgr_mapping_state);


    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_ad_tokengroups_send(state, state->ev, state->opts,
                                          sdap_id_op_handle(state->op),
                                          state->username,
                                          state->orig_dn, state->timeout);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, sdap_ad_tokengroups_initgr_mapping_done,
                            req);

    return;
}

static void sdap_ad_tokengroups_initgr_mapping_done(struct tevent_req *subreq)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sdap_ad_tokengroups_initgr_mapping_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sss_domain_info *domain = NULL;
    struct ldb_message *msg = NULL;
    const char *attrs[] = {SYSDB_NAME, NULL};
    const char *name = NULL;
    const char *sid = NULL;
    char **sids = NULL;
    size_t num_sids = 0;
    size_t i;
    time_t now;
    gid_t gid;
    char **groups = NULL;
    size_t num_groups;
    errno_t ret, sret;
    bool in_transaction = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        ret = ENOMEM;
        goto done;
    }

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_ad_tokengroups_initgr_mapping_state);

    ret = sdap_get_ad_tokengroups_recv(state, subreq, &num_sids, &sids);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to acquire tokengroups [%d]: %s\n",
                                    ret, strerror(ret));
        goto done;
    }

    num_groups = 0;
    groups = talloc_zero_array(tmp_ctx, char*, num_sids + 1);
    if (groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    now = time(NULL);
    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = true;

    for (i = 0; i < num_sids; i++) {
        sid = sids[i];
        DEBUG(SSSDBG_TRACE_LIBS, "Processing membership SID [%s]\n", sid);

        ret = sdap_idmap_sid_to_unix(state->idmap_ctx, sid, &gid);
        if (ret == ENOTSUP) {
            DEBUG(SSSDBG_TRACE_FUNC, "Skipping built-in object.\n");
            ret = EOK;
            continue;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not convert SID to GID: [%s]. "
                                         "Skipping\n", strerror(ret));
            continue;
        }

        domain = find_subdomain_by_sid(get_domains_head(state->domain), sid);
        if (domain == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Domain not found for SID %s\n", sid);
            continue;
        }

        DEBUG(SSSDBG_TRACE_LIBS, "SID [%s] maps to GID [%"SPRIgid"]\n",
                                  sid, gid);

        /* Check whether this GID already exists in the sysdb */
        ret = sysdb_search_group_by_gid(tmp_ctx, domain, gid, attrs, &msg);
        if (ret == EOK) {
            name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
            if (name == NULL) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Could not retrieve group name from sysdb\n");
                ret = EINVAL;
                goto done;
            }
        } else if (ret == ENOENT) {
            /* This is a new group. For now, we will store it under the name
             * of its SID. When a direct lookup of the group or its GID occurs,
             * it will replace this temporary entry. */
            name = sid;
            ret = sysdb_add_incomplete_group(domain, name, gid,
                                             NULL, sid, false, now);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Could not create incomplete "
                                             "group: [%s]\n", strerror(ret));
                goto done;
            }
        } else {
            /* Unexpected error */
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not look up group in sysdb: "
                                         "[%s]\n", strerror(ret));
            goto done;
        }

        groups[num_groups] = sysdb_group_strdn(tmp_ctx, domain->name, name);
        if (groups[num_groups] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        num_groups++;
    }

    groups[num_groups] = NULL;

    ret = sdap_ad_tokengroups_update_members(state->username,
                                             state->sysdb, state->domain,
                                             groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Membership update failed [%d]: %s\n",
                                     ret, strerror(ret));
        goto done;
    }

    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not commit transaction! [%s]\n",
                                    strerror(ret));
        goto done;
    }
    in_transaction = false;

done:
    talloc_free(tmp_ctx);

    if (in_transaction) {
        sret = sysdb_transaction_cancel(state->sysdb);
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not cancel transaction! [%s]\n",
                                     strerror(sret));
    }

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int sdap_ad_tokengroups_initgr_mapping_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sdap_ad_tokengroups_initgr_posix_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *id_ctx;
    struct sdap_id_conn_ctx *conn;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    const char *orig_dn;
    int timeout;
    const char *username;

    struct sdap_id_op *op;
};

static void
sdap_ad_tokengroups_initgr_posix_tg_done(struct tevent_req *subreq);

static void
sdap_ad_tokengroups_initgr_posix_sids_connect_done(struct tevent_req *subreq);
static void
sdap_ad_tokengroups_initgr_posix_sids_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_ad_tokengroups_initgr_posix_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct sdap_id_ctx *id_ctx,
                                      struct sdap_id_conn_ctx *conn,
                                      struct sdap_options *opts,
                                      struct sysdb_ctx *sysdb,
                                      struct sss_domain_info *domain,
                                      struct sdap_handle *sh,
                                      const char *name,
                                      const char *orig_dn,
                                      int timeout)
{
    struct sdap_ad_tokengroups_initgr_posix_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_domain *sdom;
    struct ad_id_ctx *subdom_id_ctx;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_ad_tokengroups_initgr_posix_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->id_ctx = id_ctx;
    state->conn = conn;
    state->opts = opts;
    state->sh = sh;
    state->sysdb = sysdb;
    state->domain = domain;
    state->orig_dn = orig_dn;
    state->timeout = timeout;
    state->username = talloc_strdup(state, name);
    if (state->username == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    sdom = sdap_domain_get(opts, domain);
    if (sdom == NULL || sdom->pvt == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No ID ctx available for [%s].\n",
                                    domain->name);
        ret = EINVAL;
        goto immediately;
    }
    subdom_id_ctx = talloc_get_type(sdom->pvt, struct ad_id_ctx);
    state->op = sdap_id_op_create(state, subdom_id_ctx->ldap_ctx->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto immediately;
    }

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq,
                            sdap_ad_tokengroups_initgr_posix_sids_connect_done,
                            req);

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

static void
sdap_ad_tokengroups_initgr_posix_sids_connect_done(struct tevent_req *subreq)
{
    struct sdap_ad_tokengroups_initgr_posix_state *state = NULL;
    struct tevent_req *req = NULL;
    int ret;
    int dp_error = DP_ERR_FATAL;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req,
                            struct sdap_ad_tokengroups_initgr_posix_state);


    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_ad_tokengroups_send(state, state->ev, state->opts,
                                          sdap_id_op_handle(state->op),
                                          state->username, state->orig_dn,
                                          state->timeout);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, sdap_ad_tokengroups_initgr_posix_tg_done,
                            req);

    return;
}

static void
sdap_ad_tokengroups_initgr_posix_tg_done(struct tevent_req *subreq)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sdap_ad_tokengroups_initgr_posix_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sss_domain_info *domain = NULL;
    struct ldb_message *msg = NULL;
    const char *attrs[] = {SYSDB_NAME, SYSDB_POSIX, NULL};
    const char *is_posix = NULL;
    const char *name = NULL;
    char *sid = NULL;
    char **sids = NULL;
    size_t num_sids = 0;
    char **valid_groups = NULL;
    size_t num_valid_groups;
    char **missing_sids = NULL;
    size_t num_missing_sids;
    size_t i;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        ret = ENOMEM;
        goto done;
    }

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req,
                            struct sdap_ad_tokengroups_initgr_posix_state);

    ret = sdap_get_ad_tokengroups_recv(state, subreq, &num_sids, &sids);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to acquire tokengroups [%d]: %s\n",
                                    ret, strerror(ret));
        goto done;
    }

    num_valid_groups = 0;
    valid_groups = talloc_zero_array(tmp_ctx, char*, num_sids + 1);
    if (valid_groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    num_missing_sids = 0;
    missing_sids = talloc_zero_array(tmp_ctx, char*, num_sids + 1);
    if (missing_sids == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* For each SID check if it is already present in the cache. If yes, we
     * will get name of the group and update the membership. Otherwise we need
     * to remember the SID and download missing groups one by one. */
    for (i = 0; i < num_sids; i++) {
        sid = sids[i];
        DEBUG(SSSDBG_TRACE_LIBS, "Processing membership SID [%s]\n", sid);

        domain = find_subdomain_by_sid(get_domains_head(state->domain), sid);
        if (domain == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Domain not found for SID %s\n", sid);
            continue;
        }

        ret = sysdb_search_group_by_sid_str(tmp_ctx, domain, sid, attrs, &msg);
        if (ret == EOK) {
            is_posix = ldb_msg_find_attr_as_string(msg, SYSDB_POSIX, NULL);
            if (is_posix != NULL && strcmp(is_posix, "FALSE") == 0) {
                /* skip non-posix group */
                continue;
            }

            /* we will update membership of this group */
            name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
            if (name == NULL) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Could not retrieve group name from sysdb\n");
                ret = EINVAL;
                goto done;
            }

            valid_groups[num_valid_groups] = sysdb_group_strdn(tmp_ctx,
                                                               domain->name,
                                                               name);
            if (valid_groups[num_valid_groups] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            num_valid_groups++;
        } else if (ret == ENOENT) {
            /* we need to download this group */
            missing_sids[num_missing_sids] = talloc_steal(missing_sids, sid);
            num_missing_sids++;

            DEBUG(SSSDBG_TRACE_FUNC, "Missing SID %s will be downloaded\n",
                                      sid);
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not look up group in sysdb: "
                                         "[%s]\n", strerror(ret));
            goto done;
        }
    }

    valid_groups[num_valid_groups] = NULL;
    missing_sids[num_missing_sids] = NULL;

    /* update membership of existing groups */
    ret = sdap_ad_tokengroups_update_members(state->username,
                                             state->sysdb, state->domain,
                                             valid_groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Membership update failed [%d]: %s\n",
                                     ret, strerror(ret));
        goto done;
    }

    /* download missing SIDs */
    missing_sids = talloc_steal(state, missing_sids);
    subreq = sdap_ad_resolve_sids_send(state, state->ev, state->id_ctx,
                                       state->conn,
                                       state->opts, state->domain,
                                       missing_sids);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_ad_tokengroups_initgr_posix_sids_done,
                            req);

    return;

done:
    talloc_free(tmp_ctx);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void
sdap_ad_tokengroups_initgr_posix_sids_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sdap_ad_resolve_sids_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to resolve missing SIDs "
                                    "[%d]: %s\n", ret, strerror(ret));
        goto done;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t sdap_ad_tokengroups_initgr_posix_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sdap_ad_tokengroups_initgroups_state {
    bool use_id_mapping;
    struct sss_domain_info *domain;
};

static void sdap_ad_tokengroups_initgroups_done(struct tevent_req *subreq);

struct tevent_req *
sdap_ad_tokengroups_initgroups_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct sdap_id_ctx *id_ctx,
                                    struct sdap_id_conn_ctx *conn,
                                    struct sdap_options *opts,
                                    struct sysdb_ctx *sysdb,
                                    struct sss_domain_info *domain,
                                    struct sdap_handle *sh,
                                    const char *name,
                                    const char *orig_dn,
                                    int timeout,
                                    bool use_id_mapping)
{
    struct sdap_ad_tokengroups_initgroups_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_ad_tokengroups_initgroups_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->use_id_mapping = use_id_mapping;
    state->domain = domain;

    if (state->use_id_mapping && !IS_SUBDOMAIN(state->domain)) {
        subreq = sdap_ad_tokengroups_initgr_mapping_send(state, ev, opts,
                                                         sysdb, domain, sh,
                                                         name, orig_dn,
                                                         timeout);
    } else {
        subreq = sdap_ad_tokengroups_initgr_posix_send(state, ev, id_ctx, conn,
                                                       opts, sysdb, domain, sh,
                                                       name, orig_dn,
                                                       timeout);
    }
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_ad_tokengroups_initgroups_done, req);

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

static void sdap_ad_tokengroups_initgroups_done(struct tevent_req *subreq)
{
    struct sdap_ad_tokengroups_initgroups_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_ad_tokengroups_initgroups_state);

    if (state->use_id_mapping && !IS_SUBDOMAIN(state->domain)) {
        ret = sdap_ad_tokengroups_initgr_mapping_recv(subreq);
    } else {
        ret = sdap_ad_tokengroups_initgr_posix_recv(subreq);
    }
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t sdap_ad_tokengroups_initgroups_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
