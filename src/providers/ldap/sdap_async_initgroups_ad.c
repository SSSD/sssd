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
#include "lib/idmap/sss_idmap.h"

struct sdap_ad_match_rule_initgr_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sysdb_ctx *sysdb;
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
    state->sh = sh;
    state->name = name;
    state->orig_dn = orig_dn;
    state->base_iter = 0;
    state->search_bases = opts->group_search_bases;

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
              ("Could not build attribute map: [%s]\n",
               strerror(ret)));
        goto immediate;
    }

    /* Sanitize the user DN in case we have special characters in DN */
    ret = sss_filter_sanitize(state, state->orig_dn, &sanitized_user_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not sanitize user DN: %s\n",
               strerror(ret)));
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
          ("Searching for groups with base [%s]\n",
           state->search_bases[state->base_iter]->basedn));

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
              ("LDAP search failed: [%s]\n", strerror(ret)));
        goto error;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          ("Search for users returned %d results\n", count));

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
              ("User is not a member of any group in the search bases\n"));
    }

    /* Get the current sysdb group list for this user
     * so we can update it.
     */
    ret = get_sysdb_grouplist(state, state->sysdb, state->name,
                              &sysdb_grouplist);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not get the list of groups for [%s] in the sysdb: "
               "[%s]\n",
               state->name, strerror(ret)));
        goto error;
    }

    /* The extensibleMatch search rule eliminates the need for
     * nested group searches, so we can just update the
     * memberships now.
     */
    ret = sdap_initgr_common_store(state->sysdb, state->opts,
                                   state->name,
                                   SYSDB_MEMBER_USER,
                                   sysdb_grouplist,
                                   state->groups,
                                   state->count);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not store groups for user [%s]: [%s]\n",
               state->name, strerror(ret)));
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

struct sdap_ad_tokengroups_initgr_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sysdb_ctx *sysdb;
    struct sdap_handle *sh;
    const char *username;
};

static void
sdap_get_ad_tokengroups_initgroups_lookup_done(struct tevent_req *req);

struct tevent_req *
sdap_get_ad_tokengroups_initgroups_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sdap_options *opts,
                                        struct sysdb_ctx *sysdb,
                                        struct sdap_handle *sh,
                                        const char *name,
                                        const char *orig_dn,
                                        int timeout)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_ad_tokengroups_initgr_state *state;
    const char *attrs[] = {AD_TOKENGROUPS_ATTR, NULL};

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_ad_tokengroups_initgr_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sysdb = sysdb;
    state->sh = sh;
    state->username = name;

    subreq = sdap_get_generic_send(
            state, state->ev, state->opts, state->sh,
            orig_dn, LDAP_SCOPE_BASE, NULL, attrs,
            NULL, 0, timeout, false);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        tevent_req_post(req, ev);
        return req;
    }

    tevent_req_set_callback(subreq,
                            sdap_get_ad_tokengroups_initgroups_lookup_done,
                            req);
    return req;
}

static void
sdap_get_ad_tokengroups_initgroups_lookup_done(struct tevent_req *subreq)
{
    errno_t ret, sret;
    enum idmap_error_code err;
    size_t user_count, group_count, i;
    TALLOC_CTX *tmp_ctx;
    bool in_transaction = false;
    char *sid_str;
    gid_t gid;
    time_t now;
    struct sysdb_attrs **users;
    struct ldb_message_element *el;
    struct ldb_message *msg;
    char **ldap_grouplist;
    char **sysdb_grouplist;
    char **add_groups;
    char **del_groups;
    const char *attrs[] = { SYSDB_NAME, NULL };
    const char *group_name;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_ad_tokengroups_initgr_state *state =
            tevent_req_data(req, struct sdap_ad_tokengroups_initgr_state);

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    ret = sdap_get_generic_recv(subreq, tmp_ctx, &user_count, &users);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("LDAP search failed: [%s]\n", strerror(ret)));
        goto done;
    }

    if (user_count != 1) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("More than one result on a base search!\n"));
        ret = EINVAL;
        goto done;
    }

    /* Get the list of group SIDs */
    ret = sysdb_attrs_get_el_ext(users[0], AD_TOKENGROUPS_ATTR,
                                 false, &el);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  ("No tokenGroups entries for [%s]\n",
                   state->username));
            /* No groups in LDAP. We need to ensure that the
             * sysdb matches.
             */
            el = talloc_zero(tmp_ctx, struct ldb_message_element);
            if (!el) {
                ret = ENOMEM;
                goto done;
            }
            el->num_values = 0;

            /* This will skip the group-processing loop below
             * and proceed to removing any sysdb groups.
             */
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Could not read tokenGroups attribute: [%s]\n",
                   strerror(ret)));
            goto done;
        }
    }

    /* Process the groups */
    now = time(NULL);

    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) goto done;
    in_transaction = true;

    ldap_grouplist = talloc_array(tmp_ctx, char *, el->num_values + 1);
    if (!ldap_grouplist) {
        ret = ENOMEM;
        goto done;
    }
    group_count = 0;

    for (i = 0; i < el->num_values; i++) {
        /* Get the SID and convert it to a GID */

        err = sss_idmap_bin_sid_to_sid(state->opts->idmap_ctx->map,
                                        el->values[i].data,
                                        el->values[i].length,
                                        &sid_str);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Could not convert binary SID to string: [%s]. Skipping\n",
                   idmap_error_string(err)));
            continue;
        }
        DEBUG(SSSDBG_TRACE_LIBS,
              ("Processing membership SID [%s]\n",
               sid_str));
        ret = sdap_idmap_sid_to_unix(state->opts->idmap_ctx, sid_str,
                                     &gid);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Could not convert SID to GID: [%s]. Skipping\n",
                   strerror(ret)));
            continue;
        }

        DEBUG(SSSDBG_TRACE_LIBS,
              ("Processing membership GID [%lu]\n",
               gid));

        /* Check whether this GID already exists in the sysdb */
        ret = sysdb_search_group_by_gid(tmp_ctx, state->sysdb,
                                        gid, attrs, &msg);
        if (ret == EOK) {
            group_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
            if (!group_name) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Could not retrieve group name from sysdb\n"));
                ret = EINVAL;
                goto done;
            }
        } else if (ret == ENOENT) {
            /* This is a new group. For now, we will store it
             * under the name of its SID. When a direct lookup of
             * the group or its GID occurs, it will replace this
             * temporary entry.
             */
            group_name = sid_str;
            ret = sysdb_add_incomplete_group(state->sysdb, group_name,
                                             gid, NULL, false, now);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Could not create incomplete group: [%s]\n",
                       strerror(ret)));
                goto done;
            }
        } else {
            /* Unexpected error */
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Could not look up group in sysdb: [%s]\n",
                   strerror(ret)));
            goto done;
        }

        ldap_grouplist[group_count] =
                talloc_strdup(ldap_grouplist, group_name);
        if (!ldap_grouplist[group_count]) {
            ret = ENOMEM;
            goto done;
        }

        group_count++;
    }
    ldap_grouplist[group_count] = NULL;

    /* Get the current sysdb group list for this user
     * so we can update it.
     */
    ret = get_sysdb_grouplist(state, state->sysdb, state->username,
                              &sysdb_grouplist);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not get the list of groups for [%s] in the sysdb: "
               "[%s]\n",
               state->username, strerror(ret)));
        goto done;
    }

    /* Find the differences between the sysdb and LDAP lists
     * Groups in the sysdb only must be removed.
     */
    ret = diff_string_lists(tmp_ctx, ldap_grouplist, sysdb_grouplist,
                            &add_groups, &del_groups, NULL);
    if (ret != EOK) goto done;

    DEBUG(SSSDBG_TRACE_LIBS,
          ("Updating memberships for [%s]\n", state->username));
    ret = sysdb_update_members(state->sysdb, state->username,
                               SYSDB_MEMBER_USER,
                               (const char *const *) add_groups,
                               (const char *const *) del_groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Membership update failed [%d]: %s\n",
               ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not commit transaction! [%s]\n",
               strerror(ret)));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(state->sysdb);
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Could not cancel transaction! [%s]\n",
               sret));
    }

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    talloc_free(tmp_ctx);
    return;
}

errno_t
sdap_get_ad_tokengroups_initgroups_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}
