/*
   SSSD

   Simple access control

   Copyright (C) Sumit Bose <sbose@redhat.com> 2010

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

#include "providers/backend.h"
#include "providers/simple/simple_access.h"
#include "util/sss_utf8.h"
#include "db/sysdb.h"

#define NON_EXIST_USR_ALLOW "The user %s does not exist. Possible typo in simple_allow_users.\n"
#define NON_EXIST_USR_DENY  "The user %s does not exist. Possible typo in simple_deny_users.\n"
#define NON_EXIST_GRP_ALLOW "The group %s does not exist. Possible typo in simple_allow_groups.\n"
#define NON_EXIST_GRP_DENY  "The group %s does not exist. Possible typo in simple_deny_groups.\n"

static bool
is_posix(const struct ldb_message *group)
{
    const char *val;

    val = ldb_msg_find_attr_as_string(group, SYSDB_POSIX, NULL);
    if (!val || /* Groups are posix by default */
        strcasecmp(val, "TRUE") == 0) {
        return true;
    }

    return false;
}

/* Returns EOK if the result is definitive, EAGAIN if only partial result
 */
static errno_t
simple_check_users(struct simple_ctx *ctx, const char *username,
                   bool *access_granted)
{
    struct sss_domain_info *domain = NULL;
    int i;

    /* First, check whether the user is in the allowed users list */
    if (ctx->allow_users != NULL) {
        for(i = 0; ctx->allow_users[i] != NULL; i++) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Checking against allow list username [%s].\n",
                  ctx->allow_users[i]);
            domain = find_domain_by_object_name(ctx->domain,
                                                ctx->allow_users[i]);
            if (domain == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, NON_EXIST_USR_ALLOW,
                      ctx->allow_users[i]);
                sss_log(SSS_LOG_CRIT, NON_EXIST_USR_ALLOW,
                        ctx->allow_users[i]);
                continue;
            }

            if (sss_string_equal(domain->case_sensitive, username,
                                 ctx->allow_users[i])) {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "User [%s] found in allow list, access granted.\n",
                      username);

                /* Do not return immediately on explicit allow
                 * We need to make sure none of the user's groups
                 * are denied. But there's no need to check username
                 * matches any more.
                 */
                *access_granted = true;
                break;
            }
        }
    } else if (!ctx->allow_groups) {
        /* If neither allow rule is in place, we'll assume allowed
         * unless a deny rule disables us below.
         */
        DEBUG(SSSDBG_TRACE_LIBS,
              "No allow rule, assuming allow unless explicitly denied\n");
        *access_granted = true;
    }

    /* Next check whether this user has been specifically denied */
    if (ctx->deny_users != NULL) {
        for(i = 0; ctx->deny_users[i] != NULL; i++) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Checking against deny list username [%s].\n",
                  ctx->deny_users[i]);
            domain = find_domain_by_object_name(ctx->domain,
                                                ctx->deny_users[i]);
            if (domain == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, NON_EXIST_USR_DENY,
                      ctx->deny_users[i]);
                sss_log(SSS_LOG_CRIT, NON_EXIST_USR_DENY,
                        ctx->deny_users[i]);
                return EINVAL;
            }

            if (sss_string_equal(domain->case_sensitive, username,
                                 ctx->deny_users[i])) {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "User [%s] found in deny list, access denied.\n",
                        ctx->deny_users[i]);

                /* Return immediately on explicit denial */
                *access_granted = false;
                return EOK;
            }
        }
    }

    return EAGAIN;
}

static errno_t
simple_check_groups(struct simple_ctx *ctx, const char **group_names,
                    bool *access_granted)
{
    struct sss_domain_info *domain = NULL;
    bool matched;
    int i, j;

    /* Now process allow and deny group rules
     * If access was already granted above, we'll skip
     * this redundant rule check
     */
    if (ctx->allow_groups && !*access_granted) {
        matched = false;
        for (i = 0; ctx->allow_groups[i]; i++) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Checking against allow list group name [%s].\n",
                  ctx->allow_groups[i]);
            domain = find_domain_by_object_name(ctx->domain,
                                                ctx->allow_groups[i]);
            if (domain == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, NON_EXIST_GRP_ALLOW,
                      ctx->allow_groups[i]);
                sss_log(SSS_LOG_CRIT, NON_EXIST_GRP_ALLOW,
                        ctx->allow_groups[i]);

                continue;
            }

            for(j = 0; group_names[j]; j++) {
                if (sss_string_equal(domain->case_sensitive,
                                     group_names[j], ctx->allow_groups[i])) {
                    matched = true;
                    break;
                }
            }

            /* If any group has matched, we can skip out on the
             * processing early
             */
            if (matched) {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "Group [%s] found in allow list, access granted.\n",
                      group_names[j]);
                *access_granted = true;
                break;
            }
        }
    }

    /* Finally, process the deny group rules */
    if (ctx->deny_groups) {
        matched = false;
        for (i = 0; ctx->deny_groups[i]; i++) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Checking against deny list group name [%s].\n",
                  ctx->deny_groups[i]);
            domain = find_domain_by_object_name(ctx->domain,
                                                ctx->deny_groups[i]);
            if (domain == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, NON_EXIST_GRP_DENY,
                      ctx->deny_groups[i]);
                sss_log(SSS_LOG_CRIT, NON_EXIST_GRP_DENY,
                        ctx->deny_groups[i]);

                return EINVAL;
            }

            for(j = 0; group_names[j]; j++) {
                if (sss_string_equal(domain->case_sensitive,
                                     group_names[j], ctx->deny_groups[i])) {
                    matched = true;
                    break;
                }
            }

            /* If any group has matched, we can skip out on the
             * processing early
             */
            if (matched) {
                DEBUG(SSSDBG_TRACE_LIBS,
                      "Group [%s] found in deny list, access denied.\n",
                      group_names[j]);
                *access_granted = false;
                break;
            }
        }
    }

    return EOK;
}

struct simple_resolve_group_state {
    struct sss_domain_info *domain;
    gid_t gid;
    struct simple_ctx *ctx;

    const char *name;
};

static errno_t
simple_resolve_group_check(struct simple_resolve_group_state *state);
static void simple_resolve_group_done(struct tevent_req *subreq);

static struct tevent_req *
simple_resolve_group_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct simple_ctx *ctx,
                          struct sss_domain_info *domain,
                          gid_t gid)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct simple_resolve_group_state *state;
    struct dp_id_data *ar;

    req = tevent_req_create(mem_ctx, &state,
                            struct simple_resolve_group_state);
    if (!req) return NULL;

    state->domain = domain;
    state->gid = gid;
    state->ctx = ctx;

    /* First check if the group was updated already. If it was (maybe its
     * parent was updated first), then just shortcut */
    ret = simple_resolve_group_check(state);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_LIBS, "Group already updated\n");
        ret = EOK;
        goto done;
    } else if (ret != EAGAIN) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot check if group was already updated [%d]: %s\n",
               ret, sss_strerror(ret));
        goto done;
    }
    /* EAGAIN - still needs update */

    ar = talloc(state, struct dp_id_data);
    if (!ar) {
        ret = ENOMEM;
        goto done;
    }

    ar->entry_type = BE_REQ_GROUP;
    ar->filter_type = BE_FILTER_IDNUM;
    ar->filter_value = talloc_asprintf(ar, "%llu", (unsigned long long) gid);
    ar->domain = talloc_strdup(ar, state->domain->name);
    if (!ar->domain || !ar->filter_value) {
        ret = ENOMEM;
        goto done;
    }

    subreq = dp_req_send(state, ctx->be_ctx->provider, ar->domain,
                         "Simple Resolve Group", 0, NULL,
                         DPT_ID, DPM_ACCOUNT_HANDLER, 0, ar, NULL);
    if (!subreq) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, simple_resolve_group_done, req);

    return req;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t
simple_resolve_group_check(struct simple_resolve_group_state *state)
{
    errno_t ret;
    struct ldb_message *group;
    bool is_sid;
    const char *group_attrs[] = { SYSDB_NAME, SYSDB_POSIX,
                                  SYSDB_GIDNUM, NULL };

    /* Check the cache by GID again and fetch the name */
    ret = sysdb_search_group_by_gid(state, state->domain, state->gid,
                                    group_attrs, &group);
    if (ret == ENOENT) {
        /* The group is missing, we will try to update it. */
        return EAGAIN;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
               "Could not look up group by gid [%"SPRIgid"]: [%d][%s]\n",
               state->gid, ret, sss_strerror(ret));
        return ret;
    }

    state->name = ldb_msg_find_attr_as_string(group, SYSDB_NAME, NULL);
    if (!state->name) {
        DEBUG(SSSDBG_OP_FAILURE, "No group name\n");
        return ERR_ACCOUNT_UNKNOWN;
    }

    /* if name is still a SID then we still need to resolve the group */
    ret = string_begins_with(state->name, "S-1-5", &is_sid);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "string_begins_with() failure\n");
        return ret;
    }

    if (is_sid) {
        DEBUG(SSSDBG_TRACE_LIBS, "POSIX group name [%s] still in SID format\n",
                                 state->name);
        return EAGAIN;
    }

    if (is_posix(group) == false) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "The group is still non-POSIX\n");
        return EAGAIN;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Got POSIX group\n");
    return EOK;
}

static void simple_resolve_group_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct simple_resolve_group_state *state;
    struct dp_reply_std *reply;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct simple_resolve_group_state);

    ret = dp_req_recv_ptr(state, subreq, struct dp_reply_std, &reply);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "dp_req_recv failed\n");
        tevent_req_error(req, ret);
        return;
    }

    if (reply->dp_error != DP_ERR_OK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot refresh data from DP: %u,%u: %s\n",
              reply->dp_error, reply->error, reply->message);
        tevent_req_error(req, EIO);
        return;
    }

    /* Check the cache by GID again and fetch the name */
    ret = simple_resolve_group_check(state);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Refresh failed\n");
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t
simple_resolve_group_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          const char **name)
{
    struct simple_resolve_group_state *state;

    state = tevent_req_data(req, struct simple_resolve_group_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *name = talloc_strdup(mem_ctx, state->name);
    return EOK;
}

struct simple_group {
    struct sss_domain_info *domain;
    gid_t gid;
};

struct simple_check_groups_state {
    struct tevent_context *ev;
    struct simple_ctx *ctx;
    struct sss_domain_info *domain;

    struct simple_group *lookup_groups;
    size_t num_groups;
    size_t giter;

    const char **group_names;
    size_t num_names;

    bool failed_to_resolve_groups;
};

static void simple_check_get_groups_next(struct tevent_req *subreq);

static errno_t
simple_check_get_groups_primary(struct simple_check_groups_state *state,
                                gid_t gid);
static errno_t
simple_check_process_group(struct simple_check_groups_state *state,
                           struct ldb_message *group);

static struct tevent_req *
simple_check_get_groups_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct simple_ctx *ctx,
                             const char *username)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct simple_check_groups_state *state;
    const char *attrs[] = { SYSDB_NAME, SYSDB_POSIX, SYSDB_GIDNUM,
                            SYSDB_SID_STR, NULL };
    size_t group_count;
    struct ldb_message *user;
    struct ldb_message **groups;
    int i;
    gid_t gid;

    req = tevent_req_create(mem_ctx, &state,
                            struct simple_check_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->failed_to_resolve_groups = false;

    DEBUG(SSSDBG_TRACE_LIBS, "Looking up groups for user %s\n", username);

    /* get domain from username */
    state->domain = find_domain_by_object_name(ctx->domain, username);
    if (state->domain == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid user %s!\n", username);
        ret = EINVAL;
        goto done;
    }

    ret = sysdb_search_user_by_name(state, state->domain, username, attrs,
                                    &user);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No such user %s\n", username);
        ret = ERR_ACCOUNT_UNKNOWN;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not look up username [%s]: [%d][%s]\n",
              username, ret, sss_strerror(ret));
        goto done;
    }

    ret = sysdb_asq_search(state, state->domain,
                           user->dn, NULL, SYSDB_MEMBEROF,
                           attrs, &group_count, &groups);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "User %s is a member of %zu supplemental groups\n",
           username, group_count);

    /* One extra space for terminator, one extra space for private group */
    state->group_names = talloc_zero_array(state, const char *, group_count + 2);
    state->lookup_groups = talloc_zero_array(state, struct simple_group,
                                             group_count + 2);
    if (!state->group_names || !state->lookup_groups) {
        ret = ENOMEM;
        goto done;
    }

    for (i=0; i < group_count; i++) {
        /* Some providers (like the AD provider) might perform initgroups
         * without resolving the group names. In order for the simple access
         * provider to work correctly, we need to resolve the groups before
         * performing the access check. In AD provider, the situation is
         * even more tricky b/c the groups HAVE name, but their name
         * attribute is set to SID and they are set as non-POSIX
         */
        ret = simple_check_process_group(state, groups[i]);
        if (ret != EOK) {
            goto done;
        }
    }

    gid = ldb_msg_find_attr_as_uint64(user, SYSDB_GIDNUM, 0);
    if (!gid) {
        DEBUG(SSSDBG_MINOR_FAILURE, "User %s has no gid?\n", username);
        ret = EINVAL;
        goto done;
    }

    ret = simple_check_get_groups_primary(state, gid);
    if (ret != EOK) {
        goto done;
    }

    if (state->num_groups == 0) {
        /* If all groups could have been resolved by name, we are
         * done
         */
        DEBUG(SSSDBG_TRACE_FUNC, "All groups had name attribute\n");
        ret = EOK;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Need to resolve %zu groups\n",
                              state->num_groups);
    state->giter = 0;
    subreq = simple_resolve_group_send(req, state->ev, state->ctx,
                                       state->lookup_groups[state->giter].domain,
                                       state->lookup_groups[state->giter].gid);
    if (!subreq) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, simple_check_get_groups_next, req);

    return req;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static void simple_check_get_groups_next(struct tevent_req *subreq)
{
    struct tevent_req *req =
                        tevent_req_callback_data(subreq, struct tevent_req);
    struct simple_check_groups_state *state =
                        tevent_req_data(req, struct simple_check_groups_state);
    errno_t ret;

    ret = simple_resolve_group_recv(subreq, state->group_names,
                                    &state->group_names[state->num_names]);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not resolve name of group with GID %"SPRIgid"\n",
              state->lookup_groups[state->giter].gid);
        state->failed_to_resolve_groups = true;
    } else {
        state->num_names++;
    }
    state->giter++;

    if (state->giter < state->num_groups) {
        subreq = simple_resolve_group_send(req, state->ev, state->ctx,
                                   state->lookup_groups[state->giter].domain,
                                   state->lookup_groups[state->giter].gid);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, simple_check_get_groups_next, req);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "All groups resolved. Done.\n");
    tevent_req_done(req);
}

static errno_t
simple_check_process_group(struct simple_check_groups_state *state,
                           struct ldb_message *group)
{
    errno_t ret;
    const char *name;
    const char *group_sid;
    struct sss_domain_info *domain;
    gid_t gid;
    bool posix;
    bool is_sid;

    posix = is_posix(group);
    name = ldb_msg_find_attr_as_string(group, SYSDB_NAME, NULL);
    gid = ldb_msg_find_attr_as_uint64(group, SYSDB_GIDNUM, 0);

    /* With the current sysdb layout, every group has a name */
    if (name == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Checking group [%s]: gid: [%u], posix: [%s]\n",
                             name, gid, posix ? "True" : "False");

    if (gid == 0) {
        if (posix == true) {
            DEBUG(SSSDBG_CRIT_FAILURE, "POSIX group without GID\n");
            return EINVAL;
        }

        /* Non-POSIX group with a name. Still can be used for access
         * control as the name should point to the real name, no SID
         */
        state->group_names[state->num_names] = talloc_strdup(state->group_names,
                                                             name);
        if (!state->group_names[state->num_names]) {
            return ENOMEM;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL, "Adding non-POSIX group %s\n", name);
        state->num_names++;
        return EOK;
    }

    /* Here are only groups with a name and gid. POSIX group can already
     * be used. If name is still a SID then dont add the group, it needs
     * to be resolved */
    ret = string_begins_with(name, "S-1-5", &is_sid);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "string_begins_with() failure\n");
        return ret;
    }

    if (is_sid) {
        DEBUG(SSSDBG_TRACE_FUNC, "POSIX group name [%s] still in SID format,"
                                 " need to resolve this\n", name);
    } else {
        state->group_names[state->num_names] = talloc_strdup(state->group_names,
                                                             name);
        if (!state->group_names[state->num_names]) {
            return ENOMEM;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL, "Adding POSIX group %s\n", name);
        state->num_names++;
        return EOK;
    }

    /* Try to get group SID and assign it a domain */
    group_sid = ldb_msg_find_attr_as_string(group, SYSDB_SID_STR, NULL);
    if (group_sid == NULL) {
        /* We will look it up in main domain. */
        domain = state->ctx->domain;
    } else {
        domain = find_domain_by_sid(state->ctx->domain, group_sid);
        if (domain == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "There is no domain information for "
                                        "SID %s\n", group_sid);
            return ENOENT;
        }
    }

    /* Group with a GID needs resolving */
    state->lookup_groups[state->num_groups].domain = domain;
    state->lookup_groups[state->num_groups].gid = gid;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Adding GID %"SPRIgid" to resolve list\n", gid);
    state->num_groups++;
    return EOK;
}

static errno_t
simple_check_get_groups_primary(struct simple_check_groups_state *state,
                                gid_t gid)
{
    errno_t ret;
    const char *group_attrs[] = { SYSDB_NAME, SYSDB_POSIX,
                                  SYSDB_GIDNUM, SYSDB_SID_STR, NULL };
    struct ldb_message *msg;

    ret = sysdb_search_group_by_gid(state, state->domain, gid, group_attrs,
                                    &msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_FUNC_DATA,
              "Could not look up primary group [%"SPRIgid"]: [%d][%s]\n",
               gid, ret, sss_strerror(ret));
        /* We have to treat this as non-fatal, because the primary
         * group may be local to the machine and not available in
         * our ID provider.
         */
    } else {
        ret = simple_check_process_group(state, msg);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot process primary group\n");
            return ret;
        }
    }

    return EOK;
}

static errno_t
simple_check_get_groups_recv(struct tevent_req *req,
                             TALLOC_CTX *mem_ctx,
                             const char ***_group_names)
{
    struct simple_check_groups_state *state;

    state = tevent_req_data(req, struct simple_check_groups_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_group_names = talloc_steal(mem_ctx, state->group_names);
    if (state->failed_to_resolve_groups) {
        return ERR_SIMPLE_GROUPS_MISSING;
    }
    return EOK;
}

struct simple_access_check_state {
    bool access_granted;
    struct simple_ctx *ctx;
    const char *username;

    const char **group_names;
};

static void simple_access_check_done(struct tevent_req *subreq);

struct tevent_req *simple_access_check_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct simple_ctx *ctx,
                                            const char *username)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct simple_access_check_state *state;

    req = tevent_req_create(mem_ctx, &state,
                            struct simple_access_check_state);
    if (!req) return NULL;

    state->access_granted = false;
    state->ctx = ctx;
    state->username = talloc_strdup(state, username);
    if (!state->username) {
        ret = ENOMEM;
        goto immediate;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Simple access check for %s\n", username);

    ret = simple_check_users(ctx, username, &state->access_granted);
    if (ret == EOK) {
        goto immediate;
    } else if (ret != EAGAIN) {
        ret = ERR_INTERNAL;
        goto immediate;
    }

    /* EAGAIN -- check groups */

    if (!ctx->allow_groups && !ctx->deny_groups) {
        /* There are no group restrictions, so just return
         * here with whatever we've decided.
         */
        DEBUG(SSSDBG_TRACE_LIBS, "No group restrictions, end request\n");
        ret = EOK;
        goto immediate;
    }

    /* The group names might not be available. Fire a request to
     * gather them. In most cases, the request will just shortcut
     */
    subreq = simple_check_get_groups_send(state, ev, ctx, username);
    if (!subreq) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, simple_access_check_done, req);

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


static void simple_access_check_done(struct tevent_req *subreq)
{
    struct tevent_req *req =
                        tevent_req_callback_data(subreq, struct tevent_req);
    struct simple_access_check_state *state =
                        tevent_req_data(req, struct simple_access_check_state);
    errno_t ret;

    /* We know the names now. Run the check. */
    ret = simple_check_get_groups_recv(subreq, state, &state->group_names);

    talloc_zfree(subreq);
    if (ret == ENOENT) {
        /* If the user wasn't found, just shortcut */
        state->access_granted = false;
        tevent_req_done(req);
        return;
    } else if (ret == ERR_SIMPLE_GROUPS_MISSING) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not collect groups of user %s\n", state->username);
        if (state->ctx->deny_groups == NULL) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "But no deny groups were defined so we can continue.\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Some deny groups were defined, we can't continue\n");
            tevent_req_error(req, ret);
            return;
        }
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not collect groups of user %s\n", state->username);
        tevent_req_error(req, ret);
        return;
    }

    ret = simple_check_groups(state->ctx, state->group_names,
                              &state->access_granted);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not check group access [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ERR_INTERNAL);
        return;
    }

    /* Now just return whatever we decided */
    DEBUG(SSSDBG_TRACE_INTERNAL, "Group check done\n");
    tevent_req_done(req);
}

errno_t simple_access_check_recv(struct tevent_req *req, bool *access_granted)
{
    struct simple_access_check_state *state =
                        tevent_req_data(req, struct simple_access_check_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    DEBUG(SSSDBG_TRACE_LIBS,
          "Access %sgranted\n", state->access_granted ? "" : "not ");
    if (access_granted) {
        *access_granted = state->access_granted;
    }

    return EOK;
}
