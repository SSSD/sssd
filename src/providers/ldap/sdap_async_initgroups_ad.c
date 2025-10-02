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
#include "providers/ldap/sdap_async_ad.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ad/ad_common.h"
#include "lib/idmap/sss_idmap.h"

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
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void sdap_get_ad_tokengroups_done(struct tevent_req *subreq)
{
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

    ret = sdap_get_generic_recv(subreq, state, &num_users, &users);
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

errno_t
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

struct tevent_req *
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

    if (state->sids == NULL || state->sids[0] == NULL) {
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

        domain = sss_get_domain_by_sid_ldap_fallback(state->domain,
                                                     state->current_sid);

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
                             BE_FILTER_SECID, false, true, false);
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

    if (ret == EOK && sdap_error == ENOENT && dp_error == DP_ERR_OK) {
        /* Group was not found, we will ignore the error and continue with
         * next group. This may happen for example if the group is built-in,
         * but a custom search base is provided. */
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Unable to resolve SID %s - will try next sid.\n",
              state->current_sid);
    } else if (ret != EOK || sdap_error != EOK || dp_error != DP_ERR_OK) {
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

errno_t sdap_ad_resolve_sids_recv(struct tevent_req *req)
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
static errno_t handle_missing_pvt(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct sdap_options *opts,
                                  const char *orig_dn,
                                  int timeout,
                                  const char *username,
                                  struct sdap_handle *sh,
                                  struct tevent_req *req,
                                  tevent_req_fn callback);

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
        ret = handle_missing_pvt(mem_ctx, ev, opts, orig_dn, timeout,
                                 state->username, sh, req,
                                 sdap_ad_tokengroups_initgr_mapping_done);
        if (ret == EOK) {
            return req;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "No ID ctx available for [%s].\n",
                  domain->name);
            goto immediately;
        }
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

errno_t sdap_ad_save_group_membership_with_idmapping(const char *username,
                                               struct sdap_options *opts,
                                               struct sss_domain_info *user_dom,
                                               struct sdap_idmap_ctx *idmap_ctx,
                                               size_t num_sids,
                                               char **sids)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    struct ldb_message *msg = NULL;
    const char *attrs[] = {SYSDB_NAME, NULL};
    const char *name = NULL;
    const char *sid = NULL;
    size_t i;
    time_t now;
    gid_t gid;
    char **groups = NULL;
    size_t num_groups;
    errno_t ret;
    errno_t sret;
    bool in_transaction = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    num_groups = 0;
    groups = talloc_zero_array(tmp_ctx, char*, num_sids + 1);
    if (groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    now = time(NULL);
    ret = sysdb_transaction_start(user_dom->sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = true;

    for (i = 0; i < num_sids; i++) {
        sid = sids[i];
        DEBUG(SSSDBG_TRACE_LIBS, "Processing membership SID [%s]\n", sid);

        ret = sdap_idmap_sid_to_unix(idmap_ctx, sid, &gid);
        if (ret == ENOTSUP) {
            DEBUG(SSSDBG_TRACE_FUNC, "Skipping built-in object.\n");
            continue;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not convert SID to GID: [%s]. "
                                         "Skipping\n", strerror(ret));
            continue;
        }

        domain = sss_get_domain_by_sid_ldap_fallback(user_dom, sid);
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
            name = sss_create_internal_fqname(tmp_ctx, sid, domain->name);
            if (name == NULL) {
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_add_incomplete_group(domain, name, gid,
                                             NULL, sid, NULL, gid != 0, now);
            if (ret == ERR_GID_DUPLICATED) {
                /* In case o group id-collision, do:
                 * - Delete the group from sysdb
                 * - Add the new incomplete group
                 * - Notify the NSS responder that the entry has also to be
                 *   removed from the memory cache
                 */
                ret = sdap_handle_id_collision_for_incomplete_groups(
                                            idmap_ctx->id_ctx->be->provider,
                                            domain, name, gid, NULL, sid, NULL,
                                            false, now);
            }

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

    ret = sdap_ad_tokengroups_update_members(username,
                                             user_dom->sysdb, user_dom,
                                             groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Membership update failed [%d]: %s\n",
                                     ret, strerror(ret));
        goto done;
    }

    ret = sysdb_transaction_commit(user_dom->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not commit transaction! [%s]\n",
                                    strerror(ret));
        goto done;
    }
    in_transaction = false;

done:
    talloc_free(tmp_ctx);

    if (in_transaction) {
        sret = sysdb_transaction_cancel(user_dom->sysdb);
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not cancel transaction! [%s]\n",
                                     strerror(sret));
    }

    return ret;
}

static void sdap_ad_tokengroups_initgr_mapping_done(struct tevent_req *subreq)
{
    struct sdap_ad_tokengroups_initgr_mapping_state *state = NULL;
    struct tevent_req *req = NULL;
    char **sids = NULL;
    size_t num_sids = 0;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_ad_tokengroups_initgr_mapping_state);

    ret = sdap_get_ad_tokengroups_recv(state, subreq, &num_sids, &sids);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to acquire tokengroups [%d]: %s\n",
                                    ret, strerror(ret));
        goto done;
    }

    ret = sdap_ad_save_group_membership_with_idmapping(state->username,
                                                       state->opts,
                                                       state->domain,
                                                       state->idmap_ctx,
                                                       num_sids,
                                                       sids);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sdap_ad_save_group_membership_with_idmapping failed.\n");
        goto done;
    }

done:
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
    char **missing_sids;
    size_t num_missing_sids;
    char **cached_groups;
    size_t num_cached_groups;
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
        ret = handle_missing_pvt(mem_ctx, ev, opts, orig_dn, timeout,
                                 state->username, sh, req,
                                 sdap_ad_tokengroups_initgr_posix_tg_done);
        if (ret == EOK) {
            return req;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "No ID ctx available for [%s].\n",
                  domain->name);
            goto immediately;
        }
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

errno_t
sdap_ad_tokengroups_get_posix_members(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *user_domain,
                                      size_t num_sids,
                                      char **sids,
                                      size_t *_num_missing,
                                      char ***_missing,
                                      size_t *_num_valid,
                                      char ***_valid_groups)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sss_domain_info *domain = NULL;
    struct ldb_message *msg = NULL;
    const char *attrs[] = {SYSDB_NAME, NULL};
    const char *name = NULL;
    char *sid = NULL;
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

        domain = sss_get_domain_by_sid_ldap_fallback(user_domain, sid);
        if (domain == NULL) {
            const char *check_dom;
            const char *check_name;

            ret = well_known_sid_to_name(sid, &check_dom, &check_name);
            if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "Skipping SID [%s][%s\\%s] which is "
                      "currently not handled by SSSD.\n",
                      sid, check_dom, check_name);
            } else {
                DEBUG(SSSDBG_MINOR_FAILURE, "Domain not found for SID %s\n", sid);
            }
            continue;
        }

        ret = sysdb_search_group_by_sid_str(tmp_ctx, domain, sid, attrs, &msg);
        if (ret == EOK) {
            /* we will update membership of this group */
            name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
            if (name == NULL) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Could not retrieve group name from sysdb\n");
                ret = EINVAL;
                goto done;
            }

            valid_groups[num_valid_groups] = sysdb_group_strdn(valid_groups,
                                                               domain->name,
                                                               name);
            if (valid_groups[num_valid_groups] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            num_valid_groups++;
        } else if (ret == ENOENT) {
            if (_missing != NULL) {
                /* we need to download this group */
                missing_sids[num_missing_sids] = talloc_steal(missing_sids,
                                                              sid);
                num_missing_sids++;

                DEBUG(SSSDBG_TRACE_FUNC, "Missing SID %s will be downloaded\n",
                                          sid);
            }

            /* else: We have downloaded missing groups but some of them may
             * remained missing because they are outside of search base. We
             * will just ignore them and continue with the next group. */
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not look up SID %s in sysdb: "
                                         "[%s]\n", sid, strerror(ret));
            goto done;
        }
    }

    valid_groups[num_valid_groups] = NULL;
    missing_sids[num_missing_sids] = NULL;

    /* return list of missing groups */
    if (_missing != NULL) {
        *_missing = talloc_steal(mem_ctx, missing_sids);
        *_num_missing = num_missing_sids;
    }

    /* return list of missing groups */
    if (_valid_groups != NULL) {
        *_valid_groups = talloc_steal(mem_ctx, valid_groups);
        *_num_valid = num_valid_groups;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void
sdap_ad_tokengroups_initgr_posix_tg_done(struct tevent_req *subreq)
{
    struct sdap_ad_tokengroups_initgr_posix_state *state = NULL;
    struct tevent_req *req = NULL;
    char **sids = NULL;
    size_t num_sids = 0;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_ad_tokengroups_initgr_posix_state);

    ret = sdap_get_ad_tokengroups_recv(state, subreq, &num_sids, &sids);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to acquire tokengroups [%d]: %s\n",
                                    ret, strerror(ret));
        goto done;
    }

    ret = sdap_ad_tokengroups_get_posix_members(state, state->domain,
                                                num_sids, sids,
                                                &state->num_missing_sids,
                                                &state->missing_sids,
                                                &state->num_cached_groups,
                                                &state->cached_groups);
    if (ret != EOK) {
        goto done;
    }

    /* download missing SIDs */
    subreq = sdap_ad_resolve_sids_send(state, state->ev, state->id_ctx,
                                       state->conn,
                                       state->opts, state->domain,
                                       state->missing_sids);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_ad_tokengroups_initgr_posix_sids_done,
                            req);

    return;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void
sdap_ad_tokengroups_initgr_posix_sids_done(struct tevent_req *subreq)
{
    struct sdap_ad_tokengroups_initgr_posix_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;
    char **cached_groups;
    size_t num_cached_groups;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_ad_tokengroups_initgr_posix_state);

    ret = sdap_ad_resolve_sids_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to resolve missing SIDs "
                                   "[%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    ret = sdap_ad_tokengroups_get_posix_members(state, state->domain,
                                                state->num_missing_sids,
                                                state->missing_sids,
                                                NULL, NULL,
                                                &num_cached_groups,
                                                &cached_groups);
    if (ret != EOK){
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sdap_ad_tokengroups_get_posix_members failed [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    state->cached_groups = concatenate_string_array(state,
                                                    state->cached_groups,
                                                    state->num_cached_groups,
                                                    cached_groups,
                                                    num_cached_groups);
    if (state->cached_groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* update membership of existing groups */
    ret = sdap_ad_tokengroups_update_members(state->username,
                                             state->sysdb, state->domain,
                                             state->cached_groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Membership update failed [%d]: %s\n",
                                     ret, strerror(ret));
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

struct sdap_ad_get_domain_local_groups_state {
    struct tevent_context *ev;
    struct sdap_id_conn_ctx *conn;
    struct sdap_options *opts;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *dom;
    int dp_error;

    struct sdap_search_base **search_bases;
    struct sysdb_attrs **groups;
    size_t num_groups;
    hash_table_t *group_hash;
};

static void
sdap_ad_get_domain_local_groups_connect_done(struct tevent_req *subreq);
static void sdap_ad_get_domain_local_groups_done(struct tevent_req *subreq);

struct tevent_req *
sdap_ad_get_domain_local_groups_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct sdap_domain *local_sdom,
                                     struct sdap_options *opts,
                                     struct sysdb_ctx *sysdb,
                                     struct sss_domain_info *dom,
                                     struct sysdb_attrs **groups,
                                     size_t num_groups)
{
    struct sdap_ad_get_domain_local_groups_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ad_id_ctx *ad_id_ctx;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_ad_get_domain_local_groups_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    ad_id_ctx = talloc_get_type(local_sdom->pvt, struct ad_id_ctx);
    state->conn = ad_id_ctx->ldap_ctx;
    state->opts = opts;
    state->sysdb = sysdb;
    state->dom = dom;
    state->search_bases = state->conn->id_ctx->opts->sdom->group_search_bases;
    state->groups = groups;
    state->num_groups = num_groups;

    ret = sss_hash_create(state, 0, &state->group_hash);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_hash_create failed.\n");
        goto fail;
    }

    state->op = sdap_id_op_create(state, state->conn->conn_cache);
    if (state->op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto fail;
    }

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed.\n");
        goto fail;
    }

    tevent_req_set_callback(subreq,
                            sdap_ad_get_domain_local_groups_connect_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void
sdap_ad_get_domain_local_groups_connect_done(struct tevent_req *subreq)
{

    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_ad_get_domain_local_groups_state *state = tevent_req_data(req,
                                  struct sdap_ad_get_domain_local_groups_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }
    subreq = rfc2307bis_nested_groups_send(state, state->ev, state->opts,
                                           state->sysdb, state->dom,
                                           sdap_id_op_handle(state->op),
                                           state->search_bases,
                                           state->groups, state->num_groups,
                                           state->group_hash, 0);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "rfc2307bis_nested_groups_send failed.\n");
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq,
                            sdap_ad_get_domain_local_groups_done, req);

    return;
}

struct sdap_nested_group {
    struct sysdb_attrs *group;
    struct sysdb_attrs **ldap_parents;
    size_t parents_count;
};

static errno_t
sdap_ad_get_domain_local_groups_parse_parents(TALLOC_CTX *mem_ctx,
                                              struct sdap_nested_group *gr,
                                              struct sss_domain_info *dom,
                                              struct sysdb_ctx *sysdb,
                                              struct sdap_options *opts,
                                              const char **_sysdb_name,
                                              enum sysdb_member_type *_type,
                                              char ***_add_list,
                                              char ***_del_list)
{
    int ret;
    size_t c;
    char **groupnamelist = NULL;
    struct sysdb_attrs *groups[1];
    enum sysdb_member_type type;
    const char *sysdb_name;
    const char *group_name;
    const char *class;
    struct sss_domain_info *obj_dom;
    char *local_groups_base_dn;
    char **cached_local_parents = NULL;
    char **add_list = NULL;
    char **del_list = NULL;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    local_groups_base_dn = talloc_asprintf(tmp_ctx, SYSDB_TMPL_GROUP_BASE,
                                           dom->name);
    if (local_groups_base_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (gr->parents_count != 0) {
        /* Store the parents if needed */
        ret = sdap_nested_groups_store(sysdb, dom, opts,
                                       gr->ldap_parents, gr->parents_count);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not save groups [%d]: %s\n",
                      ret, strerror(ret));
            goto done;
        }

        ret = sdap_get_primary_fqdn_list(dom, tmp_ctx, gr->ldap_parents,
                                       gr->parents_count,
                                       opts->group_map[SDAP_AT_GROUP_NAME].name,
                                       opts->group_map[SDAP_AT_GROUP_OBJECTSID].name,
                                       opts->idmap_ctx,
                                       &groupnamelist);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_primary_fqdn_list failed.\n");
            goto done;
        }
    }

    ret = sysdb_attrs_get_string(gr->group, SYSDB_NAME, &sysdb_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_string failed to get SYSDB_NAME, "
              "skipping.\n");
        goto done;
    }

    ret = sysdb_attrs_get_string(gr->group, SYSDB_OBJECTCATEGORY, &class);
    if (ret != EOK) {
        /* If objectcategory is missing, gr->group is a nested parent found during
         * the nested group lookup. It might not already be stored in the cache.
         */
        DEBUG(SSSDBG_TRACE_LIBS,
              "sysdb_attrs_get_string failed to get %s for [%s], assuming "
              "group.\n", SYSDB_OBJECTCATEGORY, sysdb_name);

        /* make sure group exists in cache */
        groups[0]= gr->group;
        ret = sdap_nested_groups_store(sysdb, dom, opts, groups, 1);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not save groups [%d]: %s\n",
                      ret, strerror(ret));
            goto done;
        }

        /* Since the object is coming from LDAP it cannot have the internal
         * fully-qualified name, so we can expand it unconditionally. */
        group_name = NULL;
        ret = sdap_get_primary_name(opts->group_map[SDAP_AT_GROUP_NAME].name,
                                    gr->group, &group_name);
        if (ret != EOK || group_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not determine primary name\n");
            group_name = sysdb_name;
        }

        group_name = sss_create_internal_fqname(tmp_ctx, group_name,
                                                dom->name);
        if (group_name != NULL) {
            sysdb_name = group_name;
        }

        type = SYSDB_MEMBER_GROUP;
    } else {
        if (class != NULL && strcmp(class, SYSDB_USER_CLASS) == 0) {
            type = SYSDB_MEMBER_USER;
        } else {
            type = SYSDB_MEMBER_GROUP;
        }
    }

    /* We need to get the cached list of groups form the local domain the
     * object is a member of to compare them with the current list just
     * retrieved (groupnamelist). Even if this list is empty we have to
     * proceed because the membership might have been removed recently on the
     * server. */

    obj_dom = find_domain_by_object_name(get_domains_head(dom),
                                         sysdb_name);
    if (obj_dom == NULL) {
        obj_dom = dom;
        DEBUG(SSSDBG_OP_FAILURE, "Cannot find domain for [%s], "
                                 "trying with local domain [%s].\n",
                                 sysdb_name, obj_dom->name);
    }

    ret = sysdb_get_direct_parents(tmp_ctx, obj_dom, dom, type, sysdb_name,
                                   &cached_local_parents);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,"sysdb_get_direct_parents failed.\n");
        goto done;
    }

    if (cached_local_parents != NULL && cached_local_parents[0] == NULL) {
        talloc_zfree(cached_local_parents);
    }

    if (DEBUG_IS_SET(SSSDBG_TRACE_ALL)) {
        if (cached_local_parents != NULL) {
            for (c = 0; cached_local_parents[c] != NULL; c++) {
                DEBUG(SSSDBG_TRACE_ALL, "[%s] cached_local_parents [%s].\n",
                                        sysdb_name, cached_local_parents[c]);
            }
        }

        if (groupnamelist != NULL) {
            for (c = 0; groupnamelist[c] != NULL; c++) {
                DEBUG(SSSDBG_TRACE_ALL, "[%s] groupnamelist [%s].\n",
                                        sysdb_name, groupnamelist[c]);
            }
        }
    }

    ret = diff_string_lists(tmp_ctx, cached_local_parents, groupnamelist,
                            &del_list, &add_list, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "diff_string_lists failed.\n");
        goto done;
    }

    if (DEBUG_IS_SET(SSSDBG_TRACE_ALL)) {
        if (add_list != NULL) {
            for (c = 0; add_list[c] != NULL; c++) {
                DEBUG(SSSDBG_TRACE_ALL, "add: [%s] will be member of [%s].\n",
                                        sysdb_name, add_list[c]);
            }
        }
        if (del_list != NULL) {
            for (c = 0; del_list[c] != NULL; c++) {
                DEBUG(SSSDBG_TRACE_ALL, "del: [%s] was member of [%s].\n",
                                        sysdb_name, del_list[c]);
            }
        }
    }

    *_type = type;
    *_sysdb_name = talloc_steal(mem_ctx, sysdb_name);
    *_add_list = talloc_steal(mem_ctx, groupnamelist);
    *_del_list = talloc_steal(mem_ctx, del_list);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static void sdap_ad_get_domain_local_groups_done(struct tevent_req *subreq)
{

    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_ad_get_domain_local_groups_state *state = tevent_req_data(req,
                                  struct sdap_ad_get_domain_local_groups_state);
    int ret;
    int hret;
    unsigned long count;
    hash_value_t *values = NULL;
    struct sdap_nested_group *gr;
    size_t c;
    const char *sysdb_name = NULL;
    enum sysdb_member_type type;
    char **add_list = NULL;
    char **del_list = NULL;

    ret = rfc2307bis_nested_groups_recv(subreq);
    talloc_zfree(subreq);
    if (ret == ENOENT) {
        /* In case of ENOENT we can just proceed without making
         * sdap_get_initgr_user() fail because there's no nested
         * groups for this user/group. */
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    hret = hash_values(state->group_hash, &count, &values);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "hash_values failed.\n");
        ret = EIO;
        goto done;
    }

    for (c = 0; c < count; c++) {
        gr = talloc_get_type(values[c].ptr,
                             struct sdap_nested_group);

        /* The values from the hash are either user or group objects returned
         * by sysdb_initgroups() which where used to start the request or
         * nested parents found during the request. The nested parents contain
         * the processed LDAP data and can be identified by a missing
         * objectclass attribute. */
        ret = sdap_ad_get_domain_local_groups_parse_parents(state, gr,
                                                            state->dom,
                                                            state->sysdb,
                                                            state->opts,
                                                            &sysdb_name,
                                                            &type,
                                                            &add_list,
                                                            &del_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sdap_ad_get_domain_local_groups_parse_parents failed.\n");
            continue;
        }

        if ((add_list == NULL && del_list == NULL)
                || (add_list == NULL && del_list != NULL && del_list[0] == NULL)
                || (add_list != NULL && add_list[0] == NULL && del_list == NULL)
                || (add_list != NULL && add_list[0] == NULL
                        && del_list != NULL && del_list[0] == NULL) ) {
            continue;
        }

        DEBUG(SSSDBG_TRACE_INTERNAL, "Updating domain local memberships for %s\n",
                                     sysdb_name);
        ret = sysdb_update_members(state->dom, sysdb_name, type,
                                   (const char *const *) add_list,
                                   (const char *const *) del_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_update_members failed.\n");
            goto done;
        }
    }

    ret = EOK;
done:
    talloc_zfree(values);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    return;
}

errno_t sdap_ad_get_domain_local_groups_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct sdap_ad_tokengroups_initgroups_state {
    bool use_id_mapping;
    bool use_shortcut;
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
    char **param = NULL;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_ad_tokengroups_initgroups_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->use_id_mapping = use_id_mapping;
    state->domain = domain;

    /* We can compute the gidNumber attribute from SIDs obtained from
     * the tokenGroups lookup in case ID mapping is used for a user from the
     * parent domain. For trusted domains, we need to know the group type
     * to be able to filter out domain-local groups. Additionally, as a
     * temporary workaround until https://fedorahosted.org/sssd/ticket/2656
     * is fixed, we also fetch the group object if group members are ignored
     * to avoid having to transfer and retain members when the fake
     * tokengroups object without name is replaced by the full group object
     */
    state->use_shortcut = false;
    if (state->use_id_mapping
            && !IS_SUBDOMAIN(state->domain)
            && !state->domain->ignore_group_members) {
        ret = confdb_get_param(id_ctx->be->cdb, mem_ctx, id_ctx->be->conf_path,
                               CONFDB_NSS_FILTER_GROUPS, &param);
        if (ret == EOK) {
            state->use_shortcut = (param == NULL || param[0] == NULL);
            talloc_free(param);
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to access %s: %i (%s)\n",
                  CONFDB_NSS_FILTER_GROUPS, ret, sss_strerror(ret));
            /* Continue without using the shortcut. Safest option. */
        }
    }
    if (state->use_shortcut) {
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
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    } else {
        tevent_req_set_callback(subreq, sdap_ad_tokengroups_initgroups_done, req);
    }

    return req;
}

static void sdap_ad_tokengroups_initgroups_done(struct tevent_req *subreq)
{
    struct sdap_ad_tokengroups_initgroups_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_ad_tokengroups_initgroups_state);

    if (state->use_shortcut) {
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

static errno_t handle_missing_pvt(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct sdap_options *opts,
                                  const char *orig_dn,
                                  int timeout,
                                  const char *username,
                                  struct sdap_handle *sh,
                                  struct tevent_req *req,
                                  tevent_req_fn callback)
{
    struct tevent_req *subreq = NULL;
    errno_t ret;

    if (sh != NULL) {
        /*  plain LDAP provider already has a sdap_handle */
        subreq = sdap_get_ad_tokengroups_send(mem_ctx, ev, opts, sh, username,
                                              orig_dn, timeout);
        if (subreq == NULL) {
            ret = ENOMEM;
            tevent_req_error(req, ret);
            goto done;
        }

        tevent_req_set_callback(subreq, callback, req);
        ret = EOK;
        goto done;

    } else {
        ret = EINVAL;
        goto done;
    }

done:
    return ret;
}

struct sdap_id_conn_ctx *get_ldap_conn_from_sdom_pvt(struct sdap_options *opts,
                                                     struct sdap_domain *sdom)
{
    struct ad_id_ctx *ad_id_ctx;
    struct sdap_id_conn_ctx *user_conn = NULL;

    if (opts->schema_type == SDAP_SCHEMA_AD && sdom->pvt != NULL) {
        ad_id_ctx = talloc_get_type(sdom->pvt, struct ad_id_ctx);
        if (ad_id_ctx != NULL &&  ad_id_ctx->ldap_ctx != NULL) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Returning LDAP connection for user lookup.\n");
            user_conn = ad_id_ctx->ldap_ctx;
        }
    }

    return user_conn;
}
