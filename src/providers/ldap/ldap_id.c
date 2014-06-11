/*
    SSSD

    LDAP Identity Backend Module

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2008 Red Hat

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
#include <time.h>
#include <sys/time.h>

#include "util/util.h"
#include "util/strtonum.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ldap/sdap_users.h"

/* =Users-Related-Functions-(by-name,by-uid)============================== */

struct users_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_domain *sdom;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *name;
    int filter_type;

    char *filter;
    const char **attrs;
    bool use_id_mapping;

    int dp_error;
    int sdap_ret;
    bool noexist_delete;
};

static int users_get_retry(struct tevent_req *req);
static void users_get_connect_done(struct tevent_req *subreq);
static void users_get_posix_check_done(struct tevent_req *subreq);
static void users_get_search(struct tevent_req *req);
static void users_get_done(struct tevent_req *subreq);

struct tevent_req *users_get_send(TALLOC_CTX *memctx,
                                  struct tevent_context *ev,
                                  struct sdap_id_ctx *ctx,
                                  struct sdap_domain *sdom,
                                  struct sdap_id_conn_ctx *conn,
                                  const char *name,
                                  int filter_type,
                                  int attrs_type,
                                  bool noexist_delete)
{
    struct tevent_req *req;
    struct users_get_state *state;
    const char *attr_name = NULL;
    char *clean_name;
    char *endptr;
    int ret;
    uid_t uid;
    enum idmap_error_code err;
    char *sid;

    req = tevent_req_create(memctx, &state, struct users_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->sdom = sdom;
    state->conn = conn;
    state->dp_error = DP_ERR_FATAL;
    state->noexist_delete = noexist_delete;

    state->op = sdap_id_op_create(state, state->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto done;
    }

    state->domain = sdom->dom;
    state->sysdb = sdom->dom->sysdb;
    state->name = name;
    state->filter_type = filter_type;

    state->use_id_mapping = sdap_idmap_domain_has_algorithmic_mapping(
                                                          ctx->opts->idmap_ctx,
                                                          sdom->dom->name,
                                                          sdom->dom->domain_id);
    switch (filter_type) {
    case BE_FILTER_NAME:
        attr_name = ctx->opts->user_map[SDAP_AT_USER_NAME].name;
        ret = sss_filter_sanitize(state, name, &clean_name);
        if (ret != EOK) {
            goto done;
        }
        break;
    case BE_FILTER_IDNUM:
        if (state->use_id_mapping) {
            /* If we're ID-mapping, we need to use the objectSID
             * in the search filter.
             */
            uid = strtouint32(name, &endptr, 10);
            if (errno != EOK) {
                ret = EINVAL;
                goto done;
            }

            /* Convert the UID to its objectSID */
            err = sss_idmap_unix_to_sid(ctx->opts->idmap_ctx->map,
                                        uid, &sid);
            if (err == IDMAP_NO_DOMAIN) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "[%s] did not match any configured ID mapping domain\n",
                       name);

                ret = sysdb_delete_user(state->domain, NULL, uid);
                if (ret == ENOENT) {
                    /* Ignore errors to remove users that were not cached previously */
                    ret = EOK;
                }

                goto done;
            } else if (err != IDMAP_SUCCESS) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Mapping ID [%s] to SID failed: [%s]\n",
                       name, idmap_error_string(err));
                ret = EIO;
                goto done;
            }

            attr_name = ctx->opts->user_map[SDAP_AT_USER_OBJECTSID].name;
            ret = sss_filter_sanitize(state, sid, &clean_name);
            sss_idmap_free_sid(ctx->opts->idmap_ctx->map, sid);
            if (ret != EOK) {
                goto done;
            }

        } else {
            attr_name = ctx->opts->user_map[SDAP_AT_USER_UID].name;
            ret = sss_filter_sanitize(state, name, &clean_name);
            if (ret != EOK) {
                goto done;
            }
        }
        break;
    case BE_FILTER_SECID:
        attr_name = ctx->opts->user_map[SDAP_AT_USER_OBJECTSID].name;

        ret = sss_filter_sanitize(state, name, &clean_name);
        if (ret != EOK) {
            goto done;
        }
        break;
    default:
        ret = EINVAL;
        goto done;
    }

    if (attr_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing search attribute name.\n");
        ret = EINVAL;
        goto done;
    }

    if (state->use_id_mapping || filter_type == BE_FILTER_SECID) {
        /* When mapping IDs or looking for SIDs, we don't want to limit
         * ourselves to users with a UID value. But there must be a SID to map
         * from.
         */
        state->filter = talloc_asprintf(state,
                                        "(&(%s=%s)(objectclass=%s)(%s=*)(%s=*))",
                                        attr_name, clean_name,
                                        ctx->opts->user_map[SDAP_OC_USER].name,
                                        ctx->opts->user_map[SDAP_AT_USER_NAME].name,
                                        ctx->opts->user_map[SDAP_AT_USER_OBJECTSID].name);
    } else {
        /* When not ID-mapping, make sure there is a non-NULL UID */
        state->filter = talloc_asprintf(state,
                                        "(&(%s=%s)(objectclass=%s)(%s=*)(&(%s=*)(!(%s=0))))",
                                        attr_name, clean_name,
                                        ctx->opts->user_map[SDAP_OC_USER].name,
                                        ctx->opts->user_map[SDAP_AT_USER_NAME].name,
                                        ctx->opts->user_map[SDAP_AT_USER_UID].name,
                                        ctx->opts->user_map[SDAP_AT_USER_UID].name);
    }

    talloc_zfree(clean_name);
    if (!state->filter) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build the base filter\n");
        ret = ENOMEM;
        goto done;
    }

    /* TODO: handle attrs_type */
    ret = build_attrs_from_map(state, ctx->opts->user_map,
                               ctx->opts->user_map_cnt,
                               NULL, &state->attrs, NULL);
    if (ret != EOK) goto done;

    ret = users_get_retry(req);
    if (ret != EOK) {
        goto done;
    }

    return req;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    return tevent_req_post(req, ev);
}

static int users_get_retry(struct tevent_req *req)
{
    struct users_get_state *state = tevent_req_data(req,
                                                    struct users_get_state);
    struct tevent_req *subreq;
    int ret = EOK;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        return ret;
    }

    tevent_req_set_callback(subreq, users_get_connect_done, req);
    return EOK;
}

static void users_get_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct users_get_state *state = tevent_req_data(req,
                                                     struct users_get_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    /* If POSIX attributes have been requested with an AD server and we
     * have no idea about POSIX attributes support, run a one-time check
     */
    if (state->use_id_mapping == false &&
            state->ctx->opts->schema_type == SDAP_SCHEMA_AD &&
            state->ctx->srv_opts &&
            state->ctx->srv_opts->posix_checked == false) {
        subreq = sdap_posix_check_send(state, state->ev, state->ctx->opts,
                                       sdap_id_op_handle(state->op),
                                       state->sdom->user_search_bases,
                                       dp_opt_get_int(state->ctx->opts->basic,
                                                      SDAP_SEARCH_TIMEOUT));
        if (subreq == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, users_get_posix_check_done, req);
        return;
    }

    users_get_search(req);
}

static void users_get_posix_check_done(struct tevent_req *subreq)
{
    errno_t ret;
    bool has_posix;
    int dp_error;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct users_get_state *state = tevent_req_data(req,
                                                    struct users_get_state);

    ret = sdap_posix_check_recv(subreq, &has_posix);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* We can only finish the id_op on error as the connection
         * is re-used by the user search
         */
        ret = sdap_id_op_done(state->op, ret, &dp_error);
        if (dp_error == DP_ERR_OK && ret != EOK) {
            /* retry */
            ret = users_get_retry(req);
            if (ret != EOK) {
                tevent_req_error(req, ret);
            }
            return;
        }
    }

    state->ctx->srv_opts->posix_checked = true;

    /* If the check ran to completion, we know for certain about the attributes
     */
    if (has_posix == false) {
        state->sdap_ret = ERR_NO_POSIX;
        tevent_req_done(req);
        return;
    }

    users_get_search(req);
}

static void users_get_search(struct tevent_req *req)
{
    struct users_get_state *state = tevent_req_data(req,
                                                     struct users_get_state);
    struct tevent_req *subreq;

    subreq = sdap_get_users_send(state, state->ev,
                                 state->domain, state->sysdb,
                                 state->ctx->opts,
                                 state->sdom->user_search_bases,
                                 sdap_id_op_handle(state->op),
                                 state->attrs, state->filter,
                                 dp_opt_get_int(state->ctx->opts->basic,
                                                SDAP_SEARCH_TIMEOUT),
                                 false);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, users_get_done, req);
}

static void users_get_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct users_get_state *state = tevent_req_data(req,
                                                     struct users_get_state);
    char *endptr;
    uid_t uid;
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_get_users_recv(subreq, NULL, NULL);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = users_get_retry(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        return;
    }

    if ((ret == ENOENT) &&
        (state->ctx->opts->schema_type == SDAP_SCHEMA_RFC2307) &&
        (dp_opt_get_bool(state->ctx->opts->basic,
                         SDAP_RFC2307_FALLBACK_TO_LOCAL_USERS) == true)) {
        struct sysdb_attrs **usr_attrs;
        const char *name = NULL;
        bool fallback;

        switch (state->filter_type) {
        case BE_FILTER_NAME:
            name = state->name;
            uid = -1;
            fallback = true;
            break;
        case BE_FILTER_IDNUM:
            uid = (uid_t) strtouint32(state->name, &endptr, 10);
            if (errno || *endptr || (state->name == endptr)) {
                tevent_req_error(req, errno ? errno : EINVAL);
                return;
            }
            fallback = true;
            break;
        default:
            fallback = false;
            break;
        }

        if (fallback) {
            ret = sdap_fallback_local_user(state, state->ctx->opts,
                                           name, uid, &usr_attrs);
            if (ret == EOK) {
                ret = sdap_save_user(state, state->ctx->opts, state->domain,
                                     usr_attrs[0], false, NULL, 0);
            }
        }
    }
    state->sdap_ret = ret;

    if (ret && ret != ENOENT) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    if (ret == ENOENT && state->noexist_delete == true) {
        switch (state->filter_type) {
        case BE_FILTER_ENUM:
            tevent_req_error(req, ret);
            return;
        case BE_FILTER_NAME:
            ret = sysdb_delete_user(state->domain, state->name, 0);
            if (ret != EOK && ret != ENOENT) {
                tevent_req_error(req, ret);
                return;
            }
            break;

        case BE_FILTER_IDNUM:
            uid = (uid_t) strtouint32(state->name, &endptr, 10);
            if (errno || *endptr || (state->name == endptr)) {
                tevent_req_error(req, errno ? errno : EINVAL);
                return;
            }

            ret = sysdb_delete_user(state->domain, NULL, uid);
            if (ret != EOK && ret != ENOENT) {
                tevent_req_error(req, ret);
                return;
            }
            break;

        case BE_FILTER_SECID:
            /* Since it is not clear if the SID belongs to a user or a group
             * we have nothing to do here. */
            break;

        default:
            tevent_req_error(req, EINVAL);
            return;
        }
    }

    state->dp_error = DP_ERR_OK;
    /* FIXME - return sdap error so that we know the user was not found */
    tevent_req_done(req);
}

int users_get_recv(struct tevent_req *req, int *dp_error_out, int *sdap_ret)
{
    struct users_get_state *state = tevent_req_data(req,
                                                    struct users_get_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    if (sdap_ret) {
        *sdap_ret = state->sdap_ret;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* =Groups-Related-Functions-(by-name,by-uid)============================= */

struct groups_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_domain *sdom;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *name;
    int filter_type;

    char *filter;
    const char **attrs;
    bool use_id_mapping;

    int dp_error;
    int sdap_ret;
    bool noexist_delete;
};

static int groups_get_retry(struct tevent_req *req);
static void groups_get_connect_done(struct tevent_req *subreq);
static void groups_get_posix_check_done(struct tevent_req *subreq);
static void groups_get_search(struct tevent_req *req);
static void groups_get_done(struct tevent_req *subreq);

struct tevent_req *groups_get_send(TALLOC_CTX *memctx,
                                   struct tevent_context *ev,
                                   struct sdap_id_ctx *ctx,
                                   struct sdap_domain *sdom,
                                   struct sdap_id_conn_ctx *conn,
                                   const char *name,
                                   int filter_type,
                                   int attrs_type,
                                   bool noexist_delete)
{
    struct tevent_req *req;
    struct groups_get_state *state;
    const char *attr_name = NULL;
    char *clean_name;
    char *endptr;
    int ret;
    gid_t gid;
    enum idmap_error_code err;
    char *sid;
    const char *member_filter[2];

    req = tevent_req_create(memctx, &state, struct groups_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->sdom = sdom;
    state->conn = conn;
    state->dp_error = DP_ERR_FATAL;
    state->noexist_delete = noexist_delete;

    state->op = sdap_id_op_create(state, state->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto done;
    }

    state->domain = sdom->dom;
    state->sysdb = sdom->dom->sysdb;
    state->name = name;
    state->filter_type = filter_type;

    state->use_id_mapping = sdap_idmap_domain_has_algorithmic_mapping(
                                                          ctx->opts->idmap_ctx,
                                                          sdom->dom->name,
                                                          sdom->dom->domain_id);

    switch(filter_type) {
    case BE_FILTER_NAME:
        attr_name = ctx->opts->group_map[SDAP_AT_GROUP_NAME].name;

        ret = sss_filter_sanitize(state, name, &clean_name);
        if (ret != EOK) {
            goto done;
        }
        break;
    case BE_FILTER_IDNUM:
        if (state->use_id_mapping) {
            /* If we're ID-mapping, we need to use the objectSID
             * in the search filter.
             */
            gid = strtouint32(name, &endptr, 10);
            if (errno != EOK) {
                ret = EINVAL;
                goto done;
            }

            /* Convert the GID to its objectSID */
            err = sss_idmap_unix_to_sid(ctx->opts->idmap_ctx->map,
                                        gid, &sid);
            if (err == IDMAP_NO_DOMAIN) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "[%s] did not match any configured ID mapping domain\n",
                       name);

                ret = sysdb_delete_group(state->domain, NULL, gid);
                if (ret == ENOENT) {
                    /* Ignore errors to remove users that were not cached previously */
                    ret = EOK;
                }

                goto done;
            } else if (err != IDMAP_SUCCESS) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Mapping ID [%s] to SID failed: [%s]\n",
                       name, idmap_error_string(err));
                ret = EIO;
                goto done;
            }

            attr_name = ctx->opts->group_map[SDAP_AT_GROUP_OBJECTSID].name;
            ret = sss_filter_sanitize(state, sid, &clean_name);
            sss_idmap_free_sid(ctx->opts->idmap_ctx->map, sid);
            if (ret != EOK) {
                goto done;
            }

        } else {
            attr_name = ctx->opts->group_map[SDAP_AT_GROUP_GID].name;
            ret = sss_filter_sanitize(state, name, &clean_name);
            if (ret != EOK) {
                goto done;
            }
        }
        break;
    case BE_FILTER_SECID:
        attr_name = ctx->opts->group_map[SDAP_AT_GROUP_OBJECTSID].name;

        ret = sss_filter_sanitize(state, name, &clean_name);
        if (ret != EOK) {
            goto done;
        }
        break;
    default:
        ret = EINVAL;
        goto done;
    }

    if (attr_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing search attribute name.\n");
        ret = EINVAL;
        goto done;
    }

    if (state->use_id_mapping || filter_type == BE_FILTER_SECID) {
        /* When mapping IDs or looking for SIDs, we don't want to limit
         * ourselves to groups with a GID value
         */

        state->filter = talloc_asprintf(state,
                                        "(&(%s=%s)(objectclass=%s)(%s=*))",
                                        attr_name, clean_name,
                                        ctx->opts->group_map[SDAP_OC_GROUP].name,
                                        ctx->opts->group_map[SDAP_AT_GROUP_NAME].name);
    } else {
        state->filter = talloc_asprintf(state,
                                        "(&(%s=%s)(objectclass=%s)(%s=*)(&(%s=*)(!(%s=0))))",
                                        attr_name, clean_name,
                                        ctx->opts->group_map[SDAP_OC_GROUP].name,
                                        ctx->opts->group_map[SDAP_AT_GROUP_NAME].name,
                                        ctx->opts->group_map[SDAP_AT_GROUP_GID].name,
                                        ctx->opts->group_map[SDAP_AT_GROUP_GID].name);
    }

    talloc_zfree(clean_name);
    if (!state->filter) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto done;
    }

    member_filter[0] = (const char *)ctx->opts->group_map[SDAP_AT_GROUP_MEMBER].name;
    member_filter[1] = NULL;

    /* TODO: handle attrs_type */
    ret = build_attrs_from_map(state, ctx->opts->group_map, SDAP_OPTS_GROUP,
                               state->domain->ignore_group_members ?
                                   (const char **)member_filter : NULL,
                               &state->attrs, NULL);

    if (ret != EOK) goto done;

    ret = groups_get_retry(req);
    if (ret != EOK) {
        goto done;
    }

    return req;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    return tevent_req_post(req, ev);
}

static int groups_get_retry(struct tevent_req *req)
{
    struct groups_get_state *state = tevent_req_data(req,
                                                    struct groups_get_state);
    struct tevent_req *subreq;
    int ret = EOK;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        return ret;
    }

    tevent_req_set_callback(subreq, groups_get_connect_done, req);
    return EOK;
}

static void groups_get_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct groups_get_state *state = tevent_req_data(req,
                                                     struct groups_get_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    /* If POSIX attributes have been requested with an AD server and we
     * have no idea about POSIX attributes support, run a one-time check
     */
    if (state->use_id_mapping == false &&
            state->ctx->opts->schema_type == SDAP_SCHEMA_AD &&
            state->ctx->srv_opts &&
            state->ctx->srv_opts->posix_checked == false) {
        subreq = sdap_posix_check_send(state, state->ev, state->ctx->opts,
                                       sdap_id_op_handle(state->op),
                                       state->sdom->user_search_bases,
                                       dp_opt_get_int(state->ctx->opts->basic,
                                                      SDAP_SEARCH_TIMEOUT));
        if (subreq == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, groups_get_posix_check_done, req);
        return;
    }

    groups_get_search(req);
}

static void groups_get_posix_check_done(struct tevent_req *subreq)
{
    errno_t ret;
    bool has_posix;
    int dp_error;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct groups_get_state *state = tevent_req_data(req,
                                                     struct groups_get_state);

    ret = sdap_posix_check_recv(subreq, &has_posix);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* We can only finish the id_op on error as the connection
         * is re-used by the group search
         */
        ret = sdap_id_op_done(state->op, ret, &dp_error);
        if (dp_error == DP_ERR_OK && ret != EOK) {
            /* retry */
            ret = groups_get_retry(req);
            if (ret != EOK) {
                tevent_req_error(req, ret);
            }
            return;
        }
    }

    state->ctx->srv_opts->posix_checked = true;

    /* If the check ran to completion, we know for certain about the attributes
     */
    if (has_posix == false) {
        state->sdap_ret = ERR_NO_POSIX;
        tevent_req_done(req);
        return;
    }

    groups_get_search(req);
}

static void groups_get_search(struct tevent_req *req)
{
    struct groups_get_state *state = tevent_req_data(req,
                                                     struct groups_get_state);
    struct tevent_req *subreq;

    subreq = sdap_get_groups_send(state, state->ev,
                                  state->sdom,
                                  state->ctx->opts,
                                  sdap_id_op_handle(state->op),
                                  state->attrs, state->filter,
                                  dp_opt_get_int(state->ctx->opts->basic,
                                                 SDAP_SEARCH_TIMEOUT),
                                  false);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, groups_get_done, req);
}

static void groups_get_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct groups_get_state *state = tevent_req_data(req,
                                                     struct groups_get_state);
    char *endptr;
    gid_t gid;
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_get_groups_recv(subreq, NULL, NULL);
    talloc_zfree(subreq);
    ret = sdap_id_op_done(state->op, ret, &dp_error);

    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = groups_get_retry(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        return;
    }
    state->sdap_ret = ret;

    if (ret && ret != ENOENT) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    if (ret == ENOENT && state->noexist_delete == true) {
        switch (state->filter_type) {
        case BE_FILTER_ENUM:
            tevent_req_error(req, ret);
            return;
        case BE_FILTER_NAME:
            ret = sysdb_delete_group(state->domain, state->name, 0);
            if (ret != EOK && ret != ENOENT) {
                tevent_req_error(req, ret);
                return;
            }
            break;

        case BE_FILTER_IDNUM:
            gid = (gid_t) strtouint32(state->name, &endptr, 10);
            if (errno || *endptr || (state->name == endptr)) {
                tevent_req_error(req, errno ? errno : EINVAL);
                return;
            }

            ret = sysdb_delete_group(state->domain, NULL, gid);
            if (ret != EOK && ret != ENOENT) {
                tevent_req_error(req, ret);
                return;
            }
            break;

        case BE_FILTER_SECID:
            /* Since it is not clear if the SID belongs to a user or a group
             * we have nothing to do here. */
            break;

        default:
            tevent_req_error(req, EINVAL);
            return;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
}

int groups_get_recv(struct tevent_req *req, int *dp_error_out, int *sdap_ret)
{
    struct groups_get_state *state = tevent_req_data(req,
                                                     struct groups_get_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    if (sdap_ret) {
        *sdap_ret = state->sdap_ret;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}


/* =Get-Groups-for-User================================================== */

struct groups_by_user_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_domain *sdom;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *name;
    const char **attrs;

    int dp_error;
    int sdap_ret;
    bool noexist_delete;
};

static int groups_by_user_retry(struct tevent_req *req);
static void groups_by_user_connect_done(struct tevent_req *subreq);
static void groups_by_user_done(struct tevent_req *subreq);

static struct tevent_req *groups_by_user_send(TALLOC_CTX *memctx,
                                              struct tevent_context *ev,
                                              struct sdap_id_ctx *ctx,
                                              struct sdap_domain *sdom,
                                              struct sdap_id_conn_ctx *conn,
                                              const char *name,
                                              bool noexist_delete)
{
    struct tevent_req *req;
    struct groups_by_user_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct groups_by_user_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->dp_error = DP_ERR_FATAL;
    state->conn = conn;
    state->sdom = sdom;
    state->noexist_delete = noexist_delete;

    state->op = sdap_id_op_create(state, state->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto fail;
    }

    state->name = name;
    state->domain = sdom->dom;
    state->sysdb = sdom->dom->sysdb;

    ret = build_attrs_from_map(state, ctx->opts->group_map, SDAP_OPTS_GROUP,
                               NULL, &state->attrs, NULL);
    if (ret != EOK) goto fail;

    ret = groups_by_user_retry(req);
    if (ret != EOK) {
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static int groups_by_user_retry(struct tevent_req *req)
{
    struct groups_by_user_state *state = tevent_req_data(req,
                                                         struct groups_by_user_state);
    struct tevent_req *subreq;
    int ret = EOK;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        return ret;
    }

    tevent_req_set_callback(subreq, groups_by_user_connect_done, req);
    return EOK;
}

static void groups_by_user_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct groups_by_user_state *state = tevent_req_data(req,
                                                     struct groups_by_user_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_initgr_send(state,
                                  state->ev,
                                  state->sdom,
                                  sdap_id_op_handle(state->op),
                                  state->ctx,
                                  state->conn,
                                  state->name,
                                  state->attrs);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, groups_by_user_done, req);
}

static void groups_by_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct groups_by_user_state *state = tevent_req_data(req,
                                                     struct groups_by_user_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_get_initgr_recv(subreq);
    talloc_zfree(subreq);
    ret = sdap_id_op_done(state->op, ret, &dp_error);

    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = groups_by_user_retry(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        return;
    }
    state->sdap_ret = ret;

    if (ret && ret != ENOENT) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    if (ret == ENOENT && state->noexist_delete == true) {
        ret = sysdb_delete_user(state->ctx->be->domain, state->name, 0);
        if (ret != EOK && ret != ENOENT) {
            tevent_req_error(req, ret);
            return;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
}

int groups_by_user_recv(struct tevent_req *req, int *dp_error_out, int *sdap_ret)
{
    struct groups_by_user_state *state = tevent_req_data(req,
                                                             struct groups_by_user_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    if (sdap_ret) {
        *sdap_ret = state->sdap_ret;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void sdap_check_online_done(struct tevent_req *req);
void sdap_check_online(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct sdap_id_ctx *ctx;

    ctx = talloc_get_type(be_ctx->bet_info[BET_ID].pvt_bet_data,
                          struct sdap_id_ctx);

    return sdap_do_online_check(be_req, ctx);
}

struct sdap_online_check_ctx {
    struct be_req *be_req;
    struct sdap_id_ctx *id_ctx;
};

void sdap_do_online_check(struct be_req *be_req, struct sdap_id_ctx *ctx)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct tevent_req *req;
    struct sdap_online_check_ctx *check_ctx;
    errno_t ret;

    check_ctx = talloc_zero(be_req, struct sdap_online_check_ctx);
    if (!check_ctx) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed\n");
        goto fail;
    }
    check_ctx->id_ctx = ctx;
    check_ctx->be_req = be_req;

    req = sdap_cli_connect_send(be_req, be_ctx->ev, ctx->opts,
                                be_ctx, ctx->conn->service, false,
                                CON_TLS_DFL, false);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_cli_connect_send failed.\n");
        ret = EIO;
        goto fail;
    }
    tevent_req_set_callback(req, sdap_check_online_done, check_ctx);

    return;
fail:
    sdap_handler_done(be_req, DP_ERR_FATAL, ret, NULL);
}

static void sdap_check_online_reinit_done(struct tevent_req *req);

static void sdap_check_online_done(struct tevent_req *req)
{
    struct sdap_online_check_ctx *check_ctx = tevent_req_callback_data(req,
                                        struct sdap_online_check_ctx);
    int ret;
    int dp_err = DP_ERR_FATAL;
    bool can_retry;
    struct sdap_server_opts *srv_opts;
    struct be_req *be_req;
    struct sdap_id_ctx *id_ctx;
    struct tevent_req *reinit_req = NULL;
    bool reinit = false;
    struct be_ctx *be_ctx;

    ret = sdap_cli_connect_recv(req, NULL, &can_retry, NULL, &srv_opts);
    talloc_zfree(req);

    if (ret != EOK) {
        if (!can_retry) {
            dp_err = DP_ERR_OFFLINE;
        }
    } else {
        dp_err = DP_ERR_OK;

        if (!check_ctx->id_ctx->srv_opts) {
            srv_opts->max_user_value = 0;
            srv_opts->max_group_value = 0;
            srv_opts->max_service_value = 0;
            srv_opts->max_sudo_value = 0;
        } else if (strcmp(srv_opts->server_id, check_ctx->id_ctx->srv_opts->server_id) == 0
                   && srv_opts->supports_usn
                   && check_ctx->id_ctx->srv_opts->last_usn > srv_opts->last_usn) {
            check_ctx->id_ctx->srv_opts->max_user_value = 0;
            check_ctx->id_ctx->srv_opts->max_group_value = 0;
            check_ctx->id_ctx->srv_opts->max_service_value = 0;
            check_ctx->id_ctx->srv_opts->max_sudo_value = 0;
            check_ctx->id_ctx->srv_opts->last_usn = srv_opts->last_usn;

            reinit = true;
        }

        sdap_steal_server_opts(check_ctx->id_ctx, &srv_opts);
    }

    be_req = check_ctx->be_req;
    be_ctx = be_req_get_be_ctx(be_req);
    id_ctx = check_ctx->id_ctx;
    talloc_free(check_ctx);

    if (reinit) {
        DEBUG(SSSDBG_TRACE_FUNC, "Server reinitialization detected. "
                                  "Cleaning cache.\n");
        reinit_req = sdap_reinit_cleanup_send(be_req, be_ctx, id_ctx);
        if (reinit_req == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to perform reinitialization "
                                        "clean up.\n");
            /* not fatal */
            goto done;
        }

        tevent_req_set_callback(reinit_req, sdap_check_online_reinit_done,
                                be_req);
        return;
    }

done:
    sdap_handler_done(be_req, dp_err, 0, NULL);
}

static void sdap_check_online_reinit_done(struct tevent_req *req)
{
    struct be_req *be_req = NULL;
    errno_t ret;

    be_req = tevent_req_callback_data(req, struct be_req);
    ret = sdap_reinit_cleanup_recv(req);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to perform reinitialization "
              "clean up [%d]: %s\n", ret, strerror(ret));
        /* not fatal */
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Reinitialization clean up completed\n");
    }

    sdap_handler_done(be_req, DP_ERR_OK, 0, NULL);
}

/* =Get-Account-Info-Call================================================= */

/* FIXME: embed this function in sssd_be and only call out
 * specific functions from modules ? */

void sdap_handle_account_info(struct be_req *breq, struct sdap_id_ctx *ctx,
                              struct sdap_id_conn_ctx *conn);

static struct tevent_req *get_user_and_group_send(TALLOC_CTX *memctx,
                                                  struct tevent_context *ev,
                                                  struct sdap_id_ctx *ctx,
                                                  struct sdap_domain *sdom,
                                                  struct sdap_id_conn_ctx *conn,
                                                  const char *name,
                                                  int filter_type,
                                                  int attrs_type,
                                                  bool noexist_delete);

errno_t sdap_get_user_and_group_recv(struct tevent_req *req,
                                     int *dp_error_out, int *sdap_ret);

void sdap_account_info_handler(struct be_req *breq)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(breq);
    struct sdap_id_ctx *ctx;

    ctx = talloc_get_type(be_ctx->bet_info[BET_ID].pvt_bet_data, struct sdap_id_ctx);
    if (!ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not get sdap ctx\n");
        return sdap_handler_done(breq, DP_ERR_FATAL,
                                 EINVAL, "Invalid request data\n");
    }
    return sdap_handle_account_info(breq, ctx, ctx->conn);
}

/* A generic LDAP account info handler */
struct sdap_handle_acct_req_state {
    struct be_req *breq;
    struct be_acct_req *ar;
    const char *err;
    int dp_error;
    int sdap_ret;
};

static void sdap_handle_acct_req_done(struct tevent_req *subreq);

struct tevent_req *
sdap_handle_acct_req_send(TALLOC_CTX *mem_ctx,
                          struct be_req *breq,
                          struct be_acct_req *ar,
                          struct sdap_id_ctx *id_ctx,
                          struct sdap_domain *sdom,
                          struct sdap_id_conn_ctx *conn,
                          bool noexist_delete)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct be_ctx *be_ctx;
    struct sdap_handle_acct_req_state *state;
    errno_t ret;

    be_ctx = be_req_get_be_ctx(breq);

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_handle_acct_req_state);
    if (!req) {
        ret = ENOMEM;
        goto done;
    }
    state->breq = breq;
    state->ar = ar;

    if (ar == NULL) {
        ret = EINVAL;
        goto done;
    }

    switch (ar->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER: /* user */

        /* skip enumerations on demand */
        if (ar->filter_type == BE_FILTER_ENUM) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Skipping user enumeration on demand\n");
            state->err = "Success";
            ret = EOK;
            goto done;
        }

        subreq = users_get_send(breq, be_ctx->ev, id_ctx,
                                sdom, conn,
                                ar->filter_value,
                                ar->filter_type,
                                ar->attr_type,
                                noexist_delete);
        break;

    case BE_REQ_GROUP: /* group */

        /* skip enumerations on demand */
        if (ar->filter_type == BE_FILTER_ENUM) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Skipping group enumeration on demand\n");
            state->err = "Success";
            ret = EOK;
            goto done;
        }

        subreq = groups_get_send(breq, be_ctx->ev, id_ctx,
                                 sdom, conn,
                                 ar->filter_value,
                                 ar->filter_type,
                                 ar->attr_type,
                                 noexist_delete);
        break;

    case BE_REQ_INITGROUPS: /* init groups for user */
        if (ar->filter_type != BE_FILTER_NAME) {
            ret = EINVAL;
            state->err = "Invalid filter type";
            goto done;
        }
        if (ar->attr_type != BE_ATTR_CORE) {
            ret = EINVAL;
            state->err = "Invalid attr type";
            goto done;
        }

        subreq = groups_by_user_send(breq, be_ctx->ev, id_ctx,
                                     sdom, conn,
                                     ar->filter_value,
                                     noexist_delete);
        break;

    case BE_REQ_NETGROUP:
        if (ar->filter_type != BE_FILTER_NAME) {
            ret = EINVAL;
            state->err = "Invalid filter type";
            goto done;
        }

        subreq = ldap_netgroup_get_send(breq, be_ctx->ev, id_ctx,
                                        sdom, conn,
                                        ar->filter_value,
                                        noexist_delete);
        break;

    case BE_REQ_SERVICES:
        /* skip enumerations on demand */
        if (ar->filter_type == BE_FILTER_ENUM) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Skipping service enumeration on demand\n");
            state->err = "Success";
            ret = EOK;
            goto done;
        }

        if (ar->filter_type == BE_FILTER_SECID) {
            ret = EINVAL;
            state->err = "Invalid filter type";
            goto done;
        }

        subreq = services_get_send(breq, be_ctx->ev, id_ctx,
                                   sdom, conn,
                                   ar->filter_value,
                                   ar->extra_value,
                                   ar->filter_type,
                                   noexist_delete);
        break;

    case BE_REQ_BY_SECID:
        if (ar->filter_type != BE_FILTER_SECID) {
            ret = EINVAL;
            state->err = "Invalid filter type";
            goto done;
        }

        subreq = get_user_and_group_send(breq, be_ctx->ev, id_ctx,
                                         sdom, conn,
                                         ar->filter_value,
                                         ar->filter_type,
                                         ar->attr_type,
                                         noexist_delete);
        break;

    case BE_REQ_USER_AND_GROUP:
        if (!(ar->filter_type == BE_FILTER_NAME ||
              ar->filter_type == BE_FILTER_IDNUM)) {
            ret = EINVAL;
            state->err = "Invalid filter type";
            goto done;
        }

        subreq = get_user_and_group_send(breq, be_ctx->ev, id_ctx,
                                         sdom, conn,
                                         ar->filter_value,
                                         ar->filter_type,
                                         ar->attr_type,
                                         noexist_delete);
        break;

    default: /*fail*/
        ret = EINVAL;
        state->err = "Invalid request type";
        goto done;
    }

    if (!subreq) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_handle_acct_req_done, req);
    return req;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    tevent_req_post(req, be_ctx->ev);
    return req;
}

static void
sdap_handle_acct_req_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_handle_acct_req_state *state;
    errno_t ret;
    const char *err = "Invalid request type";

    state = tevent_req_data(req, struct sdap_handle_acct_req_state);

    switch (state->ar->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER: /* user */
        err = "User lookup failed";
        ret = users_get_recv(subreq, &state->dp_error, &state->sdap_ret);
        break;
    case BE_REQ_GROUP: /* group */
        err = "Group lookup failed";
        ret = groups_get_recv(subreq, &state->dp_error, &state->sdap_ret);
        break;
    case BE_REQ_INITGROUPS: /* init groups for user */
        err = "Init group lookup failed";
        ret = groups_by_user_recv(subreq, &state->dp_error, &state->sdap_ret);
        break;
    case BE_REQ_NETGROUP:
        err = "Netgroup lookup failed";
        ret = ldap_netgroup_get_recv(subreq, &state->dp_error, &state->sdap_ret);
        break;
    case BE_REQ_SERVICES:
        err = "Service lookup failed";
        ret = services_get_recv(subreq, &state->dp_error, &state->sdap_ret);
        break;
    case BE_REQ_BY_SECID:
        /* Fallthrough */
    case BE_REQ_USER_AND_GROUP:
        err = "Lookup by SID failed";
        ret = sdap_get_user_and_group_recv(subreq, &state->dp_error,
                                           &state->sdap_ret);
        break;
    default: /*fail*/
        ret = EINVAL;
        break;
    }
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->err = err;
        tevent_req_error(req, ret);
        return;
    }

    state->err = "Success";
    tevent_req_done(req);
}

errno_t
sdap_handle_acct_req_recv(struct tevent_req *req,
                          int *_dp_error, const char **_err,
                          int *sdap_ret)
{
    struct sdap_handle_acct_req_state *state;

    state = tevent_req_data(req, struct sdap_handle_acct_req_state);

    if (_dp_error) {
        *_dp_error = state->dp_error;
    }

    if (_err) {
        *_err = state->err;
    }

    if (sdap_ret) {
        *sdap_ret = state->sdap_ret;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static void sdap_account_info_complete(struct tevent_req *req);

void sdap_handle_account_info(struct be_req *breq, struct sdap_id_ctx *ctx,
                              struct sdap_id_conn_ctx *conn)
{
    struct be_acct_req *ar;
    struct tevent_req *req;

    if (be_is_offline(ctx->be)) {
        return sdap_handler_done(breq, DP_ERR_OFFLINE, EAGAIN, "Offline");
    }

    ar = talloc_get_type(be_req_get_data(breq), struct be_acct_req);
    if (ar == NULL) {
        return sdap_handler_done(breq, DP_ERR_FATAL,
                                 EINVAL, "Invalid private data");
    }

    req = sdap_handle_acct_req_send(breq, breq, ar, ctx,
                                    ctx->opts->sdom, conn, true);
    if (req == NULL) {
        return sdap_handler_done(breq, DP_ERR_FATAL, ENOMEM, "Out of memory");
    }
    tevent_req_set_callback(req, sdap_account_info_complete, breq);
}

static void sdap_account_info_complete(struct tevent_req *req)
{
    const char *error_text;
    const char *req_error_text;
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    int ret, dp_error;

    ret = sdap_handle_acct_req_recv(req, &dp_error, &req_error_text, NULL);
    talloc_zfree(req);
    if (dp_error == DP_ERR_OK) {
        if (ret == EOK) {
            error_text = NULL;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Bug: dp_error is OK on failed request");
            dp_error = DP_ERR_FATAL;
            error_text = req_error_text;
        }
    } else if (dp_error == DP_ERR_OFFLINE) {
        error_text = "Offline";
    } else if (dp_error == DP_ERR_FATAL && ret == ENOMEM) {
        error_text = "Out of memory";
    } else {
        error_text = req_error_text;
    }

    sdap_handler_done(breq, dp_error, ret, error_text);
}

struct get_user_and_group_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *id_ctx;
    struct sdap_domain *sdom;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *filter_val;
    int filter_type;
    int attrs_type;

    char *filter;
    const char **attrs;

    int dp_error;
    int sdap_ret;
    bool noexist_delete;
};

static void get_user_and_group_users_done(struct tevent_req *subreq);
static void get_user_and_group_groups_done(struct tevent_req *subreq);

static struct tevent_req *get_user_and_group_send(TALLOC_CTX *memctx,
                                                  struct tevent_context *ev,
                                                  struct sdap_id_ctx *id_ctx,
                                                  struct sdap_domain *sdom,
                                                  struct sdap_id_conn_ctx *conn,
                                                  const char *filter_val,
                                                  int filter_type,
                                                  int attrs_type,
                                                  bool noexist_delete)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct get_user_and_group_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct get_user_and_group_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->id_ctx = id_ctx;
    state->sdom = sdom;
    state->conn = conn;
    state->dp_error = DP_ERR_FATAL;
    state->noexist_delete = noexist_delete;

    state->op = sdap_id_op_create(state, state->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto fail;
    }

    state->domain = sdom->dom;
    state->sysdb = sdom->dom->sysdb;
    state->filter_val = filter_val;
    state->filter_type = filter_type;
    state->attrs_type = attrs_type;

    subreq = groups_get_send(req, state->ev, state->id_ctx,
                             state->sdom, state->conn,
                             state->filter_val, state->filter_type,
                             state->attrs_type, state->noexist_delete);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "users_get_send failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, get_user_and_group_groups_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void get_user_and_group_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct get_user_and_group_state *state = tevent_req_data(req,
                                               struct get_user_and_group_state);
    int ret;

    ret = groups_get_recv(subreq, &state->dp_error, &state->sdap_ret);
    talloc_zfree(subreq);

    if (ret != EOK) {           /* Fatal error while looking up group */
        tevent_req_error(req, ret);
        return;
    }

    if (state->sdap_ret == EOK) {   /* Matching group found */
        tevent_req_done(req);
        return;
    } else if (state->sdap_ret != ENOENT) {
        tevent_req_error(req, EIO);
        return;
    }

    /* Now the search finished fine but did not find an entry.
     * Retry with users. */
    subreq = users_get_send(req, state->ev, state->id_ctx,
                            state->sdom, state->conn,
                            state->filter_val, state->filter_type,
                            state->attrs_type, state->noexist_delete);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "groups_get_send failed.\n");
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, get_user_and_group_users_done, req);
}

static void get_user_and_group_users_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct get_user_and_group_state *state = tevent_req_data(req,
                                               struct get_user_and_group_state);
    int ret;

    ret = users_get_recv(subreq, &state->dp_error, &state->sdap_ret);
    talloc_zfree(subreq);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->sdap_ret == ENOENT) {
        /* The search ran to completion, but nothing was found.
         * Delete the existing entry, if any. */
        ret = sysdb_delete_by_sid(state->sysdb, state->domain,
                                  state->filter_val);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not delete entry by SID!\n");
            tevent_req_error(req, ret);
            return;
        }
    } else if (state->sdap_ret != EOK) {
        tevent_req_error(req, EIO);
        return;
    }

    /* Both ret and sdap->ret are EOK. Matching user found */
    tevent_req_done(req);
    return;
}

errno_t sdap_get_user_and_group_recv(struct tevent_req *req,
                                     int *dp_error_out, int *sdap_ret)
{
    struct get_user_and_group_state *state = tevent_req_data(req,
                                               struct get_user_and_group_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    if (sdap_ret) {
        *sdap_ret = state->sdap_ret;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
