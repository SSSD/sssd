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
#include "util/probes.h"
#include "util/strtonum.h"
#include "util/cert.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ldap/sdap_users.h"

errno_t users_get_handle_no_user(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 int filter_type, const char *filter_value,
                                 bool name_is_upn)
{
    int ret;
    const char *del_name;
    struct ldb_message *msg = NULL;
    uid_t uid;
    char *endptr;

    switch (filter_type) {
    case BE_FILTER_ENUM:
        ret = EOK;
        break;
    case BE_FILTER_NAME:
        if (name_is_upn == true) {
            ret = sysdb_search_user_by_upn(mem_ctx, domain, false,
                                           filter_value,
                                           NULL, &msg);
            if (ret == ENOENT) {
                return EOK;
            } else if (ret != EOK && ret != ENOENT) {
                return ret;
            }
            del_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        } else {
            del_name = filter_value;
        }

        if (del_name == NULL) {
            ret = ENOMEM;
            break;
        }

        ret = sysdb_delete_user(domain, del_name, 0);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_delete_user failed [%d].\n", ret);
        } else {
            ret = EOK;
        }
        break;

    case BE_FILTER_IDNUM:
        uid = (uid_t) strtouint32(filter_value, &endptr, 10);
        if (errno || *endptr || (filter_value == endptr)) {
            ret = errno ? errno : EINVAL;
            break;
        }

        ret = sysdb_delete_user(domain, NULL, uid);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_delete_user failed [%d].\n", ret);
        } else {
            ret = EOK;
        }
        break;

    case BE_FILTER_SECID:
    case BE_FILTER_UUID:
        /* Since it is not clear if the SID/UUID belongs to a user or a
         * group we have nothing to do here. */
        ret  = EOK;
        break;

    case BE_FILTER_WILDCARD:
        /* We can't know if all users are up-to-date, especially in a large
         * environment. Do not delete any records, let the responder fetch
         * the entries they are requested in
         */
        ret = EOK;
        break;

    case BE_FILTER_CERT:
        ret = sysdb_remove_cert(domain, filter_value);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to remove user certificate"
                  "[%d]: %s\n", ret, sss_strerror(ret));
        }
        break;

    default:
        ret = EINVAL;
    }

    talloc_free(msg);
    return ret;
}

/* =Users-Related-Functions-(by-name,by-uid)============================== */

struct users_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_domain *sdom;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    char *shortname;

    const char *filter_value;
    int filter_type;
    bool name_is_upn;

    char *filter;
    const char **attrs;
    bool use_id_mapping;
    bool non_posix;

    int dp_error;
    int sdap_ret;
    bool noexist_delete;
    struct sysdb_attrs *extra_attrs;
};

static int users_get_retry(struct tevent_req *req);
static void users_get_connect_done(struct tevent_req *subreq);
static void users_get_search(struct tevent_req *req);
static void users_get_done(struct tevent_req *subreq);

struct tevent_req *users_get_send(TALLOC_CTX *memctx,
                                  struct tevent_context *ev,
                                  struct sdap_id_ctx *ctx,
                                  struct sdap_domain *sdom,
                                  struct sdap_id_conn_ctx *conn,
                                  const char *filter_value,
                                  int filter_type,
                                  const char *extra_value,
                                  bool noexist_delete,
                                  bool set_non_posix)
{
    struct tevent_req *req;
    struct users_get_state *state;
    const char *attr_name = NULL;
    char *clean_value = NULL;
    char *endptr;
    int ret;
    uid_t uid;
    enum idmap_error_code err;
    char *sid;
    char *user_filter = NULL;
    char *ep_filter;

    req = tevent_req_create(memctx, &state, struct users_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->sdom = sdom;
    state->conn = conn;
    state->dp_error = DP_ERR_FATAL;
    state->noexist_delete = noexist_delete;
    state->extra_attrs = NULL;

    state->op = sdap_id_op_create(state, state->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto done;
    }

    state->domain = sdom->dom;
    state->sysdb = sdom->dom->sysdb;
    state->filter_value = filter_value;
    state->filter_type = filter_type;

    if (state->domain->type == DOM_TYPE_APPLICATION || set_non_posix) {
        state->non_posix = true;
    }

    state->use_id_mapping = sdap_idmap_domain_has_algorithmic_mapping(
                                                          ctx->opts->idmap_ctx,
                                                          sdom->dom->name,
                                                          sdom->dom->domain_id);
    switch (filter_type) {
    case BE_FILTER_WILDCARD:
        attr_name = ctx->opts->user_map[SDAP_AT_USER_NAME].name;
        ret = sss_filter_sanitize_ex(state, filter_value, &clean_value,
                                     LDAP_ALLOWED_WILDCARDS);
        if (ret != EOK) {
            goto done;
        }
        break;
    case BE_FILTER_NAME:
        if (extra_value && strcmp(extra_value, EXTRA_NAME_IS_UPN) == 0) {
            ret = sss_filter_sanitize(state, filter_value, &clean_value);
            if (ret != EOK) {
                goto done;
            }

            ep_filter = get_enterprise_principal_string_filter(state,
                                   ctx->opts->user_map[SDAP_AT_USER_PRINC].name,
                                   clean_value, ctx->opts->basic);
            /* TODO: Do we have to check the attribute names more carefully? */
            user_filter = talloc_asprintf(state, "(|(%s=%s)(%s=%s)%s)",
                                   ctx->opts->user_map[SDAP_AT_USER_PRINC].name,
                                   clean_value,
                                   ctx->opts->user_map[SDAP_AT_USER_EMAIL].name,
                                   clean_value,
                                   ep_filter == NULL ? "" : ep_filter);
            talloc_zfree(clean_value);
            if (user_filter == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
                ret = ENOMEM;
                goto done;
            }
        } else {
            attr_name = ctx->opts->user_map[SDAP_AT_USER_NAME].name;

            ret = sss_parse_internal_fqname(state, filter_value,
                                            &state->shortname, NULL);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Cannot parse %s\n", filter_value);
                goto done;
            }

            ret = sss_filter_sanitize(state, state->shortname, &clean_value);
            if (ret != EOK) {
                goto done;
            }
        }
        break;
    case BE_FILTER_IDNUM:
        if (state->use_id_mapping) {
            /* If we're ID-mapping, we need to use the objectSID
             * in the search filter.
             */
            uid = strtouint32(filter_value, &endptr, 10);
            if ((errno != EOK) || *endptr || (filter_value == endptr)) {
                ret = EINVAL;
                goto done;
            }

            /* Convert the UID to its objectSID */
            err = sss_idmap_unix_to_sid(ctx->opts->idmap_ctx->map,
                                        uid, &sid);
            if (err == IDMAP_NO_DOMAIN) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "[%s] did not match any configured ID mapping domain\n",
                       filter_value);

                ret = sysdb_delete_user(state->domain, NULL, uid);
                if (ret == ENOENT) {
                    /* Ignore errors to remove users that were not cached previously */
                    ret = EOK;
                }

                goto done;
            } else if (err != IDMAP_SUCCESS) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Mapping ID [%s] to SID failed: [%s]\n",
                       filter_value, idmap_error_string(err));
                ret = EIO;
                goto done;
            }

            attr_name = ctx->opts->user_map[SDAP_AT_USER_OBJECTSID].name;
            ret = sss_filter_sanitize(state, sid, &clean_value);
            sss_idmap_free_sid(ctx->opts->idmap_ctx->map, sid);
            if (ret != EOK) {
                goto done;
            }

        } else {
            attr_name = ctx->opts->user_map[SDAP_AT_USER_UID].name;
            ret = sss_filter_sanitize(state, filter_value, &clean_value);
            if (ret != EOK) {
                goto done;
            }
        }
        break;
    case BE_FILTER_SECID:
        attr_name = ctx->opts->user_map[SDAP_AT_USER_OBJECTSID].name;

        ret = sss_filter_sanitize(state, filter_value, &clean_value);
        if (ret != EOK) {
            goto done;
        }
        break;
    case BE_FILTER_UUID:
        attr_name = ctx->opts->user_map[SDAP_AT_USER_UUID].name;
        if (attr_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "UUID search not configured for this backend.\n");
            ret = EINVAL;
            goto done;
        }

        ret = sss_filter_sanitize(state, filter_value, &clean_value);
        if (ret != EOK) {
            goto done;
        }
        break;
    case BE_FILTER_CERT:
        attr_name = ctx->opts->user_map[SDAP_AT_USER_CERT].name;
        if (attr_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Certificate search not configured for this backend.\n");
            ret = EINVAL;
            goto done;
        }

        ret = sss_cert_derb64_to_ldap_filter(state, filter_value, attr_name,
                              sdap_get_sss_certmap(ctx->opts->sdap_certmap_ctx),
                              state->domain, &user_filter);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sss_cert_derb64_to_ldap_filter failed.\n");

            /* Typically sss_cert_derb64_to_ldap_filter() will fail if there
             * is no mapping rule matching the current certificate. But this
             * just means that no matching user can be found so we can finish
             * the request with this result. Even if
             * sss_cert_derb64_to_ldap_filter() would fail for other reason
             * there is no need to return an error which might cause the
             * domain go offline. */

            if (noexist_delete) {
                ret = sysdb_remove_cert(state->domain, filter_value);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "Ignoring error while removing user certificate "
                          "[%d]: %s\n", ret, sss_strerror(ret));
                }
            }

            ret = EOK;
            state->sdap_ret = ENOENT;
            state->dp_error = DP_ERR_OK;
            goto done;
        }

        state->extra_attrs = sysdb_new_attrs(state);
        if (state->extra_attrs == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_add_base64_blob(state->extra_attrs,
                                          SYSDB_USER_MAPPED_CERT, filter_value);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_base64_blob failed.\n");
            goto done;
        }

        break;
    default:
        ret = EINVAL;
        goto done;
    }

    if (attr_name == NULL && user_filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing search attribute name or filter.\n");
        ret = EINVAL;
        goto done;
    }

    if (user_filter == NULL) {
        user_filter = talloc_asprintf(state, "(%s=%s)", attr_name, clean_value);
        talloc_free(clean_value);
        if (user_filter == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (state->non_posix) {
        state->filter = talloc_asprintf(state,
                                        "(&%s(objectclass=%s)(%s=*))",
                                        user_filter,
                                        ctx->opts->user_map[SDAP_OC_USER].name,
                                        ctx->opts->user_map[SDAP_AT_USER_NAME].name);
    } else if (state->use_id_mapping || filter_type == BE_FILTER_SECID) {
        /* When mapping IDs or looking for SIDs, we don't want to limit
         * ourselves to users with a UID value. But there must be a SID to map
         * from.
         */
        state->filter = talloc_asprintf(state,
                                        "(&%s(objectclass=%s)(%s=*)(%s=*))",
                                        user_filter,
                                        ctx->opts->user_map[SDAP_OC_USER].name,
                                        ctx->opts->user_map[SDAP_AT_USER_NAME].name,
                                        ctx->opts->user_map[SDAP_AT_USER_OBJECTSID].name);
    } else {
        /* When not ID-mapping or looking up POSIX users,
         * make sure there is a non-NULL UID */
        state->filter = talloc_asprintf(state,
                                        "(&%s(objectclass=%s)(%s=*)(&(%s=*)(!(%s=0))))",
                                        user_filter,
                                        ctx->opts->user_map[SDAP_OC_USER].name,
                                        ctx->opts->user_map[SDAP_AT_USER_NAME].name,
                                        ctx->opts->user_map[SDAP_AT_USER_UID].name,
                                        ctx->opts->user_map[SDAP_AT_USER_UID].name);
    }

    talloc_zfree(user_filter);
    if (!state->filter) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build the base filter\n");
        ret = ENOMEM;
        goto done;
    }

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

    users_get_search(req);
}

static void users_get_search(struct tevent_req *req)
{
    struct users_get_state *state = tevent_req_data(req,
                                                     struct users_get_state);
    struct tevent_req *subreq;
    enum sdap_entry_lookup_type lookup_type;

    if (state->filter_type == BE_FILTER_WILDCARD) {
        lookup_type = SDAP_LOOKUP_WILDCARD;
    } else {
        lookup_type = SDAP_LOOKUP_SINGLE;
    }

    subreq = sdap_get_users_send(state, state->ev,
                                 state->domain, state->sysdb,
                                 state->ctx->opts,
                                 state->sdom->user_search_bases,
                                 sdap_id_op_handle(state->op),
                                 state->attrs, state->filter,
                                 dp_opt_get_int(state->ctx->opts->basic,
                                                SDAP_SEARCH_TIMEOUT),
                                 lookup_type, state->extra_attrs);
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
    uid_t uid = 0;
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
        bool fallback;

        switch (state->filter_type) {
        case BE_FILTER_NAME:
            uid = -1;
            fallback = true;
            break;
        case BE_FILTER_IDNUM:
            uid = (uid_t) strtouint32(state->filter_value, &endptr, 10);
            if (errno || *endptr || (state->filter_value == endptr)) {
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
            ret = sdap_fallback_local_user(state, state->shortname, uid, &usr_attrs);
            if (ret == EOK) {
                ret = sdap_save_user(state, state->ctx->opts, state->domain,
                                     usr_attrs[0], NULL, NULL, 0,
                                     state->non_posix);
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
        ret = users_get_handle_no_user(state, state->domain, state->filter_type,
                                       state->filter_value, state->name_is_upn);
        if (ret != EOK) {
            tevent_req_error(req, ret);
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

    const char *filter_value;
    int filter_type;

    char *filter;
    const char **attrs;
    bool use_id_mapping;
    bool non_posix;

    int dp_error;
    int sdap_ret;
    bool noexist_delete;
    bool no_members;
};

static int groups_get_retry(struct tevent_req *req);
static void groups_get_connect_done(struct tevent_req *subreq);
static void groups_get_mpg_done(struct tevent_req *subreq);
static void groups_get_search(struct tevent_req *req);
static void groups_get_done(struct tevent_req *subreq);

struct tevent_req *groups_get_send(TALLOC_CTX *memctx,
                                   struct tevent_context *ev,
                                   struct sdap_id_ctx *ctx,
                                   struct sdap_domain *sdom,
                                   struct sdap_id_conn_ctx *conn,
                                   const char *filter_value,
                                   int filter_type,
                                   bool noexist_delete,
                                   bool no_members,
                                   bool set_non_posix)
{
    struct tevent_req *req;
    struct groups_get_state *state;
    const char *attr_name = NULL;
    char *shortname = NULL;
    char *clean_value;
    char *endptr;
    int ret;
    gid_t gid;
    enum idmap_error_code err;
    char *sid;
    const char *member_filter[2];
    char *oc_list;

    req = tevent_req_create(memctx, &state, struct groups_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->sdom = sdom;
    state->conn = conn;
    state->dp_error = DP_ERR_FATAL;
    state->noexist_delete = noexist_delete;
    state->no_members = no_members;

    state->op = sdap_id_op_create(state, state->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto done;
    }

    state->domain = sdom->dom;
    state->sysdb = sdom->dom->sysdb;
    state->filter_value = filter_value;
    state->filter_type = filter_type;

    if (state->domain->type == DOM_TYPE_APPLICATION || set_non_posix) {
        state->non_posix = true;
    }

    state->use_id_mapping = sdap_idmap_domain_has_algorithmic_mapping(
                                                          ctx->opts->idmap_ctx,
                                                          sdom->dom->name,
                                                          sdom->dom->domain_id);

    switch(filter_type) {
    case BE_FILTER_WILDCARD:
        attr_name = ctx->opts->group_map[SDAP_AT_GROUP_NAME].name;
        ret = sss_filter_sanitize_ex(state, filter_value, &clean_value,
                                     LDAP_ALLOWED_WILDCARDS);
        if (ret != EOK) {
            goto done;
        }
        break;
    case BE_FILTER_NAME:
        attr_name = ctx->opts->group_map[SDAP_AT_GROUP_NAME].name;

        ret = sss_parse_internal_fqname(state, filter_value,
                                        &shortname, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot parse %s\n", filter_value);
            goto done;
        }

        ret = sss_filter_sanitize(state, shortname, &clean_value);
        if (ret != EOK) {
            goto done;
        }
        break;
    case BE_FILTER_IDNUM:
        if (state->use_id_mapping) {
            /* If we're ID-mapping, we need to use the objectSID
             * in the search filter.
             */
            gid = strtouint32(filter_value, &endptr, 10);
            if ((errno != EOK) || *endptr || (filter_value == endptr)) {
                ret = EINVAL;
                goto done;
            }

            /* Convert the GID to its objectSID */
            err = sss_idmap_unix_to_sid(ctx->opts->idmap_ctx->map,
                                        gid, &sid);
            if (err == IDMAP_NO_DOMAIN) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "[%s] did not match any configured ID mapping domain\n",
                       filter_value);

                ret = sysdb_delete_group(state->domain, NULL, gid);
                if (ret == ENOENT) {
                    /* Ignore errors to remove users that were not cached previously */
                    ret = EOK;
                }

                goto done;
            } else if (err != IDMAP_SUCCESS) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Mapping ID [%s] to SID failed: [%s]\n",
                       filter_value, idmap_error_string(err));
                ret = EIO;
                goto done;
            }

            attr_name = ctx->opts->group_map[SDAP_AT_GROUP_OBJECTSID].name;
            ret = sss_filter_sanitize(state, sid, &clean_value);
            sss_idmap_free_sid(ctx->opts->idmap_ctx->map, sid);
            if (ret != EOK) {
                goto done;
            }

        } else {
            attr_name = ctx->opts->group_map[SDAP_AT_GROUP_GID].name;
            ret = sss_filter_sanitize(state, filter_value, &clean_value);
            if (ret != EOK) {
                goto done;
            }
        }
        break;
    case BE_FILTER_SECID:
        attr_name = ctx->opts->group_map[SDAP_AT_GROUP_OBJECTSID].name;

        ret = sss_filter_sanitize(state, filter_value, &clean_value);
        if (ret != EOK) {
            goto done;
        }
        break;
    case BE_FILTER_UUID:
        attr_name = ctx->opts->group_map[SDAP_AT_GROUP_UUID].name;
        if (attr_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "UUID search not configured for this backend.\n");
            ret = EINVAL;
            goto done;
        }

        ret = sss_filter_sanitize(state, filter_value, &clean_value);
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

    oc_list = sdap_make_oc_list(state, ctx->opts->group_map);
    if (oc_list == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create objectClass list.\n");
        ret = ENOMEM;
        goto done;
    }

    if (state->non_posix
            || state->use_id_mapping
            || filter_type == BE_FILTER_SECID) {
        /* When mapping IDs or looking for SIDs, or when in a non-POSIX domain,
         * we don't want to limit ourselves to groups with a GID value
         */

        state->filter = talloc_asprintf(state,
                                        "(&(%s=%s)(%s)(%s=*))",
                                        attr_name, clean_value, oc_list,
                                        ctx->opts->group_map[SDAP_AT_GROUP_NAME].name);
    } else {
        state->filter = talloc_asprintf(state,
                                        "(&(%s=%s)(%s)(%s=*)(&(%s=*)(!(%s=0))))",
                                        attr_name, clean_value, oc_list,
                                        ctx->opts->group_map[SDAP_AT_GROUP_NAME].name,
                                        ctx->opts->group_map[SDAP_AT_GROUP_GID].name,
                                        ctx->opts->group_map[SDAP_AT_GROUP_GID].name);
    }

    talloc_zfree(clean_value);
    if (!state->filter) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto done;
    }

    member_filter[0] = (const char *)ctx->opts->group_map[SDAP_AT_GROUP_MEMBER].name;
    member_filter[1] = NULL;

    ret = build_attrs_from_map(state, ctx->opts->group_map, SDAP_OPTS_GROUP,
                               (state->domain->ignore_group_members
                                    || state->no_members) ?
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

    groups_get_search(req);
}

static void groups_get_search(struct tevent_req *req)
{
    struct groups_get_state *state = tevent_req_data(req,
                                                     struct groups_get_state);
    struct tevent_req *subreq;
    enum sdap_entry_lookup_type lookup_type;

    if (state->filter_type == BE_FILTER_WILDCARD) {
        lookup_type = SDAP_LOOKUP_WILDCARD;
    } else {
        lookup_type = SDAP_LOOKUP_SINGLE;
    }

    subreq = sdap_get_groups_send(state, state->ev,
                                  state->sdom,
                                  state->ctx->opts,
                                  sdap_id_op_handle(state->op),
                                  state->attrs, state->filter,
                                  dp_opt_get_int(state->ctx->opts->basic,
                                                 SDAP_SEARCH_TIMEOUT),
                                  lookup_type,
                                  state->no_members);
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

    if (ret == ENOENT
            && sss_domain_is_mpg(state->domain) == true
            && !state->conn->no_mpg_user_fallback) {
        /* The requested filter did not find a group. Before giving up, we must
         * also check if the GID can be resolved through a primary group of a
         * user
         */
        subreq = users_get_send(state,
                                state->ev,
                                state->ctx,
                                state->sdom,
                                state->conn,
                                state->filter_value,
                                state->filter_type,
                                NULL,
                                state->noexist_delete,
                                false);
        if (subreq == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, groups_get_mpg_done, req);
        return;
    } else if (ret == ENOENT && state->noexist_delete == true) {
        ret = groups_get_handle_no_group(state, state->domain,
                                         state->filter_type,
                                         state->filter_value);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Could not delete group [%d]: %s\n", ret, sss_strerror(ret));
            tevent_req_error(req, ret);
            return;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
}

static void groups_get_mpg_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct groups_get_state *state = tevent_req_data(req,
                                                     struct groups_get_state);

    ret = users_get_recv(subreq, &state->dp_error, &state->sdap_ret);
    talloc_zfree(subreq);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->sdap_ret == ENOENT && state->noexist_delete == true) {
        ret = groups_get_handle_no_group(state, state->domain,
                                         state->filter_type,
                                         state->filter_value);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Could not delete group [%d]: %s\n", ret, sss_strerror(ret));
            tevent_req_error(req, ret);
            return;
        }
    }

    /* GID resolved to a user private group, done */
    tevent_req_done(req);
    return;
}

errno_t groups_get_handle_no_group(TALLOC_CTX *mem_ctx,
                                   struct sss_domain_info *domain,
                                   int filter_type, const char *filter_value)
{
    errno_t ret;
    char *endptr;
    gid_t gid;

    switch (filter_type) {
    case BE_FILTER_ENUM:
        ret = ENOENT;
        break;
    case BE_FILTER_NAME:
        ret = sysdb_delete_group(domain, filter_value, 0);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot delete group %s [%d]: %s\n",
                  filter_value, ret, sss_strerror(ret));
            return ret;
        }
        ret = EOK;
        break;
    case BE_FILTER_IDNUM:
        gid = (gid_t) strtouint32(filter_value, &endptr, 10);
        if (errno || *endptr || (filter_value == endptr)) {
            ret = errno ? errno : EINVAL;
            break;
        }

        ret = sysdb_delete_group(domain, NULL, gid);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot delete group %"SPRIgid" [%d]: %s\n",
                  gid, ret, sss_strerror(ret));
            return ret;
        }
        ret = EOK;
        break;
    case BE_FILTER_SECID:
    case BE_FILTER_UUID:
        /* Since it is not clear if the SID/UUID belongs to a user or a
         * group we have nothing to do here. */
        ret = EOK;
        break;
    case BE_FILTER_WILDCARD:
        /* We can't know if all groups are up-to-date, especially in
         * a large environment. Do not delete any records, let the
         * responder fetch the entries they are requested in.
         */
        ret = EOK;
        break;
    default:
        ret = EINVAL;
        break;
    }

    return ret;
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

    const char *filter_value;
    int filter_type;
    const char *extra_value;
    const char **attrs;
    bool non_posix;

    int dp_error;
    int sdap_ret;
    bool noexist_delete;
};

static int groups_by_user_retry(struct tevent_req *req);
static void groups_by_user_connect_done(struct tevent_req *subreq);
static void groups_by_user_done(struct tevent_req *subreq);

struct tevent_req *groups_by_user_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sdap_id_ctx *ctx,
                                       struct sdap_domain *sdom,
                                       struct sdap_id_conn_ctx *conn,
                                       const char *filter_value,
                                       int filter_type,
                                       const char *extra_value,
                                       bool noexist_delete,
                                       bool set_non_posix)
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

    state->filter_value = filter_value;
    state->filter_type = filter_type;
    state->extra_value = extra_value;
    state->domain = sdom->dom;
    state->sysdb = sdom->dom->sysdb;

    if (state->domain->type == DOM_TYPE_APPLICATION || set_non_posix) {
        state->non_posix = true;
    }

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
                                  state->filter_value,
                                  state->filter_type,
                                  state->extra_value,
                                  state->attrs,
                                  state->non_posix);
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

    switch (state->sdap_ret) {
    case ENOENT:
        if (state->noexist_delete == true) {
            const char *cname;

            /* state->filter_value is still the name used for the original
             * req. The cached object might have a different name, e.g. a
             * fully-qualified name. */
            ret = sysdb_get_real_name(state,
                                      state->domain,
                                      state->filter_value,
                                      &cname);
            if (ret != EOK) {
                cname = state->filter_value;
                DEBUG(SSSDBG_TRACE_INTERNAL,
                      "Failed to canonicalize name, using [%s] [%d]: %s.\n",
                      cname, ret, sss_strerror(ret));
            }

            ret = sysdb_delete_user(state->domain, cname, 0);
            if (ret != EOK && ret != ENOENT) {
                tevent_req_error(req, ret);
                return;
            }
        }
        break;
    case EOK:
        break;
    default:
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
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

/* =Get-Account-Info-Call================================================= */

/* FIXME: embed this function in sssd_be and only call out
 * specific functions from modules? */

static struct tevent_req *get_user_and_group_send(TALLOC_CTX *memctx,
                                                  struct tevent_context *ev,
                                                  struct sdap_id_ctx *ctx,
                                                  struct sdap_domain *sdom,
                                                  struct sdap_id_conn_ctx *conn,
                                                  const char *filter_value,
                                                  int filter_type,
                                                  bool noexist_delete);

errno_t sdap_get_user_and_group_recv(struct tevent_req *req,
                                     int *dp_error_out, int *sdap_ret);

bool sdap_is_enum_request(struct dp_id_data *ar)
{
    switch (ar->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER:
    case BE_REQ_GROUP:
    case BE_REQ_SERVICES:
        if (ar->filter_type == BE_FILTER_ENUM) {
            return true;
        }
    }

    return false;
}

/* A generic LDAP account info handler */
struct sdap_handle_acct_req_state {
    struct dp_id_data *ar;
    const char *err;
    int dp_error;
    int sdap_ret;
};

static void sdap_handle_acct_req_done(struct tevent_req *subreq);

struct tevent_req *
sdap_handle_acct_req_send(TALLOC_CTX *mem_ctx,
                          struct be_ctx *be_ctx,
                          struct dp_id_data *ar,
                          struct sdap_id_ctx *id_ctx,
                          struct sdap_domain *sdom,
                          struct sdap_id_conn_ctx *conn,
                          bool noexist_delete)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_handle_acct_req_state *state;
    errno_t ret;


    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_handle_acct_req_state);
    if (!req) {
        return NULL;
    }
    state->ar = ar;

    if (ar == NULL) {
        ret = EINVAL;
        goto done;
    }

    PROBE(SDAP_ACCT_REQ_SEND,
          state->ar->entry_type & BE_REQ_TYPE_MASK,
          state->ar->filter_type, state->ar->filter_value,
          PROBE_SAFE_STR(state->ar->extra_value));

    switch (ar->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER: /* user */
        subreq = users_get_send(state, be_ctx->ev, id_ctx,
                                sdom, conn,
                                ar->filter_value,
                                ar->filter_type,
                                ar->extra_value,
                                noexist_delete,
                                false);
        break;

    case BE_REQ_GROUP: /* group */
        subreq = groups_get_send(state, be_ctx->ev, id_ctx,
                                 sdom, conn,
                                 ar->filter_value,
                                 ar->filter_type,
                                 noexist_delete, false, false);
        break;

    case BE_REQ_INITGROUPS: /* init groups for user */
        if (ar->filter_type != BE_FILTER_NAME
                && ar->filter_type != BE_FILTER_SECID
                && ar->filter_type != BE_FILTER_UUID) {
            ret = EINVAL;
            state->err = "Invalid filter type";
            goto done;
        }

        subreq = groups_by_user_send(state, be_ctx->ev, id_ctx,
                                     sdom, conn,
                                     ar->filter_value,
                                     ar->filter_type,
                                     ar->extra_value,
                                     noexist_delete, false);
        break;

    case BE_REQ_SUBID_RANGES:
#ifdef BUILD_SUBID
        if (!ar->extra_value) {
            ret = ERR_GET_ACCT_SUBID_RANGES_NOT_SUPPORTED;
            state->err = "This id_provider doesn't support subid ranges";
            goto done;
        }
        subreq = subid_ranges_get_send(state, be_ctx->ev, id_ctx,
                                       sdom, conn,
                                       ar->filter_value,
                                       ar->extra_value);
#else
        ret = ERR_GET_ACCT_SUBID_RANGES_NOT_SUPPORTED;
        state->err = "Subid ranges are not supported";
        goto done;
#endif
        break;

    case BE_REQ_NETGROUP:
        if (ar->filter_type != BE_FILTER_NAME) {
            ret = EINVAL;
            state->err = "Invalid filter type";
            goto done;
        }

        subreq = ldap_netgroup_get_send(state, be_ctx->ev, id_ctx,
                                        sdom, conn,
                                        ar->filter_value,
                                        noexist_delete);
        break;

    case BE_REQ_SERVICES:
        if (ar->filter_type == BE_FILTER_SECID
                || ar->filter_type == BE_FILTER_UUID) {
            ret = EINVAL;
            state->err = "Invalid filter type";
            goto done;
        }

        subreq = services_get_send(state, be_ctx->ev, id_ctx,
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

        subreq = get_user_and_group_send(state, be_ctx->ev, id_ctx,
                                         sdom, conn,
                                         ar->filter_value,
                                         ar->filter_type,
                                         noexist_delete);
        break;

    case BE_REQ_BY_UUID:
        if (ar->filter_type != BE_FILTER_UUID) {
            ret = EINVAL;
            state->err = "Invalid filter type";
            goto done;
        }

        subreq = get_user_and_group_send(state, be_ctx->ev, id_ctx,
                                         sdom, conn,
                                         ar->filter_value,
                                         ar->filter_type,
                                         noexist_delete);
        break;

    case BE_REQ_USER_AND_GROUP:
        if (!(ar->filter_type == BE_FILTER_NAME ||
              ar->filter_type == BE_FILTER_IDNUM)) {
            ret = EINVAL;
            state->err = "Invalid filter type";
            goto done;
        }

        subreq = get_user_and_group_send(state, be_ctx->ev, id_ctx,
                                         sdom, conn,
                                         ar->filter_value,
                                         ar->filter_type,
                                         noexist_delete);
        break;

    case BE_REQ_BY_CERT:
        subreq = users_get_send(state, be_ctx->ev, id_ctx,
                                sdom, conn,
                                ar->filter_value,
                                ar->filter_type,
                                ar->extra_value,
                                noexist_delete,
                                false);
        break;

    default: /*fail*/
        ret = EINVAL;
        state->err = "Invalid request type";
        DEBUG(SSSDBG_OP_FAILURE,
              "Unexpected request type: 0x%X [%s:%s] in %s\n",
              ar->entry_type, ar->filter_value,
              ar->extra_value?ar->extra_value:"-",
              ar->domain);
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
    case BE_REQ_SUBID_RANGES:
        err = "Subid ranges lookup failed";
#ifdef BUILD_SUBID
        ret = subid_ranges_get_recv(subreq, &state->dp_error, &state->sdap_ret);
#else
        ret = EINVAL;
#endif
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
        /* Fall through */
    case BE_REQ_BY_UUID:
        /* Fall through */
    case BE_REQ_USER_AND_GROUP:
        err = "Lookup by SID failed";
        ret = sdap_get_user_and_group_recv(subreq, &state->dp_error,
                                           &state->sdap_ret);
        break;
    case BE_REQ_BY_CERT:
        err = "User lookup by certificate failed";
        ret = users_get_recv(subreq, &state->dp_error, &state->sdap_ret);
        break;
    default: /* fail */
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

    PROBE(SDAP_ACCT_REQ_RECV,
          state->ar->entry_type & BE_REQ_TYPE_MASK,
          state->ar->filter_type, state->ar->filter_value,
          PROBE_SAFE_STR(state->ar->extra_value));

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

    subreq = groups_get_send(req, state->ev, state->id_ctx,
                             state->sdom, state->conn,
                             state->filter_val, state->filter_type,
                             state->noexist_delete, false, false);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "groups_get_send failed.\n");
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
    struct sdap_id_conn_ctx *user_conn;

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

    /* Prefer LDAP over GC for users */
    user_conn = get_ldap_conn_from_sdom_pvt(state->id_ctx->opts, state->sdom);
    if (user_conn == NULL) {
        user_conn = state->conn;
    }

    subreq = users_get_send(req, state->ev, state->id_ctx,
                            state->sdom, user_conn,
                            state->filter_val, state->filter_type, NULL,
                            state->noexist_delete, false);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "users_get_send failed.\n");
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
        if (state->noexist_delete == true) {
            /* The search ran to completion, but nothing was found.
             * Delete the existing entry, if any. */
            ret = sysdb_delete_by_sid(state->sysdb, state->domain,
                                      state->filter_val);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Could not delete entry by SID!\n");
                tevent_req_error(req, ret);
                return;
            }
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

struct sdap_account_info_handler_state {
    struct dp_reply_std reply;
};

static void sdap_account_info_handler_done(struct tevent_req *subreq);

struct tevent_req *
sdap_account_info_handler_send(TALLOC_CTX *mem_ctx,
                               struct sdap_id_ctx *id_ctx,
                               struct dp_id_data *data,
                               struct dp_req_params *params)
{
    struct sdap_account_info_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_account_info_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (sdap_is_enum_request(data)) {
        DEBUG(SSSDBG_TRACE_LIBS, "Skipping enumeration on demand\n");
        ret = EOK;
        goto immediately;
    }

    subreq = sdap_handle_acct_req_send(state, params->be_ctx, data, id_ctx,
                                       id_ctx->opts->sdom, id_ctx->conn, true);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_account_info_handler_done, req);

    return req;

immediately:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void sdap_account_info_handler_done(struct tevent_req *subreq)
{
    struct sdap_account_info_handler_state *state;
    struct tevent_req *req;
    const char *error_msg;
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_account_info_handler_state);

    ret = sdap_handle_acct_req_recv(subreq, &dp_error, &error_msg, NULL);
    talloc_zfree(subreq);

    /* TODO For backward compatibility we always return EOK to DP now. */
    dp_reply_std_set(&state->reply, dp_error, ret, error_msg);
    tevent_req_done(req);
}

errno_t sdap_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req,
                                       struct dp_reply_std *data)
{
    struct sdap_account_info_handler_state *state = NULL;

    state = tevent_req_data(req, struct sdap_account_info_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}
