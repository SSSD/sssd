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
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"

/* =Users-Related-Functions-(by-name,by-uid)============================== */

struct users_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *name;
    int filter_type;

    char *filter;
    const char **attrs;

    int dp_error;
};

static int users_get_retry(struct tevent_req *req);
static void users_get_connect_done(struct tevent_req *subreq);
static void users_get_done(struct tevent_req *subreq);

struct tevent_req *users_get_send(TALLOC_CTX *memctx,
                                  struct tevent_context *ev,
                                  struct sdap_id_ctx *ctx,
                                  const char *name,
                                  int filter_type,
                                  int attrs_type)
{
    struct tevent_req *req;
    struct users_get_state *state;
    const char *attr_name;
    int ret;

    req = tevent_req_create(memctx, &state, struct users_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->dp_error = DP_ERR_FATAL;

    state->op = sdap_id_op_create(state, state->ctx->conn_cache);
    if (!state->op) {
        DEBUG(2, ("sdap_id_op_create failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    state->sysdb = ctx->be->sysdb;
    state->domain = state->ctx->be->domain;
    state->name = name;
    state->filter_type = filter_type;

    switch (filter_type) {
    case BE_FILTER_NAME:
        attr_name = ctx->opts->user_map[SDAP_AT_USER_NAME].name;
        break;
    case BE_FILTER_IDNUM:
        attr_name = ctx->opts->user_map[SDAP_AT_USER_UID].name;
        break;
    default:
        ret = EINVAL;
        goto fail;
    }

    state->filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                                    attr_name, name,
                                    ctx->opts->user_map[SDAP_OC_USER].name);
    if (!state->filter) {
        DEBUG(2, ("Failed to build filter\n"));
        ret = ENOMEM;
        goto fail;
    }

    /* TODO: handle attrs_type */
    ret = build_attrs_from_map(state, ctx->opts->user_map,
                               SDAP_OPTS_USER, &state->attrs);
    if (ret != EOK) goto fail;

    ret = users_get_retry(req);
    if (ret != EOK) {
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
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

    subreq = sdap_get_users_send(state, state->ev,
                                 state->domain, state->sysdb,
                                 state->ctx->opts,
                                 sdap_id_op_handle(state->op),
                                 state->attrs, state->filter);
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

    if (ret && ret != ENOENT) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    if (ret == ENOENT) {
        if (strchr(state->name, '*')) {
            /* it was an enumeration */
            tevent_req_error(req, ret);
            return;
        }

        switch (state->filter_type) {
        case BE_FILTER_NAME:
            ret = sysdb_delete_user(state, state->sysdb,
                                    state->domain, state->name, 0);
            if (ret) {
                tevent_req_error(req, ret);
                return;
            }
            break;

        case BE_FILTER_IDNUM:
            errno = 0;
            uid = (uid_t)strtol(state->name, &endptr, 0);
            if (errno || *endptr || (state->name == endptr)) {
                tevent_req_error(req, errno);
                return;
            }

            ret = sysdb_delete_user(state, state->sysdb,
                                    state->domain, NULL, uid);
            if (ret) {
                tevent_req_error(req, ret);
                return;
            }
            break;

        default:
            tevent_req_error(req, EINVAL);
            return;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
}

int users_get_recv(struct tevent_req *req, int *dp_error_out)
{
    struct users_get_state *state = tevent_req_data(req,
                                                    struct users_get_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* =Groups-Related-Functions-(by-name,by-uid)============================= */

struct groups_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *name;
    int filter_type;

    char *filter;
    const char **attrs;

    int dp_error;
};

static int groups_get_retry(struct tevent_req *req);
static void groups_get_connect_done(struct tevent_req *subreq);
static void groups_get_done(struct tevent_req *subreq);

struct tevent_req *groups_get_send(TALLOC_CTX *memctx,
                                   struct tevent_context *ev,
                                   struct sdap_id_ctx *ctx,
                                   const char *name,
                                   int filter_type,
                                   int attrs_type)
{
    struct tevent_req *req;
    struct groups_get_state *state;
    const char *attr_name;
    int ret;

    req = tevent_req_create(memctx, &state, struct groups_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->dp_error = DP_ERR_FATAL;

    state->op = sdap_id_op_create(state, state->ctx->conn_cache);
    if (!state->op) {
        DEBUG(2, ("sdap_id_op_create failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    state->sysdb = ctx->be->sysdb;
    state->domain = state->ctx->be->domain;
    state->name = name;
    state->filter_type = filter_type;

    switch(filter_type) {
    case BE_FILTER_NAME:
        attr_name = ctx->opts->group_map[SDAP_AT_GROUP_NAME].name;
        break;
    case BE_FILTER_IDNUM:
        attr_name = ctx->opts->group_map[SDAP_AT_GROUP_GID].name;
        break;
    default:
        ret = EINVAL;
        goto fail;
    }

    state->filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                                    attr_name, name,
                                    ctx->opts->group_map[SDAP_OC_GROUP].name);
    if (!state->filter) {
        DEBUG(2, ("Failed to build filter\n"));
        ret = ENOMEM;
        goto fail;
    }

    /* TODO: handle attrs_type */
    ret = build_attrs_from_map(state, ctx->opts->group_map,
                               SDAP_OPTS_GROUP, &state->attrs);
    if (ret != EOK) goto fail;

    ret = groups_get_retry(req);
    if (ret != EOK) {
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
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

    subreq = sdap_get_groups_send(state, state->ev,
                                  state->domain, state->sysdb,
                                  state->ctx->opts, sdap_id_op_handle(state->op),
                                  state->attrs, state->filter);
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

    if (ret && ret != ENOENT) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    if (ret == ENOENT) {
        if (strchr(state->name, '*')) {
            /* it was an enumeration */
            tevent_req_error(req, ret);
            return;
        }

        switch (state->filter_type) {
        case BE_FILTER_NAME:
            ret = sysdb_delete_group(state, state->sysdb,
                                     state->domain, state->name, 0);
            if (ret) {
                tevent_req_error(req, ret);
                return;
            }
            break;

        case BE_FILTER_IDNUM:
            errno = 0;
            gid = (gid_t)strtol(state->name, &endptr, 0);
            if (errno || *endptr || (state->name == endptr)) {
                tevent_req_error(req, errno);
                return;
            }

            ret = sysdb_delete_group(state, state->sysdb,
                                     state->domain, NULL, gid);
            if (ret) {
                tevent_req_error(req, ret);
                return;
            }
            break;

        default:
            tevent_req_error(req, EINVAL);
            return;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
}

int groups_get_recv(struct tevent_req *req, int *dp_error_out)
{
    struct groups_get_state *state = tevent_req_data(req,
                                                     struct groups_get_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}


/* =Get-Groups-for-User================================================== */

struct groups_by_user_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_id_op *op;
    const char *name;
    const char **attrs;

    int dp_error;
};

static int groups_by_user_retry(struct tevent_req *req);
static void groups_by_user_connect_done(struct tevent_req *subreq);
static void groups_by_user_done(struct tevent_req *subreq);

static struct tevent_req *groups_by_user_send(TALLOC_CTX *memctx,
                                              struct tevent_context *ev,
                                              struct sdap_id_ctx *ctx,
                                              const char *name)
{
    struct tevent_req *req;
    struct groups_by_user_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct groups_by_user_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->dp_error = DP_ERR_FATAL;

    state->op = sdap_id_op_create(state, state->ctx->conn_cache);
    if (!state->op) {
        DEBUG(2, ("sdap_id_op_create failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    state->name = name;

    ret = build_attrs_from_map(state, ctx->opts->group_map,
                               SDAP_OPTS_GROUP, &state->attrs);
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

    subreq = sdap_get_initgr_send(state, state->ev,
                                  state->ctx->be->domain,
                                  state->ctx->be->sysdb,
                                  state->ctx->opts, sdap_id_op_handle(state->op),
                                  state->name, state->attrs);
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

    if (ret && ret != ENOENT) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int groups_by_user_recv(struct tevent_req *req, int *dp_error_out)
{
    struct groups_by_user_state *state = tevent_req_data(req,
                                                             struct groups_by_user_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}



/* =Get-Account-Info-Call================================================= */

/* FIXME: embed this function in sssd_be and only call out
 * specific functions from modules ? */

static void sdap_account_info_users_done(struct tevent_req *req);
static void sdap_account_info_groups_done(struct tevent_req *req);
static void sdap_account_info_initgr_done(struct tevent_req *req);

void sdap_account_info_handler(struct be_req *breq)
{
    struct sdap_id_ctx *ctx;
    struct be_acct_req *ar;
    struct tevent_req *req;
    const char *err = "Unknown Error";
    int ret = EOK;

    ctx = talloc_get_type(breq->be_ctx->bet_info[BET_ID].pvt_bet_data, struct sdap_id_ctx);

    if (be_is_offline(ctx->be)) {
        return sdap_handler_done(breq, DP_ERR_OFFLINE, EAGAIN, "Offline");
    }

    ar = talloc_get_type(breq->req_data, struct be_acct_req);

    switch (ar->entry_type & 0xFFF) {
    case BE_REQ_USER: /* user */

        /* skip enumerations on demand */
        if (strcmp(ar->filter_value, "*") == 0) {
            return sdap_handler_done(breq, DP_ERR_OK, EOK, "Success");
        }

        req = users_get_send(breq, breq->be_ctx->ev, ctx,
                             ar->filter_value,
                             ar->filter_type,
                             ar->attr_type);
        if (!req) {
            return sdap_handler_done(breq, DP_ERR_FATAL, ENOMEM, "Out of memory");
        }

        tevent_req_set_callback(req, sdap_account_info_users_done, breq);

        break;

    case BE_REQ_GROUP: /* group */

        if (strcmp(ar->filter_value, "*") == 0) {
            return sdap_handler_done(breq, DP_ERR_OK, EOK, "Success");
        }

        /* skip enumerations on demand */
        req = groups_get_send(breq, breq->be_ctx->ev, ctx,
                              ar->filter_value,
                              ar->filter_type,
                              ar->attr_type);
        if (!req) {
            return sdap_handler_done(breq, DP_ERR_FATAL, ENOMEM, "Out of memory");
        }

        tevent_req_set_callback(req, sdap_account_info_groups_done, breq);

        break;

    case BE_REQ_INITGROUPS: /* init groups for user */
        if (ar->filter_type != BE_FILTER_NAME) {
            ret = EINVAL;
            err = "Invalid filter type";
            break;
        }
        if (ar->attr_type != BE_ATTR_CORE) {
            ret = EINVAL;
            err = "Invalid attr type";
            break;
        }
        if (strchr(ar->filter_value, '*')) {
            ret = EINVAL;
            err = "Invalid filter value";
            break;
        }
        req = groups_by_user_send(breq, breq->be_ctx->ev, ctx,
                                  ar->filter_value);
        if (!req) ret = ENOMEM;
        /* tevent_req_set_callback(req, groups_by_user_done, breq); */

        tevent_req_set_callback(req, sdap_account_info_initgr_done, breq);

        break;

    default: /*fail*/
        ret = EINVAL;
        err = "Invalid request type";
    }

    if (ret != EOK) return sdap_handler_done(breq, DP_ERR_FATAL, ret, err);
}

static void sdap_account_info_complete(struct be_req *breq, int dp_error,
                                       int ret, const char *default_error_text)
{
    const char* error_text;

    if (dp_error == DP_ERR_OK) {
        if (ret == EOK) {
            error_text = NULL;
        } else {
            DEBUG(1, ("Bug: dp_error is OK on failed request"));
            dp_error = DP_ERR_FATAL;
            error_text = default_error_text;
        }
    } else if (dp_error == DP_ERR_OFFLINE) {
        error_text = "Offline";
    } else if (dp_error == DP_ERR_FATAL && ret == ENOMEM) {
        error_text = "Out of memory";
    } else {
        error_text = default_error_text;
    }

    sdap_handler_done(breq, dp_error, ret, error_text);
}

static void sdap_account_info_users_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    int ret, dp_error;

    ret = users_get_recv(req, &dp_error);
    talloc_zfree(req);

    sdap_account_info_complete(breq, dp_error, ret, "User lookup failed");
}

static void sdap_account_info_groups_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    int ret, dp_error;

    ret = groups_get_recv(req, &dp_error);
    talloc_zfree(req);

    sdap_account_info_complete(breq, dp_error, ret, "Group lookup failed");
}

static void sdap_account_info_initgr_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    int ret, dp_error;

    ret = groups_by_user_recv(req, &dp_error);
    talloc_zfree(req);

    sdap_account_info_complete(breq, dp_error, ret, "Init Groups Failed");
}

