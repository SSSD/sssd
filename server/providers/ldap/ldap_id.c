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
#include "providers/dp_backend.h"
#include "providers/ldap/sdap_async.h"

struct sdap_id_ctx {
    struct sdap_options *opts;

    /* global sdap handler */
    struct sdap_handle *gsh;

    time_t went_offline;
    bool offline;
};

static void sdap_req_done(struct be_req *req, int ret, const char *err)
{
    return req->fn(req, ret, err);
}

static bool is_offline(struct sdap_id_ctx *ctx)
{
    time_t now = time(NULL);

    if (ctx->went_offline + ctx->opts->offline_timeout < now) {
        return false;
    }
    return ctx->offline;
}

static void sdap_check_online(struct be_req *req)
{
    struct be_online_req *oreq;
    struct sdap_id_ctx *ctx;

    ctx = talloc_get_type(req->be_ctx->bet_info[BET_ID].pvt_bet_data, struct sdap_id_ctx);
    oreq = talloc_get_type(req->req_data, struct be_online_req);

    if (is_offline(ctx)) {
        oreq->online = MOD_OFFLINE;
    } else {
        oreq->online = MOD_ONLINE;
    }

    sdap_req_done(req, EOK, NULL);
}

static int build_attrs_from_map(TALLOC_CTX *memctx,
                                struct sdap_id_map *map,
                                size_t size,
                                const char ***_attrs)
{
    char **attrs;
    int i;

    attrs = talloc_array(memctx, char *, size + 1);
    if (!attrs) return ENOMEM;

    /* first attribute is the objectclass value not the attribute name */
    attrs[0] = talloc_strdup(memctx, "objectClass");
    if (!attrs[0]) return ENOMEM;

    /* add the others */
    for (i = 1; i < size; i++) {
        attrs[i] = map[i].name;
    }
    attrs[i] = NULL;

    *_attrs = (const char **)attrs;

    return EOK;
}


/* =Connection-handling-functions========================================= */

static bool connected(struct sdap_id_ctx *ctx)
{
    if (ctx->gsh) {
        return ctx->gsh->connected;
    }

    return false;
}

struct sdap_id_connect_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    bool use_start_tls;

    struct sdap_handle *sh;
};

static void sdap_id_connect_done(struct tevent_req *subreq);
static void sdap_id_anon_bind_done(struct tevent_req *subreq);

struct tevent_req *sdap_id_connect_send(TALLOC_CTX *memctx,
                                        struct tevent_context *ev,
                                        struct sdap_options *opts,
                                        bool use_start_tls)
{
    struct tevent_req *req, *subreq;
    struct sdap_id_connect_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_id_connect_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->use_start_tls = use_start_tls;

    subreq = sdap_connect_send(state, ev, opts, use_start_tls);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_id_connect_done, req);

    return req;
}

static void sdap_id_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_id_connect_state *state = tevent_req_data(req,
                                                struct sdap_id_connect_state);
    int ret;

    ret = sdap_connect_recv(subreq, state, &state->sh);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    /* TODO: use authentication (SASL/GSSAPI) when necessary */
    subreq = sdap_auth_send(state, state->ev, state->sh, NULL, NULL);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, sdap_id_anon_bind_done, req);
}

static void sdap_id_anon_bind_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    enum sdap_result result;
    int ret;

    ret = sdap_auth_recv(subreq, &result);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    if (result != SDAP_AUTH_SUCCESS) {
        tevent_req_error(req, EACCES);
        return;
    }

    tevent_req_done(req);
}

static int sdap_id_connect_recv(struct tevent_req *req,
                                TALLOC_CTX *memctx, struct sdap_handle **sh)
{
    struct sdap_id_connect_state *state = tevent_req_data(req,
                                                struct sdap_id_connect_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        if (err) return err;
        return EIO;
    }

    *sh = talloc_steal(memctx, state->sh);
    if (!*sh) {
        return ENOMEM;
    }
    return EOK;
}


/* =Users-Related-Functions-(by-name,by-uid)============================== */

struct users_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;

    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;

    char *filter;
    const char **attrs;
};

static void users_get_connect_done(struct tevent_req *subreq);
static void users_get_op_done(struct tevent_req *subreq);

static struct tevent_req *users_get_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_id_ctx *ctx,
                                         struct be_ctx *bectx,
                                         const char *wildcard,
                                         int filter_type,
                                         int attrs_type)
{
    struct tevent_req *req, *subreq;
    struct users_get_state *state;
    const char *attr_name;
    int ret;

    req = tevent_req_create(memctx, &state, struct users_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->dom = bectx->domain;
    state->sysdb = bectx->sysdb;

    switch(filter_type) {
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
                                    attr_name, wildcard,
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

    if (!connected(ctx)) {

        if (ctx->gsh) talloc_zfree(ctx->gsh);

        /* FIXME: add option to decide if tls should be used
         * or SASL/GSSAPI, etc ... */
        subreq = sdap_id_connect_send(state, ev, ctx->opts, false);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, users_get_connect_done, req);

        return req;
    }

    subreq = sdap_get_users_send(state, state->ev,
                                 state->dom, bectx->sysdb,
                                 state->ctx->opts, state->ctx->gsh,
                                 state->attrs, state->filter);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, users_get_op_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void users_get_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct users_get_state *state = tevent_req_data(req,
                                                     struct users_get_state);
    int ret;

    ret = sdap_id_connect_recv(subreq, state->ctx, &state->ctx->gsh);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_users_send(state, state->ev,
                                 state->dom, state->sysdb,
                                 state->ctx->opts, state->ctx->gsh,
                                 state->attrs, state->filter);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, users_get_op_done, req);
}

static void users_get_op_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sdap_get_users_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void users_get_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    enum tevent_req_state tstate;
    uint64_t err;
    const char *error = NULL;
    int ret = EOK;

    if (tevent_req_is_error(req, &tstate, &err)) {
        ret = err;
    }

    if (ret) error = "Enum Users Failed";

    return sdap_req_done(breq, ret, error);
}

/* =Groups-Related-Functions-(by-name,by-uid)============================= */

struct groups_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;

    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;

    char *filter;
    const char **attrs;
};

static void groups_get_connect_done(struct tevent_req *subreq);
static void groups_get_op_done(struct tevent_req *subreq);

static struct tevent_req *groups_get_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          struct be_ctx *bectx,
                                          const char *wildcard,
                                          int filter_type,
                                          int attrs_type)
{
    struct tevent_req *req, *subreq;
    struct groups_get_state *state;
    const char *attr_name;
    int ret;

    req = tevent_req_create(memctx, &state, struct groups_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->dom = bectx->domain;
    state->sysdb = bectx->sysdb;

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
                                    attr_name, wildcard,
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

    if (!connected(ctx)) {

        if (ctx->gsh) talloc_zfree(ctx->gsh);

        /* FIXME: add option to decide if tls should be used
         * or SASL/GSSAPI, etc ... */
        subreq = sdap_id_connect_send(state, ev, ctx->opts, false);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, groups_get_connect_done, req);

        return req;
    }

    subreq = sdap_get_groups_send(state, state->ev,
                                 state->dom, bectx->sysdb,
                                 state->ctx->opts, state->ctx->gsh,
                                 state->attrs, state->filter);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, groups_get_op_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void groups_get_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct users_get_state *state = tevent_req_data(req,
                                                     struct users_get_state);
    int ret;

    ret = sdap_id_connect_recv(subreq, state->ctx, &state->ctx->gsh);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_groups_send(state, state->ev,
                                 state->dom, state->sysdb,
                                 state->ctx->opts, state->ctx->gsh,
                                 state->attrs, state->filter);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, groups_get_op_done, req);
}

static void groups_get_op_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sdap_get_groups_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void groups_get_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    enum tevent_req_state tstate;
    uint64_t err;
    const char *error = NULL;
    int ret = EOK;

    if (tevent_req_is_error(req, &tstate, &err)) {
        ret = err;
    }

    if (ret) error = "Enum Groups Failed";

    return sdap_req_done(breq, ret, error);
}

/* =Get-Groups-for-User================================================== */

struct groups_by_user_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    const char *name;
    const char **attrs;
};

static void groups_by_user_connect_done(struct tevent_req *subreq);
static void groups_by_user_op_done(struct tevent_req *subreq);

static struct tevent_req *groups_by_user_send(TALLOC_CTX *memctx,
                                              struct tevent_context *ev,
                                              struct sdap_id_ctx *ctx,
                                              struct sss_domain_info *dom,
                                              struct sysdb_ctx *sysdb,
                                              const char *name)
{
    struct tevent_req *req, *subreq;
    struct groups_by_user_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct groups_by_user_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->dom = dom;
    state->sysdb = sysdb;
    state->name = name;

    ret = build_attrs_from_map(state, ctx->opts->group_map,
                               SDAP_OPTS_GROUP, &state->attrs);
    if (ret != EOK) goto fail;

    if (!connected(ctx)) {

        if (ctx->gsh) talloc_zfree(ctx->gsh);

        /* FIXME: add option to decide if tls should be used
         * or SASL/GSSAPI, etc ... */
        subreq = sdap_id_connect_send(state, ev, ctx->opts, false);
        if (!subreq) {
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_set_callback(subreq, groups_by_user_connect_done, req);

        return req;
    }

    subreq = sdap_get_initgr_send(state, state->ev,
                                  state->dom, state->sysdb,
                                  state->ctx->opts, state->ctx->gsh,
                                  state->name, state->attrs);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, groups_by_user_op_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void groups_by_user_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct groups_by_user_state *state = tevent_req_data(req,
                                                     struct groups_by_user_state);
    int ret;

    ret = sdap_id_connect_recv(subreq, state->ctx, &state->ctx->gsh);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_initgr_send(state, state->ev,
                                  state->dom, state->sysdb,
                                  state->ctx->opts, state->ctx->gsh,
                                  state->name, state->attrs);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, groups_by_user_op_done, req);
}

static void groups_by_user_op_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sdap_get_initgr_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void groups_by_user_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    enum tevent_req_state tstate;
    uint64_t err;
    const char *error = NULL;
    int ret = EOK;

    if (tevent_req_is_error(req, &tstate, &err)) {
        ret = err;
    }

    if (ret) error = "Init Groups Failed";

    return sdap_req_done(breq, ret, error);
}



/* =Get-Account-Info-Call================================================= */

/* FIXME: embed this function in sssd_be and only call out
 * specific functions from modules */
static void sdap_get_account_info(struct be_req *breq)
{
    struct sdap_id_ctx *ctx;
    struct be_acct_req *ar;
    struct tevent_req *req;
    const char *err = "Unknown Error";
    int ret = EOK;

    ctx = talloc_get_type(breq->be_ctx->bet_info[BET_ID].pvt_bet_data, struct sdap_id_ctx);

    if (is_offline(ctx)) {
        return sdap_req_done(breq, EAGAIN, "Offline");
    }

    ar = talloc_get_type(breq->req_data, struct be_acct_req);

    switch (ar->entry_type) {
    case BE_REQ_USER: /* user */

        req = users_get_send(breq, breq->be_ctx->ev,
                             ctx, breq->be_ctx,
                             ar->filter_value,
                             ar->filter_type,
                             ar->attr_type);
        if (!req) {
            return sdap_req_done(breq, ENOMEM, "Out of memory");
        }

        tevent_req_set_callback(req, users_get_done, breq);

        break;

    case BE_REQ_GROUP: /* group */

        req = groups_get_send(breq, breq->be_ctx->ev,
                              ctx, breq->be_ctx,
                              ar->filter_value,
                              ar->filter_type,
                              ar->attr_type);
        if (!req) {
            return sdap_req_done(breq, ENOMEM, "Out of memory");
        }

        tevent_req_set_callback(req, groups_get_done, breq);

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
                                  breq->be_ctx->domain, breq->be_ctx->sysdb,
                                  ar->filter_value);
        if (!req) ret = ENOMEM;
        /* tevent_req_set_callback(req, groups_by_user_done, breq); */

        tevent_req_set_callback(req, groups_by_user_done, breq);

        break;

    default: /*fail*/
        ret = EINVAL;
        err = "Invalid request type";
    }

    if (ret != EOK) return sdap_req_done(breq, ret, err);
}

static void sdap_shutdown(struct be_req *req)
{
    /* TODO: Clean up any internal data */
    sdap_req_done(req, EOK, NULL);
}

struct bet_ops sdap_id_ops = {
    .check_online = sdap_check_online,
    .handler = sdap_get_account_info,
    .finalize = sdap_shutdown
};

int sssm_ldap_init(struct be_ctx *bectx,
                   struct bet_ops **ops,
                   void **pvt_data)
{
    int ldap_opt_x_tls_require_cert;
    struct sdap_id_ctx *ctx;
    char *tls_reqcert;
    int ret;

    ctx = talloc_zero(bectx, struct sdap_id_ctx);
    if (!ctx) return ENOMEM;

    ret = sdap_get_options(ctx, bectx->cdb, bectx->conf_path,
                           &ctx->opts);

    tls_reqcert = ctx->opts->basic[SDAP_TLS_REQCERT].value;
    if (tls_reqcert) {
        if (strcasecmp(tls_reqcert, "never") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_NEVER;
        }
        else if (strcasecmp(tls_reqcert, "allow") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_ALLOW;
        }
        else if (strcasecmp(tls_reqcert, "try") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_TRY;
        }
        else if (strcasecmp(tls_reqcert, "demand") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_DEMAND;
        }
        else if (strcasecmp(tls_reqcert, "hard") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_HARD;
        }
        else {
            DEBUG(1, ("Unknown value for tls_reqcert.\n"));
            ret = EINVAL;
            goto done;
        }
        /* LDAP_OPT_X_TLS_REQUIRE_CERT has to be set as a global option,
         * because the SSL/TLS context is initialized from this value. */
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
                              &ldap_opt_x_tls_require_cert);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_set_option failed: %s\n", ldap_err2string(ret)));
            ret = EIO;
            goto done;
        }
    }

    *ops = &sdap_id_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}
