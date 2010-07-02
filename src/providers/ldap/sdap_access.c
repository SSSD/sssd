/*
    SSSD

    sdap_access.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include <sys/param.h>
#include <security/pam_modules.h>
#include <talloc.h>
#include <tevent.h>
#include <errno.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/sdap_async.h"
#include "providers/data_provider.h"
#include "providers/dp_backend.h"

static void sdap_access_reply(struct be_req *be_req, int pam_status)
{
    struct pam_data *pd;
    pd = talloc_get_type(be_req->req_data, struct pam_data);
    pd->pam_status = pam_status;

    if (pam_status == PAM_SUCCESS || pam_status == PAM_PERM_DENIED) {
        be_req->fn(be_req, DP_ERR_OK, pam_status, NULL);
    }

    else {
        be_req->fn(be_req, DP_ERR_FATAL, pam_status, NULL);
    }
}

static struct tevent_req *sdap_access_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct be_ctx *be_ctx,
                                           struct sdap_access_ctx *access_ctx,
                                           const char *username);
static void sdap_access_done(struct tevent_req *req);
void sdap_pam_access_handler(struct be_req *breq)
{
    struct pam_data *pd;
    struct tevent_req *req;
    struct sdap_access_ctx *access_ctx;

    pd = talloc_get_type(breq->req_data, struct pam_data);

    access_ctx =
            talloc_get_type(breq->be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                            struct sdap_access_ctx);

    req = sdap_access_send(breq,
                           breq->be_ctx->ev,
                           breq->be_ctx,
                           access_ctx,
                           pd->user);
    if (req == NULL) {
        DEBUG(1, ("Unable to start sdap_access request\n"));
        sdap_access_reply(breq, PAM_SYSTEM_ERR);
        return;
    }

    tevent_req_set_callback(req, sdap_access_done, breq);
}

struct sdap_access_req_ctx {
    const char *username;
    const char *filter;
    struct tevent_context *ev;
    struct sdap_access_ctx *access_ctx;
    struct sdap_id_ctx *sdap_ctx;
    struct sdap_id_op *sdap_op;
    struct sysdb_handle *handle;
    struct be_ctx *be_ctx;
    const char **attrs;
    int pam_status;
    bool cached_access;
    char *basedn;
};

static int sdap_access_decide_offline(struct tevent_req *req);
static int sdap_access_retry(struct tevent_req *req);
static void sdap_access_connect_done(struct tevent_req *subreq);
static void sdap_access_get_access_done(struct tevent_req *req);
static struct tevent_req *sdap_access_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct be_ctx *be_ctx,
                                           struct sdap_access_ctx *access_ctx,
                                           const char *username)
{
    errno_t ret;
    struct sdap_access_req_ctx *state;
    struct tevent_req *req;
    struct ldb_result *res;
    const char *basedn;

    req = tevent_req_create(mem_ctx, &state, struct sdap_access_req_ctx);
    if (req == NULL) {
        return NULL;
    }

    if (access_ctx->filter == NULL || *access_ctx->filter == '\0') {
        /* If no filter is set, default to restrictive */
        DEBUG(6, ("No filter set. Access is denied.\n"));
        state->pam_status = PAM_PERM_DENIED;
        tevent_req_done(req);
        tevent_req_post(req, be_ctx->ev);
        return req;
    }

    state->filter = NULL;
    state->be_ctx = be_ctx;
    state->username = username;
    state->pam_status = PAM_SYSTEM_ERR;
    state->sdap_ctx = access_ctx->id_ctx;
    state->ev = ev;
    state->access_ctx = access_ctx;

    state->attrs = talloc_array(state, const char *, 3);
    if (state->attrs == NULL) {
        DEBUG(1, ("Could not allocate attributes\n"));
        goto failed;
    }

    state->attrs[0] = SYSDB_ORIG_DN;
    state->attrs[1] = SYSDB_LDAP_ACCESS;
    state->attrs[2] = NULL;

    DEBUG(6, ("Performing access check for user [%s]\n", username));

    /* Get original user DN */
    ret = sysdb_get_user_attr(state, be_ctx->sysdb,
                              be_ctx->domain, username,
                              state->attrs,
                              &res);
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* If we can't find the user, return permission denied */
            state->pam_status = PAM_PERM_DENIED;
            goto finished;
        }
        goto failed;
    }
    else {
        if (res->count == 0) {
            /* If we can't find the user, return permission denied */
            state->pam_status = PAM_PERM_DENIED;
            goto finished;
        }

        if (res->count != 1) {
            DEBUG(1, ("Invalid response from sysdb_get_user_attr\n"));
            goto failed;
        }
    }

    /* Exactly one result returned */
    state->cached_access = ldb_msg_find_attr_as_bool(res->msgs[0],
                                                     SYSDB_LDAP_ACCESS,
                                                     false);
    /* Ok, we have one result, check if we are online or offline */
    if (be_is_offline(state->be_ctx)) {
        /* Ok, we're offline. Return from the cache */
        ret = sdap_access_decide_offline(req);
        goto finished;
    }

    /* Perform online operation */
    basedn = ldb_msg_find_attr_as_string(res->msgs[0],
                                         SYSDB_ORIG_DN,
                                         NULL);
    if(basedn == NULL) {
        DEBUG(1,("Could not find originalDN for user [%s]\n",
                 state->username));
        goto failed;
    }

    state->basedn = talloc_strdup(state, basedn);
    if (state->basedn == NULL) {
        DEBUG(1, ("Could not allocate memory for originalDN\n"));
        goto failed;
    }
    talloc_zfree(res);

    /* Construct the filter */
    state->filter = talloc_asprintf(
        state,
        "(&(%s=%s)(objectclass=%s)%s)",
        state->sdap_ctx->opts->user_map[SDAP_AT_USER_NAME].name,
        state->username,
        state->sdap_ctx->opts->user_map[SDAP_OC_USER].name,
        state->access_ctx->filter);
    if (state->filter == NULL) {
        DEBUG(0, ("Could not construct access filter\n"));
        goto failed;
    }

    DEBUG(6, ("Checking filter against LDAP\n"));

    state->sdap_op = sdap_id_op_create(state, state->sdap_ctx->conn_cache);
    if (!state->sdap_op) {
        DEBUG(2, ("sdap_id_op_create failed\n"));
        goto failed;
    }

    ret = sdap_access_retry(req);
    if (ret != EOK) {
        goto failed;
    }

    return req;

failed:
    talloc_free(req);
    return NULL;

finished:
    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;
}

static int sdap_access_decide_offline(struct tevent_req *req)
{
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);

    if (state->cached_access) {
        DEBUG(6, ("Access granted by cached credentials\n"));
        state->pam_status = PAM_SUCCESS;
    } else {
        DEBUG(6, ("Access denied by cached credentials\n"));
        state->pam_status = PAM_PERM_DENIED;
    }

    return EOK;
}

static int sdap_access_retry(struct tevent_req *req)
{
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);
    struct tevent_req *subreq;
    int ret;

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (!subreq) {
        DEBUG(2, ("sdap_id_op_connect_send failed: %d (%s)\n", ret, strerror(ret)));
        return ret;
    }

    tevent_req_set_callback(subreq, sdap_access_connect_done, req);
    return EOK;
}

static void sdap_access_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);
    int ret, dp_error;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            ret = sdap_access_decide_offline(req);
            if (ret == EOK) {
                tevent_req_done(req);
                return;
            }
        }

        tevent_req_error(req, ret);
        return;
    }

    /* Connection to LDAP succeeded
     * Send filter request
     */
    subreq = sdap_get_generic_send(state,
                                   state->ev,
                                   state->sdap_ctx->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   state->basedn,
                                   LDAP_SCOPE_BASE,
                                   state->filter, NULL,
                                   NULL, 0);
    if (subreq == NULL) {
        DEBUG(1, ("Could not start LDAP communication\n"));
        state->pam_status = PAM_SYSTEM_ERR;
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq, sdap_access_get_access_done, req);
}

static void sdap_access_get_access_done(struct tevent_req *subreq)
{
    int ret, dp_error;
    size_t num_results;
    bool found = false;
    struct sysdb_attrs *attrs;
    struct sysdb_attrs **results;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);
    ret = sdap_get_generic_recv(subreq, state,
                                &num_results, &results);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OK) {
            /* retry */
            ret = sdap_access_retry(req);
            if (ret == EOK) {
                return;
            }
            state->pam_status = PAM_SYSTEM_ERR;
        } else if (dp_error == DP_ERR_OFFLINE) {
            ret = sdap_access_decide_offline(req);
        } else {
            DEBUG(1, ("sdap_get_generic_send() returned error [%d][%s]\n",
                      ret, strerror(ret)));
            state->pam_status = PAM_SYSTEM_ERR;
        }

        goto done;
    }

    /* Check the number of responses we got
     * If it's exactly 1, we passed the check
     * If it's < 1, we failed the check
     * Anything else is an error
     */
    if (num_results < 1) {
        DEBUG(4, ("User [%s] was not found with the specified filter. "
                  "Denying access.\n", state->username));
        found = false;
    }
    else if (results == NULL) {
        DEBUG(1, ("num_results > 0, but results is NULL\n"));
        ret = EIO;
        state->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }
    else if (num_results > 1) {
        /* It should not be possible to get more than one reply
         * here, since we're doing a base-scoped search
         */
        DEBUG(1, ("Received multiple replies\n"));
        ret = EIO;
        state->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }
    else { /* Ok, we got a single reply */
        found = true;
    }

    if (found) {
        /* Save "allow" to the cache for future offline
         * access checks.
         */
        DEBUG(6, ("Access granted by online lookup\n"));
        state->pam_status = PAM_SUCCESS;
    }
    else {
        /* Save "disallow" to the cache for future offline
         * access checks.
         */
        DEBUG(6, ("Access denied by online lookup\n"));
        state->pam_status = PAM_PERM_DENIED;
    }

    attrs = sysdb_new_attrs(state);
    if (attrs == NULL) {
        ret = ENOMEM;
        DEBUG(1, ("Could not set up attrs\n"));
        goto done;
    }

    ret = sysdb_attrs_add_bool(attrs, SYSDB_LDAP_ACCESS,
                               state->pam_status == PAM_SUCCESS ?
                                                    true :
                                                    false);
    if (ret != EOK) {
        /* Failing to save to the cache is non-fatal.
         * Just return the result.
         */
        ret = EOK;
        DEBUG(1, ("Could not set up attrs\n"));
        goto done;
    }

    ret = sysdb_set_user_attr(attrs,
                              state->be_ctx->sysdb,
                              state->be_ctx->domain,
                              state->username,
                              attrs, SYSDB_MOD_REP);
    if (ret != EOK) {
        /* Failing to save to the cache is non-fatal.
         * Just return the result.
         */
        ret = EOK;
        DEBUG(1, ("Failed to set user access attribute\n"));
        goto done;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    }
    else {
        tevent_req_error(req, ret);
    }
}

static errno_t sdap_access_recv(struct tevent_req *req, int *pam_status)
{
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *pam_status = state->pam_status;

    return EOK;
}

static void sdap_access_done(struct tevent_req *req)
{
    errno_t ret;
    int pam_status;
    struct be_req *breq =
            tevent_req_callback_data(req, struct be_req);

    ret = sdap_access_recv(req, &pam_status);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(1, ("Error retrieving access check result.\n"));
        pam_status = PAM_SYSTEM_ERR;
    }

    sdap_access_reply(breq, pam_status);
}
