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
    struct sysdb_handle *handle;
    struct be_ctx *be_ctx;
    const char **attrs;
    int pam_status;
    bool cached_access;
    char *basedn;
};
static void sdap_access_get_dn_done(void *pvt, int ldb_status,
                                    struct ldb_result *res);
static struct tevent_req *sdap_access_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct be_ctx *be_ctx,
                                           struct sdap_access_ctx *access_ctx,
                                           const char *username)
{
    errno_t ret;
    struct sdap_access_req_ctx *state;
    struct tevent_req *req;

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
                              sdap_access_get_dn_done, req);
    return req;

failed:
    talloc_free(req);
    return NULL;
}

static void sdap_access_connect_done(struct tevent_req *subreq);
static void sdap_access_get_access_done(struct tevent_req *req);
static void sdap_access_get_dn_done(void *pvt, int ldb_status,
                                    struct ldb_result *res)
{
    errno_t ret;
    struct sdap_access_req_ctx *state;
    const char *basedn;
    struct tevent_req *req;
    struct tevent_req *subreq;

    req = talloc_get_type(pvt, struct tevent_req);

    state = tevent_req_data(req, struct sdap_access_req_ctx);
    talloc_zfree(state->attrs);

    /* Verify our results */
    if (ldb_status == LDB_ERR_NO_SUCH_OBJECT) {
        DEBUG(4, ("User not found in LDB.\n"));
        ret = EOK;
        state->pam_status = PAM_USER_UNKNOWN;
        goto done;
    }
    else if (ldb_status != LDB_SUCCESS) {
        DEBUG(1, ("LDB search failed.\n"));
        ret = sysdb_error_to_errno(ldb_status);
        state->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    /* Make sure we got exactly one result */
    if (res->count < 1) {
        DEBUG(4, ("User not found in LDB.\n"));
        ret = EOK;
        state->pam_status = PAM_USER_UNKNOWN;
        goto done;
    }

    if (res->count > 1) {
        DEBUG(1, ("More than one user found.\n"));
        ret = EIO;
        state->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    state->cached_access = ldb_msg_find_attr_as_bool(res->msgs[0],
                                                     SYSDB_LDAP_ACCESS,
                                                     false);

    /* Ok, we have one result, check if we are online or offline */
    if (be_is_offline(state->be_ctx)) {
        /* Ok, we're offline. Return from the cache */
        if (state->cached_access) {
            DEBUG(6, ("Access granted by cached credentials\n"));
            ret = EOK;
            state->pam_status = PAM_SUCCESS;
            goto done;
        }

        /* Access denied */
        DEBUG(6, ("Access denied by cached credentials\n"));
        ret = EOK;
        state->pam_status = PAM_PERM_DENIED;
        goto done;
    }

    /* Perform online operation */
    basedn = ldb_msg_find_attr_as_string(res->msgs[0],
                                         SYSDB_ORIG_DN,
                                         NULL);
    if(basedn == NULL) {
        DEBUG(1,("Could not find originalDN for user [%s]\n",
                 state->username));
        ret = EIO;
        state->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    state->basedn = talloc_strdup(state, basedn);
    if (state->basedn == NULL) {
        DEBUG(1, ("Could not allocate memory for originalDN\n"));
        ret = ENOMEM;
        state->pam_status = PAM_SYSTEM_ERR;
        goto done;
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
        ret = ENOMEM;
        state->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    DEBUG(6, ("Checking filter against LDAP\n"));

    /* Check whether we have an active LDAP connection */
    if (state->sdap_ctx->gsh == NULL || ! state->sdap_ctx->gsh->connected) {
        subreq = sdap_cli_connect_send(state, state->ev,
                                       state->sdap_ctx->opts,
                                       state->sdap_ctx->be,
                                       state->sdap_ctx->service,
                                       NULL);
        if (!subreq) {
            DEBUG(1, ("sdap_cli_connect_send failed.\n"));
            ret = EIO;
            state->pam_status = PAM_SYSTEM_ERR;
            goto done;
        }

        tevent_req_set_callback(subreq, sdap_access_connect_done, req);
        return;
    }

    /* Make the LDAP request */
    subreq = sdap_get_generic_send(state,
                                   state->ev,
                                   state->sdap_ctx->opts,
                                   state->sdap_ctx->gsh,
                                   state->basedn, LDAP_SCOPE_BASE,
                                   state->filter, NULL,
                                   NULL, 0);
    if (subreq == NULL) {
        DEBUG(1, ("Could not start LDAP communication\n"));
        ret = EIO;
        state->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_access_get_access_done, req);
    return;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    }
    else {
        tevent_req_error(req, ret);
    }
}

static void sdap_access_connect_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);

    ret = sdap_cli_connect_recv(subreq, state->sdap_ctx,
                                &state->sdap_ctx->gsh, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* Could not connect to LDAP. Mark as offline and return
         * from cache.
         */
        be_mark_offline(state->be_ctx);
        if (state->cached_access) {
            DEBUG(6, ("Access granted by cached credentials\n"));
            state->pam_status = PAM_SUCCESS;
            tevent_req_done(req);
            return;
        }

        /* Access denied */
        DEBUG(6, ("Access denied by cached credentials\n"));
        state->pam_status = PAM_PERM_DENIED;
        tevent_req_done(req);
    }

    /* Connection to LDAP succeeded
     * Send filter request
     */
    subreq = sdap_get_generic_send(state,
                                   state->ev,
                                   state->sdap_ctx->opts,
                                   state->sdap_ctx->gsh,
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

static void sdap_access_save_cache(struct tevent_req *req);
static void sdap_access_get_access_done(struct tevent_req *subreq)
{
    errno_t ret;
    size_t num_results;
    bool found = false;
    struct sysdb_attrs **results;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);
    ret = sdap_get_generic_recv(subreq, state,
                                &num_results, &results);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("sdap_get_generic_send() returned error [%d][%s]",
                  ret, strerror(ret)));
        state->pam_status = PAM_SYSTEM_ERR;
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
        state->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }
    else if (num_results > 1) {
        /* It should not be possible to get more than one reply
         * here, since we're doing a base-scoped search
         */
        DEBUG(1, ("Received multiple replies\n"));
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

    /* Start a transaction to cache the access result */
    subreq = sysdb_transaction_send(state, state->ev,
                                    state->be_ctx->sysdb);
    if (subreq == NULL) {
        /* Failing to save the cache is non-fatal.
         * Just return the result.
         */
        ret = EOK;
        DEBUG(1, ("Failed to create transaction for user access attr\n"));
        goto done;
    }
    tevent_req_set_callback(subreq, sdap_access_save_cache, req);
    return;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    }
    else {
        tevent_req_error(req, ret);
    }
}

static void sdap_access_cache_commit(struct tevent_req *subreq);
static void sdap_access_save_cache(struct tevent_req *subreq)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);

    ret = sysdb_transaction_recv(subreq, state, &state->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* Failing to save the cache is non-fatal.
         * Just return the result.
         */
        ret = EOK;
        DEBUG(1, ("Failed to create transaction for user access attr\n"));
        goto done;
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
        DEBUG(1, ("Could not set up attrs\n"));
        goto done;
    }

    subreq = sysdb_set_user_attr_send(attrs,
                                      state->ev,
                                      state->handle,
                                      state->be_ctx->domain,
                                      state->username,
                                      attrs, SYSDB_MOD_REP);
    if (subreq == NULL) {
        /* Failing to save to the cache is non-fatal.
         * Just return the result.
         */
        DEBUG(1, ("Failed to set user access attribute\n"));
        goto done;
    }
    tevent_req_set_callback(subreq, sdap_access_cache_commit, req);
    return;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    }
    else {
        tevent_req_error(req, ret);
    }
}

static void sdap_access_cache_done(struct tevent_req *subreq);
static void sdap_access_cache_commit(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);

    ret = sysdb_set_entry_attr_recv(subreq);
    talloc_zfree(subreq);

    if(ret != EOK) {
        goto failed;
    }

    subreq = sysdb_transaction_commit_send(state, state->ev, state->handle);
    if (subreq == NULL) {
        goto failed;
    }
    tevent_req_set_callback(subreq,sdap_access_cache_done,req);
    return;

failed:
    /* Failing to save to the cache is non-fatal.
     * Just return the result.
     */
    DEBUG(1, ("Failed to set user access attribute\n"));
    tevent_req_done(req);
    return;
}

static void sdap_access_cache_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);

    ret = sysdb_transaction_commit_recv(subreq);
    talloc_zfree(subreq);

    if(ret != EOK) {
        /* Failing to save to the cache is non-fatal */
        DEBUG(1,("Unable to save access results to the cache\n"));
    }
    else {
        DEBUG(6, ("Saved access result to the user cache\n"));
    }

    tevent_req_done(req);
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
