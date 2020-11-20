/*
    SSSD

    Kerberos 5 Backend Module - access control

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include "util/util.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_utils.h"

struct krb5_access_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;

    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;
    struct krb5child_req *kr;

    bool access_allowed;
};

static void krb5_access_done(struct tevent_req *subreq);
struct tevent_req *krb5_access_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct be_ctx *be_ctx,
                                    struct pam_data *pd,
                                    struct krb5_ctx *krb5_ctx)
{
    struct krb5_access_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    int ret;
    const char **attrs;
    struct ldb_result *res;
    struct sss_domain_info *dom;

    req = tevent_req_create(mem_ctx, &state, struct krb5_access_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->be_ctx = be_ctx;
    state->pd = pd;
    state->krb5_ctx = krb5_ctx;
    state->access_allowed = false;

    ret = get_domain_or_subdomain(be_ctx, pd->domain, &dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_domain_or_subdomain failed.\n");
        goto done;
    }

    ret = krb5_setup(state, pd, dom, krb5_ctx, &state->kr);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_setup failed.\n");
        goto done;
    }

    if (pd->cmd != SSS_PAM_ACCT_MGMT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unexpected pam task %d.\n", pd->cmd);
        ret = EINVAL;
        goto done;
    }

    attrs = talloc_array(state, const char *, 5);
    if (attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    attrs[0] = SYSDB_UPN;
    attrs[1] = SYSDB_UIDNUM;
    attrs[2] = SYSDB_GIDNUM;
    attrs[3] = SYSDB_CANONICAL_UPN;
    attrs[4] = NULL;

    ret = sysdb_get_user_attr(state, be_ctx->domain, state->pd->user, attrs,
                              &res);
    if (ret) {
        DEBUG(SSSDBG_FUNC_DATA,
              "sysdb search for upn of user [%s] failed.\n", pd->user);
        goto done;
    }

    switch (res->count) {
    case 0:
        DEBUG(SSSDBG_FUNC_DATA,
              "No attributes for user [%s] found.\n", pd->user);
        ret = ENOENT;
        goto done;
        break;
    case 1:
        ret = find_or_guess_upn(state, res->msgs[0], krb5_ctx, be_ctx->domain,
                                state->kr->user, pd->domain, &state->kr->upn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "find_or_guess_upn failed.\n");
            goto done;
        }

        state->kr->uid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_UIDNUM,
                                                     0);
        if (state->kr->uid == 0) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "UID for user [%s] not known.\n", pd->user);
            ret = ENOENT;
            goto done;
        }

        state->kr->gid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_GIDNUM,
                                                     0);
        if (state->kr->gid == 0) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "GID for user [%s] not known.\n", pd->user);
            ret = ENOENT;
            goto done;
        }

        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "User search for [%s] returned > 1 results!\n", pd->user);
        ret = EINVAL;
        goto done;
        break;
    }

    subreq = handle_child_send(state, state->ev, state->kr);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "handle_child_send failed.\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, krb5_access_done, req);
    return req;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, state->ev);
    return req;
}

static void krb5_access_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct krb5_access_state *state = tevent_req_data(req,
                                                      struct krb5_access_state);
    int ret;
    uint8_t *buf = NULL;
    ssize_t len = -1;
    int32_t msg_status;

    ret = handle_child_recv(subreq, state, &buf, &len);
    talloc_free(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "child failed [%d][%s].\n", ret, strerror(ret));
        goto fail;
    }

    if ((size_t) len != sizeof(int32_t)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "message has the wrong size.\n");
        ret = EINVAL;
        goto fail;
    }

    SAFEALIGN_COPY_INT32(&msg_status, buf, NULL);

    if (msg_status == EOK) {
        state->access_allowed = true;
    } else {
        state->access_allowed = false;
    }

    tevent_req_done(req);
    return;

fail:
    tevent_req_error(req, ret);
    return;
}

int krb5_access_recv(struct tevent_req *req, bool *access_allowed)
{
    struct krb5_access_state *state = tevent_req_data(req,
                                                      struct krb5_access_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *access_allowed = state->access_allowed;

    return EOK;
}
