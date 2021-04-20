/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include <talloc.h>
#include <tevent.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "sbus/sbus_request.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/backend.h"
#include "util/sss_pam_data.h"
#include "util/util.h"

static void choose_target(struct data_provider *provider,
                          struct pam_data *pd,
                          enum dp_targets *_target,
                          enum dp_methods *_method,
                          const char **_req_name)
{
    enum dp_targets target;
    enum dp_methods method;
    const char *name;

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            target = DPT_AUTH;
            method = DPM_AUTH_HANDLER;
            name = "PAM Authenticate";
            break;
        case SSS_PAM_PREAUTH:
            target = DPT_AUTH;
            method = DPM_AUTH_HANDLER;
            name = "PAM Preauth";
            break;
        case SSS_PAM_ACCT_MGMT:
            target = DPT_ACCESS;
            method = DPM_ACCESS_HANDLER;
            name = "PAM Account";
            break;
        case SSS_PAM_CHAUTHTOK_PRELIM:
            target = DPT_CHPASS;
            method = DPM_AUTH_HANDLER;
            name = "PAM Chpass 1st";
            break;
        case SSS_PAM_CHAUTHTOK:
            target = DPT_CHPASS;
            method = DPM_AUTH_HANDLER;
            name = "PAM Chpass 2nd";
            break;
        case SSS_PAM_OPEN_SESSION:
            name = "PAM Open Session";
            if (dp_method_enabled(provider, DPT_SESSION, DPM_SESSION_HANDLER)) {
                target = DPT_SESSION;
                method = DPM_SESSION_HANDLER;
                break;
            }

            target = DP_TARGET_SENTINEL;
            method = DP_METHOD_SENTINEL;
            pd->pam_status = PAM_SUCCESS;
            break;
        case SSS_PAM_SETCRED:
            target = DP_TARGET_SENTINEL;
            method = DP_METHOD_SENTINEL;
            name = "PAM Set Credentials";
            pd->pam_status = PAM_SUCCESS;
            break;
        case SSS_PAM_CLOSE_SESSION:
            target = DP_TARGET_SENTINEL;
            method = DP_METHOD_SENTINEL;
            name = "PAM Close Session";
            pd->pam_status = PAM_SUCCESS;
            break;
        default:
            DEBUG(SSSDBG_TRACE_LIBS, "Unsupported PAM command [%d].\n",
                  pd->cmd);
            target = DP_TARGET_SENTINEL;
            method = DP_METHOD_SENTINEL;
            name = "PAM Unsupported";
            pd->pam_status = PAM_MODULE_UNKNOWN;
            break;
    }

    /* Check that target is configured. */
    if (target != DP_TARGET_SENTINEL
            && !dp_target_enabled(provider, NULL, target)) {
        target = DP_TARGET_SENTINEL;
        method = DP_METHOD_SENTINEL;
        pd->pam_status = PAM_MODULE_UNKNOWN;
    }

    *_target = target;
    *_method = method;
    *_req_name = name;
}

static bool should_invoke_selinux(struct data_provider *provider,
                                  struct pam_data *pd)
{
    if (!dp_method_enabled(provider, DPT_SELINUX, DPM_SELINUX_HANDLER)) {
        return false;
    }

    if (pd->cmd == SSS_PAM_ACCT_MGMT && pd->pam_status == PAM_SUCCESS) {
        return true;
    }

    return false;
}

struct dp_pam_handler_state {
    struct data_provider *provider;
    struct pam_data *pd;
};

static void dp_pam_handler_auth_done(struct tevent_req *subreq);
static void dp_pam_handler_done(struct tevent_req *subreq);

struct tevent_req *
dp_pam_handler_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct sbus_request *sbus_req,
                    struct data_provider *provider,
                    struct pam_data *pd)
{
    struct dp_pam_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    enum dp_targets target;
    enum dp_methods method;
    const char *req_name;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct dp_pam_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    pd->pam_status = PAM_SYSTEM_ERR;
    if (pd->domain == NULL) {
        pd->domain = talloc_strdup(pd, provider->be_ctx->domain->name);
        if (pd->domain == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    state->provider = provider;
    state->pd = pd;

    DEBUG(SSSDBG_CONF_SETTINGS, "Got request with the following data\n");
    DEBUG_PAM_DATA(SSSDBG_CONF_SETTINGS, pd);

    choose_target(provider, pd, &target, &method, &req_name);
    if (target == DP_TARGET_SENTINEL) {
        ret = EOK;
        goto done;
    }

    subreq = dp_req_send(state, provider, pd->domain, req_name,
                         pd->client_id_num, sbus_req->sender->name,
                         target, method, 0, pd, NULL);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, dp_pam_handler_auth_done, req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void dp_pam_handler_auth_done(struct tevent_req *subreq)
{
    struct dp_pam_handler_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct dp_pam_handler_state);

    ret = dp_req_recv(state, subreq, struct pam_data *, &state->pd);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (!should_invoke_selinux(state->provider, state->pd)) {
        tevent_req_done(req);
        return;
    }

    subreq = dp_req_send(state, state->provider, state->pd->domain,
                         "PAM SELinux", state->pd->client_id_num,
                         "sssd.pam", DPT_SELINUX,
                         DPM_SELINUX_HANDLER, 0, state->pd, NULL);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, dp_pam_handler_done, req);
}

static void dp_pam_handler_done(struct tevent_req *subreq)
{
    struct dp_pam_handler_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct dp_pam_handler_state);

    ret = dp_req_recv(state, subreq, struct pam_data *, &state->pd);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
dp_pam_handler_recv(TALLOC_CTX *mem_ctx,
                    struct tevent_req *req,
                    struct pam_data **_pd)
{
    struct dp_pam_handler_state *state;
    state = tevent_req_data(req, struct dp_pam_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_pd = talloc_steal(mem_ctx, state->pd);

    return EOK;
}

struct dp_access_control_refresh_rules_state {
    void *reply;
};

static void dp_access_control_refresh_rules_done(struct tevent_req *subreq);

struct tevent_req *
dp_access_control_refresh_rules_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct sbus_request *sbus_req,
                                     struct data_provider *provider)
{
    struct dp_access_control_refresh_rules_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct dp_access_control_refresh_rules_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    subreq = dp_req_send(state, provider, NULL, "Refresh Access Control Rules",
                         0, sbus_req->sender->name, DPT_ACCESS, DPM_REFRESH_ACCESS_RULES,
                         0, NULL, NULL);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, dp_access_control_refresh_rules_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void dp_access_control_refresh_rules_done(struct tevent_req *subreq)
{
    struct dp_access_control_refresh_rules_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct dp_access_control_refresh_rules_state);

    ret = dp_req_recv(state, subreq, void *, &state->reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
dp_access_control_refresh_rules_recv(TALLOC_CTX *mem_ctx,
                                     struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
