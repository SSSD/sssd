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

#include "sbus/sssd_dbus.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/backend.h"
#include "util/util.h"

static void dp_pam_reply(struct sbus_request *sbus_req,
                         const char *request_name,
                         struct pam_data *pd)
{
    DBusMessage *reply;
    dbus_bool_t dbret;

    DP_REQ_DEBUG(SSSDBG_TRACE_LIBS, request_name,
                 "Sending result [%d][%s]", pd->pam_status, pd->domain);

    reply = dbus_message_new_method_return(sbus_req->message);
    if (reply == NULL) {
        DP_REQ_DEBUG(SSSDBG_TRACE_LIBS, request_name,
                     "Unable to acquire reply message");
        return;
    }

    dbret = dp_pack_pam_response(reply, pd);
    if (!dbret) {
        DP_REQ_DEBUG(SSSDBG_TRACE_LIBS, request_name,
                     "Unable to generate reply message");
        dbus_message_unref(reply);
        return;
    }

    sbus_request_finish(sbus_req, reply);
    dbus_message_unref(reply);
    return;
}

static errno_t pam_data_create(TALLOC_CTX *mem_ctx,
                               struct sbus_request *sbus_req,
                               struct be_ctx *be_ctx,
                               struct pam_data **_pd)
{
    DBusError dbus_error;
    struct pam_data *pd;
    bool bret;

    dbus_error_init(&dbus_error);
    bret = dp_unpack_pam_request(sbus_req->message, mem_ctx, &pd, &dbus_error);
    if (bret == false) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to parse message!\n");
        return EINVAL;
    }

    pd->pam_status = PAM_SYSTEM_ERR;
    if (pd->domain == NULL) {
        pd->domain = talloc_strdup(pd, be_ctx->domain->name);
        if (pd->domain == NULL) {
            talloc_free(pd);
            return ENOMEM;
        }
    }

    *_pd = pd;

    return EOK;
}

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

struct dp_pam_handler_state {
    struct data_provider *provider;
    struct dp_client *dp_cli;
    struct sbus_request *sbus_req;
    const char *request_name;
};

void dp_pam_handler_step_done(struct tevent_req *req);
void dp_pam_handler_selinux_done(struct tevent_req *req);

errno_t dp_pam_handler(struct sbus_request *sbus_req, void *sbus_data)
{
    struct dp_pam_handler_state *state;
    struct data_provider *provider;
    struct pam_data *pd = NULL;
    struct dp_client *dp_cli;
    enum dp_targets target;
    enum dp_methods method;
    const char *req_name;
    struct tevent_req *req;
    errno_t ret;

    dp_cli = talloc_get_type(sbus_data, struct dp_client);
    provider = dp_client_provider(dp_cli);

    state = talloc_zero(sbus_req, struct dp_pam_handler_state);
    if (state == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = pam_data_create(state, sbus_req, provider->be_ctx, &pd);
    if (ret != EOK) {
        return ret;
    }

    state->provider = provider;
    state->dp_cli = dp_cli;
    state->sbus_req = sbus_req;

    DEBUG(SSSDBG_CONF_SETTINGS, "Got request with the following data\n");
    DEBUG_PAM_DATA(SSSDBG_CONF_SETTINGS, pd);

    choose_target(provider, pd, &target, &method, &req_name);
    if (target == DP_TARGET_SENTINEL) {
        /* Just send the result. Pam data are freed with this call. */
        dp_pam_reply(sbus_req, req_name, pd);
        return EOK;
    }

    req = dp_req_send(state, provider, dp_cli, pd->domain, req_name,
                      target, method, 0, pd, &state->request_name);
    if (req == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, dp_pam_handler_step_done, state);

done:
    if (ret != EOK) {
        talloc_free(pd);
    }

    return ret;
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

void dp_pam_handler_step_done(struct tevent_req *req)
{
    struct dp_pam_handler_state *state;
    struct pam_data *pd;
    errno_t ret;

    state = tevent_req_callback_data(req, struct dp_pam_handler_state);

    ret = dp_req_recv(state, req, struct pam_data *, &pd);
    talloc_zfree(req);
    if (ret != EOK) {
        dp_req_reply_error(state->sbus_req, state->request_name, ret);
        return;
    }

    if (!should_invoke_selinux(state->provider, pd)) {
        /* State and request related data are freed with sbus_req. */
        dp_pam_reply(state->sbus_req, state->request_name, pd);
        return;
    }

    req = dp_req_send(state, state->provider, state->dp_cli, pd->domain,
                      "PAM SELinux", DPT_SELINUX, DPM_SELINUX_HANDLER,
                      0, pd, NULL);
    if (req == NULL) {
        DP_REQ_DEBUG(SSSDBG_CRIT_FAILURE, state->request_name,
                     "Unable to process SELinux, killing request...");
        talloc_free(state->sbus_req);
        return;
    }

    tevent_req_set_callback(req, dp_pam_handler_selinux_done, state);
}

void dp_pam_handler_selinux_done(struct tevent_req *req)
{
    struct dp_pam_handler_state *state;
    struct pam_data *pd;
    errno_t ret;

    state = tevent_req_callback_data(req, struct dp_pam_handler_state);

    ret = dp_req_recv(state, req, struct pam_data *, &pd);
    talloc_zfree(req);
    if (ret != EOK) {
        dp_req_reply_error(state->sbus_req, state->request_name, ret);
        return;
    }

    /* State and request related data are freed with sbus_req. */
    dp_pam_reply(state->sbus_req, state->request_name, pd);
    return;
}

errno_t dp_access_control_refresh_rules_handler(struct sbus_request *sbus_req,
                                                void *dp_cli)
{
    const char *key;

    key = "RefreshRules";

    dp_req_with_reply(dp_cli, NULL, "Refresh Access Control Rules", key,
                      sbus_req, DPT_ACCESS, DPM_REFRESH_ACCESS_RULES, 0, NULL,
                      dp_req_reply_default, void *);

    return EOK;
}
