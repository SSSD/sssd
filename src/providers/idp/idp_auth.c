/*
    SSSD

    IdP Backend Module -- Authentication

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2024 Red Hat

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

#include <security/pam_modules.h>

#include "util/util.h"
#include "util/sss_chain_id.h"
#include "util/sss_cli_cmd.h"
#include "src/providers/idp/idp_auth.h"
#include "src/providers/idp/idp_private.h"

static errno_t
set_oidc_auth_extra_args(TALLOC_CTX *mem_ctx, struct idp_auth_ctx *idp_auth_ctx,
                         struct pam_data *pd,
                         const char ***oidc_child_extra_args)
{
    const char **extra_args;
    size_t c = 0;
    int ret;

    if (idp_auth_ctx == NULL || pd == NULL || oidc_child_extra_args == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing required parameter.\n");
        return EINVAL;
    }

    extra_args = talloc_zero_array(mem_ctx, const char *, 50);
    if (extra_args == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array() failed.\n");
        return ENOMEM;
    }

    switch (pd->cmd) {
    case SSS_PAM_PREAUTH:
        extra_args[c] = talloc_strdup(extra_args, "--get-device-code");
        break;
    case SSS_PAM_AUTHENTICATE:
        extra_args[c] = talloc_strdup(extra_args, "--get-access-token");
        break;
    case SSS_CMD_RENEW:
        extra_args[c] = talloc_strdup(extra_args, "--refresh-access-token");
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unsupported pam task [%d][%s].\n",
                                 pd->cmd, sss_cmd2str(pd->cmd));
        ret = EINVAL;
        goto done;
    }
    if (extra_args[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }
    c++;

    ret = set_oidc_common_args(extra_args, &c,
                               idp_auth_ctx->idp_type,
                               idp_auth_ctx->client_id,
                               idp_auth_ctx->client_secret,
                               idp_auth_ctx->token_endpoint,
                               idp_auth_ctx->scope);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set common arguments.\n");
        goto done;
    }

    extra_args[c] = talloc_asprintf(extra_args,
                                    "--device-auth-endpoint=%s",
                                    idp_auth_ctx->device_auth_endpoint);
    if (extra_args[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    c++;

    extra_args[c] = talloc_asprintf(extra_args,
                                    "--userinfo-endpoint=%s",
                                    idp_auth_ctx->userinfo_endpoint);
    if (extra_args[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    c++;

    if (idp_auth_ctx->idp_type != NULL
            && strncasecmp(idp_auth_ctx->idp_type, "keycloak:", 9) == 0) {
        /* Keycloak is using the 'id' attribute as 'sub' for OIDC */
        extra_args[c] = talloc_strdup(extra_args,
                                      "--user-identifier-attribute=sub");
    } else {
        extra_args[c] = talloc_strdup(extra_args,
                                      "--user-identifier-attribute=id");
    }
    if (extra_args[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }
    c++;

    if (DEBUG_IS_SET(SSSDBG_TRACE_LIBS)) {
        extra_args[c] = talloc_strdup(extra_args, "--libcurl-debug");
        if (extra_args[c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        c++;
    }

    extra_args[c] = NULL;

    *oidc_child_extra_args = extra_args;

    ret = EOK;

done:

    if (ret != EOK) {
        talloc_free(extra_args);
    }

    return ret;
}

static const char *get_stored_request_data(TALLOC_CTX *mem_ctx,
                                           struct idp_auth_ctx *idp_auth_ctx,
                                           struct pam_data *pd)
{
    int ret;
    const char *send_data = NULL;
    struct idp_open_req_data *open_req = NULL;
    const char *user_code;
    size_t user_code_len;

    if (sss_authtok_get_type(pd->authtok) != SSS_AUTHTOK_TYPE_OAUTH2) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unexpected authentication type [%d][%s].\n",
              sss_authtok_get_type(pd->authtok),
              sss_authtok_type_to_str(sss_authtok_get_type(pd->authtok)));
        goto done;
    }

    ret = sss_authtok_get_oauth2(pd->authtok, &user_code, &user_code_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to extract user code.\n");
        goto done;
    }

    open_req = sss_ptr_hash_lookup(idp_auth_ctx->open_request_table,
                                   user_code, struct idp_open_req_data);
    if (open_req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to retrieve stored request data.\n");
        goto done;
    }
    if (open_req->device_code_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing device code data.\n");
        goto done;
    }

    send_data = talloc_asprintf(mem_ctx, "%s\n%s",
                                dp_opt_get_cstring(idp_auth_ctx->idp_options,
                                                   IDP_CLIENT_SECRET),
                                open_req->device_code_data);
    if (send_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate auth data.\n");
        goto done;
    }

done:
    talloc_free(open_req);

    return send_data;
}

static const char *get_stored_token_data(TALLOC_CTX *mem_ctx,
                                         struct idp_auth_ctx *idp_auth_ctx,
                                         struct pam_data *pd)
{
    int ret;
    const char *attrs[] = {SYSDB_REFRESH_TOKEN, NULL};
    struct ldb_result *res = NULL;
    const char *send_data = NULL;
    const char *token = NULL;
    struct sss_domain_info *dom = NULL;

    dom = find_domain_by_name(idp_auth_ctx->be_ctx->domain,
                              pd->domain,
                              true);
    if (dom == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown domain %s\n", pd->domain);
        goto done;
    }

    ret = sysdb_get_user_attr(idp_auth_ctx, dom, pd->user, attrs, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to cached token for user [%s].\n",
                                 pd->user);
        goto done;
    }
    if (res->count != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Expected 1 user, got [%d].\n", res->count);
        ret = EINVAL;
        goto done;
    }

    token = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_REFRESH_TOKEN, NULL);
    if (token == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "User [%s] has no refresh token.\n", pd->user);
        ret = EINVAL;
        goto done;
    }

    send_data = talloc_asprintf(mem_ctx, "%s\n%s",
                                dp_opt_get_cstring(idp_auth_ctx->idp_options,
                                                   IDP_CLIENT_SECRET),
                                token);
    if (send_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate token refresh data.\n");
        goto done;
    }

done:
    talloc_free(res);

    return send_data;
}

static errno_t create_auth_send_buffer(TALLOC_CTX *mem_ctx,
                                       struct idp_auth_ctx *idp_auth_ctx,
                                       struct pam_data *pd,
                                       struct io_buffer **io_buf)
{
    struct io_buffer *buf = NULL;
    const char *send_data;
    int ret;

    buf = talloc_zero(mem_ctx, struct io_buffer);
    if (buf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        return ENOMEM;
    }

    switch (pd->cmd) {
    case SSS_PAM_PREAUTH:
        send_data = dp_opt_get_cstring(idp_auth_ctx->idp_options,
                                       IDP_CLIENT_SECRET);
        if (send_data == NULL || *send_data == '\0') {
            ret = EOK;
            goto done;
        }
        break;
    case SSS_PAM_AUTHENTICATE:
        send_data = get_stored_request_data(buf, idp_auth_ctx, pd);
        if (send_data == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get stored device code data.\n");
            ret = ENOENT;
            goto done;
        }
        break;
    case SSS_CMD_RENEW:
        send_data = get_stored_token_data(buf, idp_auth_ctx, pd);
        if (send_data == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get stored token code data.\n");
            ret = ENOENT;
            goto done;
        }
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unsupported pam task [%d][%s].\n",
                                 pd->cmd, sss_cmd2str(pd->cmd));
        ret = EINVAL;
        goto done;
    }

    buf->size = strlen(send_data);
    buf->data = talloc_size(buf, buf->size);
    if (buf->data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        ret = ENOMEM;
        goto done;
    }

    safealign_memcpy(buf->data, send_data, buf->size, NULL);

    ret = EOK;

done:
    if (ret == EOK) {
        *io_buf = buf;
    } else {
        talloc_free(buf);
    }

    return ret;
}

struct idp_auth_state {
    struct idp_req *idp_req;
    struct idp_auth_ctx *idp_auth_ctx;
    struct pam_data *pd;
    struct sss_domain_info *dom;
    struct io_buffer *send_buffer;
};

static void idp_auth_done(struct tevent_req *subreq);

struct tevent_req *idp_auth_send(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct be_ctx *be_ctx,
                                 struct idp_auth_ctx *idp_auth_ctx,
                                 struct pam_data *pd,
                                 struct sss_domain_info *dom)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct idp_auth_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct idp_auth_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create() failed.\n");
        return NULL;
    }
    state->idp_auth_ctx = idp_auth_ctx;
    state->pd = pd;
    state->dom = dom;

    state->idp_req = talloc_zero(state, struct idp_req);
    if (state->idp_req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for IdP request.\n");
        ret = ENOMEM;
        goto immediately;
    }

    state->idp_req->idp_options = idp_auth_ctx->idp_options;

    ret = set_oidc_auth_extra_args(state, idp_auth_ctx, state->pd,
                                   &state->idp_req->oidc_child_extra_args);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "set_oidc_extra_args() failed.\n");
        goto immediately;
    }

    ret = create_auth_send_buffer(state, idp_auth_ctx, pd, &state->send_buffer);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate send data.\n");
        goto immediately;
    }

    subreq = handle_oidc_child_send(state, ev, state->idp_req,
                                    state->send_buffer);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "handle_oidc_child_send() failed.\n");
        ret = ENOMEM;
        goto immediately;
    }
    tevent_req_set_callback(subreq, idp_auth_done, req);

    return req;

immediately:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    return tevent_req_post(req, ev);
}

static void idp_auth_done(struct tevent_req *subreq)
{
    struct idp_auth_state *state;
    struct tevent_req *req;
    errno_t ret;

    uint8_t *buf;
    ssize_t buflen;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct idp_auth_state);

    ret = handle_oidc_child_recv(subreq, state, &buf, &buflen);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_ALL, "[%zd][%.*s]\n", buflen, (int) buflen, buf);

    switch(state->pd->cmd) {
    case SSS_PAM_PREAUTH:
        ret = eval_device_auth_buf(state->idp_auth_ctx, state->pd, buf, buflen);
        break;
    case SSS_PAM_AUTHENTICATE:
    case SSS_CMD_RENEW:
        ret = eval_access_token_buf(state->idp_auth_ctx, state->pd, state->dom,
                                    buf, buflen);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unsupported pam task [%d][%s].\n",
                                 state->pd->cmd, sss_cmd2str(state->pd->cmd));
        tevent_req_error(req, EINVAL);
        return;
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to evaluate IdP reply.\n");
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int idp_auth_recv(struct tevent_req *req, int *_pam_status)
{
    *_pam_status = PAM_SYSTEM_ERR;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_pam_status = PAM_SUCCESS;

    return EOK;
}

struct idp_pam_auth_handler_state {
    struct tevent_context *ev;
    struct idp_auth_ctx *auth_ctx;
    struct be_ctx *be_ctx;
    struct pam_data *pd;
    struct sss_domain_info *dom;
};

static void idp_pam_auth_handler_done(struct tevent_req *subreq);

struct tevent_req *
idp_pam_auth_handler_send(TALLOC_CTX *mem_ctx,
                          struct idp_auth_ctx *auth_ctx,
                          struct pam_data *pd,
                          struct dp_req_params *params)
{
    struct idp_pam_auth_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct idp_pam_auth_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;
    state->ev = params->ev;
    state->auth_ctx = auth_ctx;
    state->be_ctx = params->be_ctx;
    state->dom = find_domain_by_name(state->be_ctx->domain,
                                     state->pd->domain,
                                     true);
    if (state->dom == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown domain %s\n", state->pd->domain);
        pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;
    }

    switch (pd->cmd) {
    case SSS_PAM_PREAUTH:
    case SSS_PAM_AUTHENTICATE:
    case SSS_CMD_RENEW:
        subreq = idp_auth_send(state, state->ev, state->be_ctx,
                               state->auth_ctx,  state->pd, state->dom);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to start IdP authentication.\n");
            state->pd->pam_status = PAM_SYSTEM_ERR;
            goto immediately;
        }
        tevent_req_set_callback(subreq, idp_pam_auth_handler_done, req);
        break;
    case SSS_PAM_SETCRED:
    case SSS_PAM_OPEN_SESSION:
    case SSS_PAM_CLOSE_SESSION:
        pd->pam_status = PAM_SUCCESS;
        goto immediately;
        break;
    default:
        DEBUG(SSSDBG_CONF_SETTINGS,
              "idp provider cannot handle pam task [%d][%s].\n",
              pd->cmd, sss_cmd2str(pd->cmd));
        pd->pam_status = PAM_MODULE_UNKNOWN;
        goto immediately;
    }

    return req;

immediately:
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void idp_pam_auth_handler_done(struct tevent_req *subreq)
{
    struct idp_pam_auth_handler_state *state = NULL;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct idp_pam_auth_handler_state);

    ret = idp_auth_recv(subreq, &state->pd->pam_status);
    talloc_zfree(subreq);
    if (ret != EOK) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
    }

    tevent_req_done(req);
}

errno_t
idp_pam_auth_handler_recv(TALLOC_CTX *mem_ctx,
                          struct tevent_req *req,
                          struct pam_data **_data)
{
    struct idp_pam_auth_handler_state *state = NULL;

    state = tevent_req_data(req, struct idp_pam_auth_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}

static void refresh_token_handler_done(struct tevent_req *req);
static void refresh_token_handler(struct tevent_context *ev,
                                  struct tevent_timer *te,
                                  struct timeval current_time,
                                  void *private_data) {
    struct idp_refresh_data *refresh_data = talloc_get_type(private_data,
                                                       struct idp_refresh_data);
    struct idp_auth_ctx *auth_ctx = refresh_data->auth_ctx;

    refresh_data->te = NULL;

    DEBUG(SSSDBG_TRACE_ALL, "Sending idp auth request.\n");
    refresh_data->req = idp_auth_send(refresh_data, ev, auth_ctx->be_ctx,
                                      auth_ctx, refresh_data->pd,
                                      refresh_data->dom);
    if (refresh_data->req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "idp_auth_send failed.\n");
        return;
    }

    tevent_req_set_callback(refresh_data->req, refresh_token_handler_done,
                            refresh_data);
}

static void refresh_token_handler_done(struct tevent_req *req) {
    struct idp_refresh_data *refresh_data = tevent_req_callback_data(req,
                                                       struct idp_refresh_data);
    errno_t ret;

    ret = idp_auth_recv(req, &refresh_data->pd->pam_status);
    talloc_free(req);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "idp auth request failed.\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "idp auth request succeeded.\n");
    switch (refresh_data->pd->pam_status) {
        case PAM_SUCCESS:
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Successfully refreshed tokens for user [%s].\n",
                      refresh_data->pd->user);
            break;
        case PAM_AUTHINFO_UNAVAIL:
        case PAM_AUTHTOK_LOCK_BUSY:
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Failed to refresh tokens for user [%s]; currently offline.\n",
                  refresh_data->pd->user);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to refresh tokens for user [%s].\n",
                  refresh_data->pd->user);
            break;
    }

done:
    talloc_free(refresh_data);
}

errno_t
create_refresh_token_timer(struct idp_auth_ctx *auth_ctx, struct pam_data *pd,
                           const char *user_uuid,
                           time_t issued_at, time_t expires_at) {
    DEBUG(SSSDBG_TRACE_ALL, "Scheduling token refresh.\n");

    int ret;
    struct idp_refresh_data *refresh_data;
    struct timeval refresh_timestamp = {.tv_sec = issued_at +
                                                  (expires_at - issued_at) / 2};

    refresh_data = talloc_zero(auth_ctx, struct idp_refresh_data);
    if (refresh_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }
    refresh_data->auth_ctx = auth_ctx;

    ret = copy_pam_data(refresh_data, pd, &refresh_data->pd);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "copy_pam_data failed.\n");
        goto fail;
    }
    refresh_data->pd->cmd = SSS_CMD_RENEW;
    sss_authtok_set_empty(refresh_data->pd->newauthtok);

    refresh_data->dom = find_domain_by_name(auth_ctx->be_ctx->domain,
                                            refresh_data->pd->domain,
                                            true);
    if (refresh_data->dom == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown domain %s\n",
                                   refresh_data->pd->domain);
        refresh_data->pd->pam_status = PAM_SYSTEM_ERR;
        ret = EINVAL;
        goto fail;
    }

    refresh_data->te = tevent_add_timer(auth_ctx->be_ctx->ev, refresh_data,
                                        refresh_timestamp,
                                        refresh_token_handler, refresh_data);
    if (refresh_data->te == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to schedule token refresh.\n");
        ret = ENOMEM;
        goto fail;
    }

    ret = sss_ptr_hash_add_or_override(auth_ctx->token_refresh_table, user_uuid,
                                       refresh_data, struct idp_refresh_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to add scheduled token refresh to table.\n");
        goto fail;
    }

    return EOK;

fail:
    talloc_free(refresh_data);

    return ret;
}
