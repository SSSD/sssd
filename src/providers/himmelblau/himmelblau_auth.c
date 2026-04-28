/*
    SSSD

    Himmelblau Provider - Authentication handler

    Authors:
        David Mulder <dmulder@suse.com>

    Copyright (C) 2026 SUSE

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

#include "config.h"

#include <security/pam_modules.h>
#include <string.h>

#include "providers/himmelblau/himmelblau_common.h"
#include "providers/backend.h"

/* Device enrollment state */
struct himmelblau_enroll_device_state {
    struct himmelblau_init_ctx *init_ctx;
    char *device_id;
};

/* Authentication state */
struct himmelblau_authenticate_user_state {
    struct himmelblau_init_ctx *init_ctx;
    struct pam_data *pd;
    struct tevent_context *ev;

    char *username;
    char *password;

    UserToken *token;
    MFAAuthContinue *mfa_continue;

    char *access_token;
    char *refresh_token;

    int poll_attempt;
    int max_poll_attempts;
    int polling_interval;
};

/* PAM handler state */
struct himmelblau_pam_handler_state {
    struct pam_data *pd;
    struct himmelblau_auth_ctx *auth_ctx;
    struct tevent_context *ev;

    char *username;
    char *password;
    char *device_id;
    bool device_enrolled;

    UserToken *token;
};

/* Destructor for authentication state */
static int himmelblau_authenticate_user_state_destructor(
    struct himmelblau_authenticate_user_state *state)
{
    if (state->token) {
        user_token_free(state->token);
        state->token = NULL;
    }

    if (state->mfa_continue) {
        mfa_auth_continue_free(state->mfa_continue);
        state->mfa_continue = NULL;
    }

    /* Sensitive data (password, tokens) is automatically erased by
     * sss_erase_talloc_mem_securely() destructors set on allocation */

    return 0;
}

/* Destructor for PAM handler state */
static int himmelblau_pam_handler_state_destructor(
    struct himmelblau_pam_handler_state *state)
{
    if (state->token) {
        user_token_free(state->token);
        state->token = NULL;
    }

    /* Sensitive data (password) is automatically erased by
     * sss_erase_talloc_mem_securely() destructor set on allocation */

    return 0;
}

/* Device enrollment - NOTE: This must be called AFTER authentication
 * because it requires a refresh_token from the authenticated UserToken */
struct tevent_req *
himmelblau_enroll_device_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct himmelblau_init_ctx *init_ctx,
                              const char *refresh_token)
{
    struct tevent_req *req;
    struct himmelblau_enroll_device_state *state;
    EnrollAttrs *attrs = NULL;
    MSAL_ERROR *error = NULL;
    char *device_id = NULL;
    LoadableMsOapxbcRsaKey *transport_key_obj = NULL;
    LoadableMsDeviceEnrolmentKey *cert_key_obj = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                           struct himmelblau_enroll_device_state);
    if (req == NULL) {
        return NULL;
    }

    state->init_ctx = init_ctx;
    state->device_id = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, "Starting device enrollment with refresh token\n");

    /* Ensure broker and machine key are initialized */
    if (!init_ctx->broker_initialized || !init_ctx->machine_key_initialized) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Broker or machine key not initialized\n");
        ret = EIO;
        goto immediately;
    }

    if (refresh_token == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "refresh_token is required for device enrollment\n");
        ret = EINVAL;
        goto immediately;
    }

    /* Create enrollment attributes */
    error = enroll_attrs_init(
        init_ctx->domain,
        "SSSD-Device",
        "Linux",
        0,  /* join_type: 0 = Azure AD Join */
        "SSSD",
        &attrs
    );

    if (error || attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialize enrollment attributes\n");
        if (error) {
            error_free(error);
        }
        ret = EIO;
        goto immediately;
    }

    /* Perform device enrollment with refresh_token and machine_key */
    DEBUG(SSSDBG_TRACE_FUNC, "Calling broker_enroll_device\n");
    error = broker_enroll_device(
        init_ctx->broker,
        refresh_token,
        attrs,
        init_ctx->tpm,
        init_ctx->machine_key,
        &transport_key_obj,
        &cert_key_obj,
        &device_id
    );

    if (error) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Device enrollment failed: %s\n", error->msg);
        error_free(error);
        ret = EIO;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Device enrollment succeeded, device_id: %s\n",
          device_id);

    /* Save device enrollment to sysdb */
    ret = himmelblau_sysdb_save_device_enrollment(
        init_ctx->be_ctx->domain,
        device_id,
        init_ctx->auth_value,
        transport_key_obj,
        cert_key_obj);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to save device enrollment to sysdb: %d\n", ret);
        goto immediately;
    }

    /* Store enrollment keys in init_ctx for future use */
    if (init_ctx->transport_key_obj) {
        loadable_ms_oapxbc_rsa_key_free(init_ctx->transport_key_obj);
    }
    if (init_ctx->cert_key_obj) {
        loadable_ms_device_enrollment_key_free(init_ctx->cert_key_obj);
    }
    init_ctx->transport_key_obj = transport_key_obj;
    init_ctx->cert_key_obj = cert_key_obj;
    init_ctx->enrollment_keys_loaded = true;

    /* Copy device_id to talloc context */
    state->device_id = talloc_strdup(state, device_id);
    if (state->device_id == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* Free libhimmelblau-allocated device_id string */
    if (device_id) string_free(device_id);

    /* NOTE: transport_key_obj and cert_key_obj ownership transferred to init_ctx,
     * so they will be freed by the init_ctx destructor */

    ret = EOK;

immediately:
    /* Clean up on error - only if keys were created but not yet transferred to init_ctx */
    if (ret != EOK) {
        if (transport_key_obj && init_ctx->transport_key_obj != transport_key_obj) {
            loadable_ms_oapxbc_rsa_key_free(transport_key_obj);
        }
        if (cert_key_obj && init_ctx->cert_key_obj != cert_key_obj) {
            loadable_ms_device_enrollment_key_free(cert_key_obj);
        }
        if (device_id) {
            string_free(device_id);
        }
    }

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

errno_t
himmelblau_enroll_device_recv(struct tevent_req *req,
                              TALLOC_CTX *mem_ctx,
                              char **_device_id)
{
    struct himmelblau_enroll_device_state *state;

    state = tevent_req_data(req, struct himmelblau_enroll_device_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_device_id != NULL) {
        *_device_id = talloc_steal(mem_ctx, state->device_id);
    }

    return EOK;
}

/* MFA polling timer callback */
static void himmelblau_mfa_poll_done(struct tevent_context *ev,
                                     struct tevent_timer *te,
                                     struct timeval current_time,
                                     void *pvt);

/* MFA authentication */
struct tevent_req *
himmelblau_authenticate_user_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct himmelblau_init_ctx *init_ctx,
                                  struct pam_data *pd,
                                  const char *username,
                                  const char *password)
{
    struct tevent_req *req;
    struct himmelblau_authenticate_user_state *state;
    MSAL_ERROR *error = NULL;
    char *msg = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                           struct himmelblau_authenticate_user_state);
    if (req == NULL) {
        return NULL;
    }

    state->init_ctx = init_ctx;
    state->pd = pd;
    state->ev = ev;
    state->username = talloc_strdup(state, username);
    state->password = talloc_strdup(state, password);
    state->token = NULL;
    state->mfa_continue = NULL;
    state->poll_attempt = 0;
    state->max_poll_attempts = -1;
    state->polling_interval = -1;

    if (state->username == NULL || state->password == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* Set secure destructor to erase password from memory */
    talloc_set_destructor((TALLOC_CTX *)state->password,
                          sss_erase_talloc_mem_securely);

    /* Set destructor */
    talloc_set_destructor(state, himmelblau_authenticate_user_state_destructor);

    DEBUG(SSSDBG_TRACE_FUNC,
          "Starting MFA authentication for user [%s]\n", username);

    /* Ensure broker is initialized */
    if (!init_ctx->broker_initialized) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Broker not initialized\n");
        ret = EIO;
        goto immediately;
    }

    /* Initiate MFA flow */
    error = broker_initiate_acquire_token_by_mfa_flow_for_device_enrollment(
        init_ctx->broker,
        state->username,
        state->password,
        &state->mfa_continue
    );

    if (error || state->mfa_continue == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to initiate MFA flow\n");
        if (error) {
            error_free(error);
        }
        ret = EACCES;
        goto immediately;
    }

    /* Extract MFA continuation details */
    error = mfa_auth_continue_msg(state->mfa_continue, &msg);
    if (error == NULL && msg != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "MFA message: %s\n", msg);
        string_free(msg);
    } else if (error) {
        error_free(error);
        error = NULL;
    }

    state->polling_interval = mfa_auth_continue_polling_interval(state->mfa_continue);
    state->max_poll_attempts = mfa_auth_continue_max_poll_attempts(state->mfa_continue);

    DEBUG(SSSDBG_TRACE_FUNC,
          "MFA flow initiated: polling_interval=%d, max_attempts=%d\n",
          state->polling_interval, state->max_poll_attempts);

    /* Determine MFA type and proceed */
    if (state->polling_interval >= 0) {
        /* Type 1: Polling-based MFA */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Polling-based MFA flow detected, scheduling first poll\n");

        /* Schedule first poll attempt immediately */
        struct tevent_timer *timer;
        struct timeval tv = tevent_timeval_current();

        timer = tevent_add_timer(ev, state, tv,
                                himmelblau_mfa_poll_done, req);
        if (timer == NULL) {
            ret = ENOMEM;
            goto immediately;
        }

        return req;
    } else {
        /* Type 2: User input MFA */
        DEBUG(SSSDBG_TRACE_FUNC,
              "User input MFA flow detected\n");

        /* For initial implementation: Try without auth_data (password-only flow) */
        /* TODO: Implement proper PAM conversation for user input */

        error = broker_acquire_token_by_mfa_flow(
            init_ctx->broker,
            state->username,
            NULL,  /* No additional auth_data for now */
            0,     /* Not polling */
            state->mfa_continue,
            &state->token
        );

        if (error) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "MFA authentication failed\n");
            error_free(error);
            ret = EACCES;
            goto immediately;
        }

        /* Extract and cache tokens */
        char *access_token = NULL;
        char *refresh_token = NULL;

        error = user_token_access_token(state->token, &access_token);
        if (error == NULL && access_token != NULL) {
            state->access_token = talloc_strdup(state, access_token);
            if (state->access_token != NULL) {
                talloc_set_destructor((TALLOC_CTX *)state->access_token,
                                      sss_erase_talloc_mem_securely);
            }
            string_free(access_token);
        } else if (error) {
            error_free(error);
            error = NULL;
        }

        error = user_token_refresh_token(state->token, &refresh_token);
        if (error == NULL && refresh_token != NULL) {
            state->refresh_token = talloc_strdup(state, refresh_token);
            if (state->refresh_token != NULL) {
                talloc_set_destructor((TALLOC_CTX *)state->refresh_token,
                                      sss_erase_talloc_mem_securely);
            }
            string_free(refresh_token);

            /* Cache refresh token */
            himmelblau_sysdb_save_refresh_token(init_ctx->be_ctx->domain,
                                                state->username,
                                                state->refresh_token);
        } else if (error) {
            error_free(error);
            error = NULL;
        }

        DEBUG(SSSDBG_TRACE_FUNC,
              "MFA authentication successful for user [%s]\n", username);

        ret = EOK;
        goto immediately;
    }

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

/* MFA polling timer callback */
static void himmelblau_mfa_poll_done(struct tevent_context *ev,
                                     struct tevent_timer *te,
                                     struct timeval current_time,
                                     void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct himmelblau_authenticate_user_state *state;
    MSAL_ERROR *error = NULL;

    state = tevent_req_data(req, struct himmelblau_authenticate_user_state);

    DEBUG(SSSDBG_TRACE_FUNC,
          "MFA polling attempt %d for user [%s]\n",
          state->poll_attempt + 1, state->username);

    /* Attempt to acquire token by polling */
    error = broker_acquire_token_by_mfa_flow(
        state->init_ctx->broker,
        state->username,
        NULL,  /* No auth_data for polling */
        state->poll_attempt,
        state->mfa_continue,
        &state->token
    );

    if (error == NULL && state->token != NULL) {
        /* Success - user completed MFA */
        DEBUG(SSSDBG_TRACE_FUNC,
              "MFA polling successful for user [%s]\n", state->username);

        /* Extract and cache tokens */
        char *access_token = NULL;
        char *refresh_token = NULL;
        MSAL_ERROR *token_error = NULL;

        token_error = user_token_access_token(state->token, &access_token);
        if (token_error == NULL && access_token != NULL) {
            state->access_token = talloc_strdup(state, access_token);
            if (state->access_token != NULL) {
                talloc_set_destructor((TALLOC_CTX *)state->access_token,
                                      sss_erase_talloc_mem_securely);
            }
            string_free(access_token);
        } else if (token_error) {
            error_free(token_error);
        }

        token_error = user_token_refresh_token(state->token, &refresh_token);
        if (token_error == NULL && refresh_token != NULL) {
            state->refresh_token = talloc_strdup(state, refresh_token);
            if (state->refresh_token != NULL) {
                talloc_set_destructor((TALLOC_CTX *)state->refresh_token,
                                      sss_erase_talloc_mem_securely);
            }
            string_free(refresh_token);

            /* Cache refresh token */
            himmelblau_sysdb_save_refresh_token(state->init_ctx->be_ctx->domain,
                                                state->username,
                                                state->refresh_token);
        } else if (token_error) {
            error_free(token_error);
        }

        tevent_req_done(req);
        return;
    }

    /* Check if we've exceeded max poll attempts */
    state->poll_attempt++;

    if (state->max_poll_attempts >= 0 &&
        state->poll_attempt >= state->max_poll_attempts) {
        DEBUG(SSSDBG_OP_FAILURE,
              "MFA polling timeout after %d attempts\n", state->poll_attempt);
        if (error) {
            error_free(error);
        }
        tevent_req_error(req, ETIMEDOUT);
        return;
    }

    /* Schedule next poll */
    struct tevent_timer *timer;
    struct timeval tv = tevent_timeval_current_ofs(state->polling_interval, 0);

    DEBUG(SSSDBG_TRACE_FUNC,
          "Scheduling next MFA poll in %d seconds\n", state->polling_interval);

    timer = tevent_add_timer(ev, state, tv, himmelblau_mfa_poll_done, req);
    if (timer == NULL) {
        if (error) {
            error_free(error);
        }
        tevent_req_error(req, ENOMEM);
        return;
    }

    if (error) {
        error_free(error);
    }
}

errno_t
himmelblau_authenticate_user_recv(struct tevent_req *req,
                                 TALLOC_CTX *mem_ctx,
                                 UserToken **_token)
{
    struct himmelblau_authenticate_user_state *state;

    state = tevent_req_data(req, struct himmelblau_authenticate_user_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_token != NULL && state->token != NULL) {
        *_token = talloc_steal(mem_ctx, state->token);
        /* Prevent destructor from freeing it */
        state->token = NULL;
    }

    return EOK;
}

/* Forward declarations for callbacks */
static void himmelblau_enroll_done(struct tevent_req *subreq);
static void himmelblau_authenticate_done(struct tevent_req *subreq);

/* PAM handler */
struct tevent_req *
himmelblau_pam_handler_send(TALLOC_CTX *mem_ctx,
                           struct himmelblau_auth_ctx *auth_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct himmelblau_pam_handler_state *state;
    const char *password;
    size_t pw_len;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                           struct himmelblau_pam_handler_state);
    if (req == NULL) {
        return NULL;
    }

    state->pd = pd;
    state->auth_ctx = auth_ctx;
    state->ev = params->ev;
    state->username = NULL;
    state->password = NULL;
    state->device_id = NULL;
    state->device_enrolled = false;
    state->token = NULL;

    /* Set destructor */
    talloc_set_destructor(state, himmelblau_pam_handler_state_destructor);

    DEBUG(SSSDBG_TRACE_FUNC,
          "himmelblau auth handler called for user [%s], command [%d]\n",
          pd->user, pd->cmd);

    /* Only handle authenticate command for now */
    if (pd->cmd != SSS_PAM_AUTHENTICATE) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "himmelblau does not handle PAM command %d\n", pd->cmd);
        pd->pam_status = PAM_MODULE_UNKNOWN;
        goto immediately;
    }

    /* Extract username */
    state->username = talloc_strdup(state, pd->user);
    if (state->username == NULL) {
        pd->pam_status = PAM_BUF_ERR;
        goto immediately;
    }

    /* Extract password from authtok */
    ret = sss_authtok_get_password(pd->authtok, &password, &pw_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get password from authtok: %d\n", ret);
        pd->pam_status = PAM_AUTH_ERR;
        goto immediately;
    }

    state->password = talloc_strndup(state, password, pw_len);
    if (state->password == NULL) {
        pd->pam_status = PAM_BUF_ERR;
        goto immediately;
    }

    /* Set secure destructor to erase password from memory */
    talloc_set_destructor((TALLOC_CTX *)state->password,
                          sss_erase_talloc_mem_securely);

    /* Check device enrollment status (but authenticate regardless) */
    ret = himmelblau_sysdb_check_device_enrolled(auth_ctx->init_ctx->be_ctx->domain,
                                                 &state->device_enrolled);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to check device enrollment: %d\n", ret);
        pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        goto immediately;
    }

    if (state->device_enrolled) {
        DEBUG(SSSDBG_TRACE_FUNC, "Device already enrolled\n");
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Device not yet enrolled, will enroll after authentication\n");
    }

    /* Authenticate user (needed for both enrollment and normal auth) */
    subreq = himmelblau_authenticate_user_send(state, params->ev,
                                               auth_ctx->init_ctx,
                                               pd,
                                               state->username,
                                               state->password);
    if (subreq == NULL) {
        pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;
    }

    tevent_req_set_callback(subreq, himmelblau_authenticate_done, req);
    return req;

immediately:
    tevent_req_done(req);
    tevent_req_post(req, params->ev);
    return req;
}

/* Device enrollment callback */
static void himmelblau_enroll_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct himmelblau_pam_handler_state *state;
    char *device_id = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct himmelblau_pam_handler_state);

    ret = himmelblau_enroll_device_recv(subreq, state, &device_id);
    talloc_free(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Device enrollment failed: %d\n", ret);
        state->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        tevent_req_done(req);
        return;
    }

    state->device_id = device_id;
    state->device_enrolled = true;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Device enrollment successful (ID: %s), completing authentication\n",
          state->device_id);

    /* Authentication already succeeded, enrollment is complete */
    state->pd->pam_status = PAM_SUCCESS;
    tevent_req_done(req);
}

/* Authentication callback */
static void himmelblau_authenticate_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct tevent_req *next_req;
    struct himmelblau_pam_handler_state *state;
    UserToken *token = NULL;
    MSAL_ERROR *error = NULL;
    char *refresh_token = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct himmelblau_pam_handler_state);

    ret = himmelblau_authenticate_user_recv(subreq, state, &token);
    talloc_free(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Authentication failed for user [%s]: %d\n",
              state->username, ret);
        state->pd->pam_status = himmelblau_error_to_pam_status(ret, NULL);
        tevent_req_done(req);
        return;
    }

    state->token = token;

    /* If device not enrolled, enroll it now using the refresh token */
    if (!state->device_enrolled) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Device not enrolled, extracting refresh token for enrollment\n");

        /* Extract refresh token from UserToken */
        error = user_token_refresh_token(token, &refresh_token);
        if (error) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to extract refresh token: %s\n", error->msg);
            error_free(error);
            state->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
            tevent_req_done(req);
            return;
        }

        DEBUG(SSSDBG_TRACE_FUNC,
              "Initiating device enrollment with refresh token\n");

        /* Initiate device enrollment */
        next_req = himmelblau_enroll_device_send(state, state->ev,
                                                  state->auth_ctx->init_ctx,
                                                  refresh_token);
        string_free(refresh_token);

        if (next_req == NULL) {
            state->pd->pam_status = PAM_SYSTEM_ERR;
            tevent_req_done(req);
            return;
        }

        tevent_req_set_callback(next_req, himmelblau_enroll_done, req);
        return;
    }

    /* Device already enrolled, complete authentication */
    state->pd->pam_status = PAM_SUCCESS;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Authentication successful for user [%s]\n", state->username);

    tevent_req_done(req);
}

errno_t
himmelblau_pam_handler_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           struct pam_data **_data)
{
    struct himmelblau_pam_handler_state *state;
    state = tevent_req_data(req, struct himmelblau_pam_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);
    return EOK;
}
