/*
    SSSD

    Himmelblau Provider - Identity handler

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

#include <string.h>

#include "providers/himmelblau/himmelblau_common.h"
#include "providers/backend.h"
#include "db/sysdb.h"
#include "lib/idmap/sss_idmap.h"

/* User lookup by name state */
struct himmelblau_get_user_by_name_state {
    struct himmelblau_id_ctx *id_ctx;
    char *username;
    bool user_exists;
};

/* Account info handler state */
struct himmelblau_account_info_state {
    struct himmelblau_id_ctx *id_ctx;
    struct dp_reply_std reply;
    struct dp_id_data *data;
    char *username;
};

/* Forward declaration for callback */
static void himmelblau_get_user_done(struct tevent_req *subreq);

/* User lookup by name */
struct tevent_req *
himmelblau_get_user_by_name_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct himmelblau_id_ctx *id_ctx,
                                  const char *username)
{
    struct tevent_req *req;
    struct himmelblau_get_user_by_name_state *state;
    MSAL_ERROR *error = NULL;
    bool user_exists = false;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                           struct himmelblau_get_user_by_name_state);
    if (req == NULL) {
        return NULL;
    }

    state->id_ctx = id_ctx;
    state->username = talloc_strdup(state, username);
    state->user_exists = false;

    if (state->username == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Checking user existence for [%s]\n", username);

    /* Ensure broker is initialized */
    if (!id_ctx->init_ctx->broker_initialized) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Broker not initialized\n");
        ret = EIO;
        goto immediately;
    }

    /* Check if user exists in Azure AD */
    error = broker_check_user_exists(
        id_ctx->init_ctx->broker,
        state->username,
        &user_exists
    );

    if (error) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to check user existence\n");
        error_free(error);
        ret = EIO;
        goto immediately;
    }

    state->user_exists = user_exists;

    if (!user_exists) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "User [%s] does not exist in Azure AD\n", username);
        ret = EOK;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "User [%s] exists in Azure AD, storing minimal info in sysdb\n",
          username);

    /* Map username to UID using sss_idmap */
    uid_t uid;
    gid_t gid;
    enum idmap_error_code err;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Mapping user [%s] to POSIX UID using idmap\n", username);

    err = sss_idmap_gen_to_unix(id_ctx->idmap_ctx,
                                id_ctx->domain,
                                username,
                                &uid);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to generate UID for [%s]: %s\n",
              username, idmap_error_string(err));
        ret = EIO;
        goto immediately;
    }

    /* Set GID based on MPG (Magic Private Groups) mode */
    if (id_ctx->be_ctx->domain->mpg_mode != MPG_DISABLED) {
        gid = 0;  /* sysdb will assign primary group */
    } else {
        gid = uid;  /* Traditional UNIX: UID == GID */
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "User [%s] mapped to UID=%u, GID=%u\n", username, uid, gid);

    ret = sysdb_store_user(id_ctx->be_ctx->domain,
                          username,
                          NULL,  /* password */
                          uid,
                          gid,
                          NULL,  /* gecos */
                          NULL,  /* homedir */
                          NULL,  /* shell */
                          NULL,  /* orig_dn */
                          NULL,  /* attrs */
                          NULL,  /* remove_attrs */
                          0,     /* cache_timeout */
                          time(NULL));

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to store user in sysdb: %d\n", ret);
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "User [%s] stored in sysdb successfully\n", username);

    ret = EOK;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

errno_t
himmelblau_get_user_by_name_recv(struct tevent_req *req,
                                 bool *_user_exists)
{
    struct himmelblau_get_user_by_name_state *state;

    state = tevent_req_data(req, struct himmelblau_get_user_by_name_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_user_exists != NULL) {
        *_user_exists = state->user_exists;
    }

    return EOK;
}

/* Account info handler */
struct tevent_req *
himmelblau_account_info_handler_send(TALLOC_CTX *mem_ctx,
                                    struct himmelblau_id_ctx *id_ctx,
                                    struct dp_id_data *data,
                                    struct dp_req_params *params)
{
    struct tevent_req *req;
    struct himmelblau_account_info_state *state;

    req = tevent_req_create(mem_ctx, &state,
                           struct himmelblau_account_info_state);
    if (req == NULL) {
        return NULL;
    }

    state->id_ctx = id_ctx;
    state->data = data;
    state->username = NULL;

    DEBUG(SSSDBG_TRACE_FUNC,
          "himmelblau account info handler called for entry type [%d], "
          "filter type [%d], value [%s]\n",
          data->entry_type & BE_REQ_TYPE_MASK, data->filter_type,
          data->filter_value ? data->filter_value : "(null)");

    /* Dispatch based on entry type */
    switch (data->entry_type & BE_REQ_TYPE_MASK) {
        case BE_REQ_USER:
            if (data->filter_type == BE_FILTER_NAME) {
                /* User lookup by name */
                struct tevent_req *subreq;

                state->username = talloc_strdup(state, data->filter_value);
                if (state->username == NULL) {
                    dp_reply_std_set(&state->reply, DP_ERR_FATAL, ENOMEM,
                                     "Out of memory");
                    goto immediately;
                }

                subreq = himmelblau_get_user_by_name_send(state, params->ev,
                                                          id_ctx,
                                                          state->username);
                if (subreq == NULL) {
                    dp_reply_std_set(&state->reply, DP_ERR_FATAL, ENOMEM,
                                     "Out of memory");
                    goto immediately;
                }

                tevent_req_set_callback(subreq, himmelblau_get_user_done, req);
                return req;
            } else if (data->filter_type == BE_FILTER_IDNUM) {
                /* User lookup by UID - not implemented yet */
                DEBUG(SSSDBG_TRACE_FUNC,
                      "User lookup by UID not implemented\n");
                dp_reply_std_set(&state->reply, DP_ERR_OK, ENOENT,
                                 "User lookup by UID not implemented");
                goto immediately;
            } else if (data->filter_type == BE_FILTER_ENUM) {
                /* User enumeration - not supported */
                DEBUG(SSSDBG_TRACE_FUNC,
                      "User enumeration not supported\n");
                dp_reply_std_set(&state->reply, DP_ERR_OK, ENOTSUP,
                                 "User enumeration not supported");
                goto immediately;
            }
            break;

        case BE_REQ_GROUP:
            /* Group lookup - not implemented yet */
            DEBUG(SSSDBG_TRACE_FUNC, "Group lookup not implemented\n");
            dp_reply_std_set(&state->reply, DP_ERR_OK, ENOTSUP,
                             "Group lookup not implemented");
            goto immediately;

        case BE_REQ_INITGROUPS:
            /* Group membership - not implemented yet */
            DEBUG(SSSDBG_TRACE_FUNC, "Group membership not implemented\n");
            dp_reply_std_set(&state->reply, DP_ERR_OK, ENOTSUP,
                             "Group membership not implemented");
            goto immediately;

        default:
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Unsupported entry type: %d\n", data->entry_type);
            dp_reply_std_set(&state->reply, DP_ERR_OK, ENOTSUP,
                             "Unsupported entry type");
            goto immediately;
    }

    /* Should not reach here */
    dp_reply_std_set(&state->reply, DP_ERR_OK, ENOENT, "Not found");

immediately:
    tevent_req_done(req);
    tevent_req_post(req, params->ev);
    return req;
}

/* User lookup callback */
static void himmelblau_get_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct himmelblau_account_info_state *state;
    bool user_exists;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct himmelblau_account_info_state);

    ret = himmelblau_get_user_by_name_recv(subreq, &user_exists);
    talloc_free(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "User lookup failed for [%s]: %d\n", state->username, ret);
        dp_reply_std_set(&state->reply, DP_ERR_FATAL, ret,
                         "User lookup failed");
    } else if (!user_exists) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "User [%s] not found in Azure AD\n", state->username);
        dp_reply_std_set(&state->reply, DP_ERR_OK, ENOENT,
                         "User not found");
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "User [%s] found and cached\n", state->username);
        dp_reply_std_set(&state->reply, DP_ERR_OK, EOK, NULL);
    }

    tevent_req_done(req);
}

errno_t
himmelblau_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct dp_reply_std *data)
{
    struct himmelblau_account_info_state *state;
    state = tevent_req_data(req, struct himmelblau_account_info_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;
    return EOK;
}
