/*
    SSSD

    IdP Identity Backend Module - evalute authentication replies

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

#include <errno.h>
#include <jansson.h>

#include "util/util.h"
#include "providers/idp/idp_auth.h"
#include "providers/idp/idp_private.h"
#include "krb5_plugin/idp/idp.h"
#include "providers/krb5/krb5_utils.h"

errno_t eval_device_auth_buf(struct idp_auth_ctx *idp_auth_ctx,
                             struct pam_data *pd,
                             uint8_t *buf, ssize_t buflen)
{
    uint8_t *user_reply;
    uint8_t *end;
    struct sss_idp_oauth2 *user_data = NULL;
    int ret;
    struct idp_open_req_data *open_req = NULL;

    user_reply = memchr(buf, '\n', buflen);
    if (user_reply == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing separator in device auth reply.\n");
        return EINVAL;
    }

    *user_reply = '\0';
    user_reply++;

    end = memchr(user_reply, '\n', buflen - (user_reply - buf));
    if (end == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Missing second separator in device auth reply.\n");
        return EINVAL;
    }

    *end = '\0';

    user_data = sss_idp_oauth2_decode((char *) user_reply);
    if (user_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to decode device auth reply.\n");
        ret = EINVAL;
        goto done;
    }

    ret = attach_oauth2_info_msg(pd, user_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to attach device auth user information.\n");
        goto done;
    }

    open_req = talloc_zero(idp_auth_ctx, struct idp_open_req_data);
    if (open_req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to store data to finish authentication.\n");
        ret = ENOMEM;
        goto done;
    }

    open_req->device_code_data = talloc_strdup(open_req, (char *) buf);
    if (open_req->device_code_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy device code data.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sss_ptr_hash_add(idp_auth_ctx->open_request_table,
                           user_data->user_code,
                           open_req, struct idp_open_req_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add device code data [%d][%s].\n",
                                 ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    sss_idp_oauth2_free(user_data);

    if (ret != EOK) {
        talloc_free(open_req);
    }

    return ret;
}

static errno_t store_json_tokens(struct idp_auth_ctx *idp_auth_ctx,
                                 struct pam_data *pd, json_t *token_data) {
    errno_t ret;
    struct sysdb_attrs *attrs = NULL;
    char *access_token = NULL;
    char *id_token = NULL;
    char *refresh_token = NULL;

    struct sss_domain_info *dom = idp_auth_ctx->be_ctx->domain;

    ret = json_unpack(token_data, "{s:s, s?s, s?s}",
                                  "access_token", &access_token,
                                  "id_token", &id_token,
                                  "refresh_token", &refresh_token);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed getting token strings from JSON object.\n");
        ret = EINVAL;
        goto done;
    }

    attrs = sysdb_new_attrs(idp_auth_ctx);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to allocate memory for attributes.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_ACCESS_TOKEN, access_token);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add %s attribute.\n",
                                 SYSDB_ACCESS_TOKEN);
        goto done;
    }

    if (id_token != NULL) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_ID_TOKEN, id_token);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add %s attribute.\n",
                                     SYSDB_ID_TOKEN);
            goto done;
        }
    }

    if (refresh_token != NULL) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_REFRESH_TOKEN, refresh_token);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add %s attribute.\n",
                                     SYSDB_REFRESH_TOKEN);
            goto done;
        }
    }

    ret = sysdb_set_user_attr(dom, pd->user, attrs, SYSDB_MOD_REP);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_set_user_attr failed.\n");
        goto done;
    }

done:
    talloc_free(attrs);

    return ret;
}

errno_t eval_access_token_buf(struct idp_auth_ctx *idp_auth_ctx,
                              struct pam_data *pd, struct sss_domain_info *dom,
                              uint8_t *buf, ssize_t buflen)
{
    int ret;
    const char *attrs[] = {SYSDB_UUID, NULL};
    struct ldb_result *res = NULL;
    const char *uuid;
    uint8_t *user_reply;
    size_t user_reply_len;
    json_error_t json_error;
    json_t *token_data = NULL;

    if (buf == NULL || buflen == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing input.\n");
        return EINVAL;
    }

    user_reply = memchr(buf, '\n', buflen);
    if (user_reply == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing separator in access token reply.\n");
        return EINVAL;
    }
    *user_reply = '\0';
    user_reply++;
    user_reply_len = buflen - (user_reply - buf);
    buflen -= user_reply_len + 1;

    DEBUG(SSSDBG_TRACE_ALL, "Got user_reply=[%.*s] token_buf=[%.*s].\n",
                            (int) user_reply_len, user_reply,
                            (int) buflen, buf);

    token_data = json_loadb((const char *) buf, buflen, 0, &json_error);
    if (token_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse token data on line [%d]: [%s].\n",
              json_error.line, json_error.text);
        ret = EINVAL;
        goto done;
    }

    if (!json_is_object(token_data)) {
        DEBUG(SSSDBG_OP_FAILURE, "Object expected.\n");
        ret = EINVAL;
        goto done;
    }

    ret = sysdb_get_user_attr(idp_auth_ctx, dom, pd->user, attrs, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read cache data for user [%s].\n",
                                 pd->user);
        goto done;
    }

    if (res->count != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Expected 1 user got [%d].\n", res->count);
        ret = EINVAL;
        goto done;
    }

    uuid = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_UUID, NULL);
    if (uuid == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "User [%s] has no UUID attribute.\n",
                                 pd->user);
        ret = EINVAL;
        goto done;
    }

    if (strncmp(uuid, (char *) user_reply, user_reply_len) != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "UUID [%s] of user [%s] and input [%.*s] do not match.\n",
              uuid, pd->user, (int) user_reply_len, user_reply);
        ret = ENOENT;
        goto done;
    }

    ret = store_json_tokens(idp_auth_ctx, pd, token_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to store tokens in cache for user [%s].\n", pd->user);
        goto done;
    }

done:
    json_decref(token_data);
    talloc_free(res);

    return ret;
}
