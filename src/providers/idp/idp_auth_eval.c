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

/* The following is a 1:1 copy from src/krb5_plugin/idp/idp_utils.c, let's see
 * what would be the best way to make it public. */

#include "krb5_plugin/idp/idp.h"
#include "krb5_plugin/common/utils.h"

void
sss_idp_oauth2_free(struct sss_idp_oauth2 *data)
{
    if (data == NULL) {
        return;
    }

    free(data->verification_uri);
    free(data->verification_uri_complete);
    free(data->user_code);
    free(data);
}

static struct sss_idp_oauth2 *
sss_idp_oauth2_init(const char *verification_uri,
                    const char *verification_uri_complete,
                    const char *user_code)
{
    struct sss_idp_oauth2 *data;

    /* These are required fields. */
    if (is_empty(verification_uri) || is_empty(user_code)) {
        return NULL;
    }

    data = malloc(sizeof(struct sss_idp_oauth2));
    if (data == NULL) {
        return NULL;
    }
    memset(data, 0, sizeof(struct sss_idp_oauth2));

    data->verification_uri = strdup(verification_uri);
    data->user_code = strdup(user_code);
    if (data->verification_uri == NULL || data->user_code == NULL) {
        sss_idp_oauth2_free(data);
        return NULL;
    }

    if (!is_empty(verification_uri_complete)) {
        data->verification_uri_complete = strdup(verification_uri_complete);
        if (data->verification_uri_complete == NULL) {
            sss_idp_oauth2_free(data);
            return NULL;
        }
    }

    return data;
}

static struct sss_idp_oauth2 *
sss_idp_oauth2_from_json(const char *json_str)
{
    struct sss_idp_oauth2 jdata = {0};
    struct sss_idp_oauth2 *data;
    json_error_t jret;
    json_t *jroot;
    int ret;

    jroot = json_loads(json_str, 0, &jret);
    if (jroot == NULL) {
        return NULL;
    }

    ret = json_unpack(jroot, "{s:s, s?:s, s:s}",
                "verification_uri", &jdata.verification_uri,
                "verification_uri_complete", &jdata.verification_uri_complete,
                "user_code", &jdata.user_code);
    if (ret != 0) {
        json_decref(jroot);
        return NULL;
    }

    data = sss_idp_oauth2_init(jdata.verification_uri,
                               jdata.verification_uri_complete,
                               jdata.user_code);

    json_decref(jroot);
    return data;
}


static struct sss_idp_oauth2 *
sss_idp_oauth2_decode(const char *str)
{
    return sss_radius_message_decode(SSSD_IDP_OAUTH2_PREFIX,
        (sss_radius_message_decode_fn)sss_idp_oauth2_from_json, str);
}
/* end of copy from src/krb5_plugin/idp/idp_utils.c */

/* The following is a 1:1 copy from src/providers/krb5/krb5_child.c with a
 * small change in the first parameter, let's see what would be the best way
 * to make it public. */

static errno_t k5c_attach_oauth2_info_msg(struct pam_data *pd,
                                          struct sss_idp_oauth2 *data)
{
    uint8_t *msg;
    const char *curi;
    size_t msg_len;
    size_t uri_len = 0;
    size_t curi_len = 0;
    size_t user_code_len = 0;
    size_t idx = 0;
    errno_t ret;

    if (data->verification_uri == NULL || data->user_code == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Empty oauth2 verification_uri or user_code\n");
        return EINVAL;
    }

    msg_len = 0;

    uri_len = strlen(data->verification_uri) + 1;
    msg_len += uri_len;

    if (data->verification_uri_complete != NULL) {
        curi = data->verification_uri_complete;
        curi_len = strlen(curi) + 1;
    } else {
        curi = "";
        curi_len = 1;
    }
    msg_len += curi_len;

    user_code_len = strlen(data->user_code) + 1;
    msg_len += user_code_len;

    msg = talloc_zero_size(NULL, msg_len);
    if (msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    memcpy(msg, data->verification_uri, uri_len);
    idx += uri_len;

    memcpy(msg + idx, curi, curi_len);
    idx += curi_len;

    memcpy(msg + idx, data->user_code, user_code_len);

    ret = pam_add_response(pd, SSS_PAM_OAUTH2_INFO, msg_len, msg);
    talloc_zfree(msg);

    return ret;
}

/* end of copy from src/providers/krb5/krb5_child.c */

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
        DEBUG(SSSDBG_OP_FAILURE, "Missing seperator in device auth reply.\n");
        return EINVAL;
    }

    *user_reply = '\0';
    user_reply++;

    end = memchr(user_reply, '\n', buflen - (user_reply - 1 - buf));
    if (end == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Missing second seperator in device auth reply.\n");
        return EINVAL;
    }

    *end = '\0';

    user_data = sss_idp_oauth2_decode((char *) user_reply);
    if (user_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to decode device auth reply.\n");
        ret = EINVAL;
        goto done;
    }

    ret = k5c_attach_oauth2_info_msg(pd, user_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to attach device auth user information.\n");
        goto done;
    }

    /* TODO: add first part of buf to a hash so it can be used during
     * SSS_PAM_AUTHENTICATE. */
    open_req = talloc_zero(idp_auth_ctx, struct idp_open_req_data);
    if (open_req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to store data to finish authentication.\n");
        ret = ENOMEM;
        goto done;
    }

    open_req->device_code_data = talloc_strdup(open_req, (char *) buf);
    if (open_req->device_code_data == NULL) {
        talloc_free(open_req);
        ret = ENOMEM;
        goto done;
    }

    ret = sss_ptr_hash_add(idp_auth_ctx->open_request_table,
                           user_data->user_code,
                           open_req, struct idp_open_req_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add device code data [%d][%s].\n",
                                 ret, sss_strerror(ret));
        talloc_free(open_req);
        goto done;
    }

    ret = EOK;
done:
    sss_idp_oauth2_free(user_data);

    return ret;
}

errno_t eval_access_token_buf(struct idp_auth_ctx *idp_auth_ctx,
                              struct pam_data *pd, struct sss_domain_info *dom,
                              uint8_t *buf, ssize_t buflen)
{
    int ret;
    const char *attrs[] = {SYSDB_NAME, SYSDB_UUID, NULL};
    struct ldb_result *res = NULL;
    const char *uuid;

    /* TODO: expect access token as well */

    if (buf == NULL || buflen == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing input.\n");
        return EINVAL;
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

    if (strncmp(uuid, (char *) buf, buflen) != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "UUID [%s] of user [%s] and input [%.*s] do not match.\n",
              uuid, pd->user, (int) buflen, buf);
        ret = ENOENT;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(res);

    return ret;
}
