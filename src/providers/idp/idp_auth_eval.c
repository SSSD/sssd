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
        DEBUG(SSSDBG_OP_FAILURE, "Missing seperator in device auth reply.\n");
        return EINVAL;
    }

    *user_reply = '\0';
    user_reply++;

    end = memchr(user_reply, '\n', buflen - (user_reply - buf));
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

errno_t eval_access_token_buf(struct idp_auth_ctx *idp_auth_ctx,
                              struct pam_data *pd, struct sss_domain_info *dom,
                              uint8_t *buf, ssize_t buflen)
{
    int ret;
    const char *attrs[] = {SYSDB_UUID, NULL};
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
