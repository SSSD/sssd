/*
    SSSD

    Kerberos Provider Functions shared by krb5_child and others

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2025 Red Hat

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
#include "util/sss_pam_data.h"
#include "krb5_plugin/idp/idp.h"

errno_t attach_oauth2_info_msg(struct pam_data *pd,
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
