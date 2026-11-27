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

/* SSS_PAM_OAUTH2_INFO: NUL-terminated strings
 *   verification_uri, verification_uri_complete (may be empty), user_code,
 *   and, for DARC (PA-152 version 2 with a confirmation code), a fourth one
 *   "<charset>:<length>:<delivery>", e.g. "numeric:6:page".
 * Older pam_sss modules ignore the fourth string and fail closed: they send
 * the user_code back, which the IdP does not accept as a confirmation. */
errno_t attach_oauth2_info_msg(struct pam_data *pd,
                               struct sss_idp_oauth2 *data)
{
    uint8_t *msg;
    const char *uri;
    const char *curi;
    const char *user_code;
    char *confirmation = NULL;
    size_t msg_len;
    size_t uri_len = 0;
    size_t curi_len = 0;
    size_t user_code_len = 0;
    size_t confirmation_len = 0;
    size_t idx = 0;
    errno_t ret;

    if (!sss_idp_oauth2_needs_confirmation(data)
            && (data->verification_uri == NULL || data->user_code == NULL)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Empty oauth2 verification_uri or user_code\n");
        return EINVAL;
    }

    uri = data->verification_uri != NULL ? data->verification_uri : "";
    curi = data->verification_uri_complete != NULL
                ? data->verification_uri_complete : "";
    user_code = data->user_code != NULL ? data->user_code : "";

    uri_len = strlen(uri) + 1;
    curi_len = strlen(curi) + 1;
    user_code_len = strlen(user_code) + 1;
    msg_len = uri_len + curi_len + user_code_len;

    if (sss_idp_oauth2_needs_confirmation(data)) {
        confirmation = talloc_asprintf(NULL, "%s:%d:%s",
                data->confirmation_charset != NULL
                        ? data->confirmation_charset : "numeric",
                data->confirmation_length,
                data->delivery != NULL ? data->delivery : "page");
        if (confirmation == NULL) {
            return ENOMEM;
        }
        confirmation_len = strlen(confirmation) + 1;
        msg_len += confirmation_len;
    }

    msg = talloc_zero_size(NULL, msg_len);
    if (msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        talloc_free(confirmation);
        return ENOMEM;
    }

    memcpy(msg, uri, uri_len);
    idx += uri_len;

    memcpy(msg + idx, curi, curi_len);
    idx += curi_len;

    memcpy(msg + idx, user_code, user_code_len);
    idx += user_code_len;

    if (confirmation != NULL) {
        memcpy(msg + idx, confirmation, confirmation_len);
    }

    ret = pam_add_response(pd, SSS_PAM_OAUTH2_INFO, msg_len, msg);
    talloc_zfree(msg);
    talloc_free(confirmation);

    return ret;
}

/* end of copy from src/providers/krb5/krb5_child.c */
