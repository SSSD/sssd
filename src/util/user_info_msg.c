/*
    SSSD

    Pack user info messages

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include "util/user_info_msg.h"
#include "sss_client/sss_cli.h"

errno_t pack_user_info_chpass_error(TALLOC_CTX *mem_ctx,
                                    const char *user_error_message,
                                    size_t *resp_len,
                                    uint8_t **_resp)
{
    uint32_t resp_type = SSS_PAM_USER_INFO_CHPASS_ERROR;
    size_t err_len;
    uint8_t *resp;
    size_t p;

    err_len = strlen(user_error_message);
    *resp_len = 2 * sizeof(uint32_t) + err_len;
    resp = talloc_size(mem_ctx, *resp_len);
    if (resp == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    p = 0;
    SAFEALIGN_SET_UINT32(&resp[p], resp_type, &p);
    SAFEALIGN_SET_UINT32(&resp[p], err_len, &p);
    safealign_memcpy(&resp[p], user_error_message, err_len, &p);
    if (p != *resp_len) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Size mismatch\n");
    }

    *_resp = resp;
    return EOK;
}
