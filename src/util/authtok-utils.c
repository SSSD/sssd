/*
   SSSD - auth utils helpers

   Copyright (C) Sumit Bose <sbose@redhat.com> 2015

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

/* This file is use by SSSD clients and the main daemons. Please do not add
 * code which is specific to only one of them. */

#include <errno.h>

#include "sss_client/sss_cli.h"

errno_t sss_auth_pack_2fa_blob(const char *fa1, size_t fa1_len,
                               const char *fa2, size_t fa2_len,
                               uint8_t *buf, size_t buf_len,
                               size_t *_2fa_blob_len)
{
    size_t c;
    uint32_t tmp_uint32_t;

    if (fa1 == NULL || *fa1 == '\0' || fa1_len > UINT32_MAX
            || fa2 == NULL || *fa2 == '\0' || fa2_len > UINT32_MAX
            || (buf == NULL && buf_len != 0)) {
        return EINVAL;
    }

    if (fa1_len == 0) {
        fa1_len = strlen(fa1);
    } else {
        if (fa1[fa1_len] != '\0') {
            return EINVAL;
        }
    }

    if (fa2_len == 0) {
        fa2_len = strlen(fa2);
    } else {
        if (fa2[fa2_len] != '\0') {
            return EINVAL;
        }
    }

    *_2fa_blob_len = fa1_len + fa2_len + 2 + 2 * sizeof(uint32_t);
    if (buf == NULL || buf_len < *_2fa_blob_len) {
        return EAGAIN;
    }

    c = 0;
    tmp_uint32_t = (uint32_t) fa1_len + 1;
    SAFEALIGN_COPY_UINT32(buf, &tmp_uint32_t, &c);
    tmp_uint32_t = (uint32_t) fa2_len + 1;
    SAFEALIGN_COPY_UINT32(buf + c, &tmp_uint32_t, &c);

    memcpy(buf + c, fa1, fa1_len + 1);
    c += fa1_len + 1;

    memcpy(buf + c, fa2, fa2_len + 1);

    return 0;
}
