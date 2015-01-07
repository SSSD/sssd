/*
   SSSD - auth utils helpers

   Copyright (C) Sumit Bose <simo@redhat.com> 2015

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

#ifndef __AUTHTOK_UTILS_H__
#define __AUTHTOK_UTILS_H__

#include <talloc.h>

#include "sss_client/sss_cli.h"

/**
 * @brief Fill memory buffer with 2FA blob
 *
 * @param[in]  fa1       First authentication factor, null terminated
 * @param[in]  fa1_len   Length of the first authentication factor, if 0
 *                       strlen() will be called internally
 * @param[in]  fa2       Second authentication factor, null terminated
 * @param[in]  fa2_len   Length of the second authentication factor, if 0
 *                       strlen() will be called internally
 * @param[in]  buf       memory buffer of size buf_len
 * @param[in]  buf_len   size of memory buffer buf
 *
 * @param[out] _2fa_blob_len size of the 2FA blob
 *
 * @return     EOK       on success
 *             EINVAL    if input data is not consistent
 *             EAGAIN    if provided buffer is too small, _2fa_blob_len
 *                       contains the size needed to store the 2FA blob
 */
errno_t sss_auth_pack_2fa_blob(const char *fa1, size_t fa1_len,
                               const char *fa2, size_t fa2_len,
                               uint8_t *buf, size_t buf_len,
                               size_t *_2fa_blob_len);

/**
 * @brief Extract 2FA data from memory buffer
 *
 * @param[in]  mem_ctx   Talloc memory context to allocate the 2FA data on
 * @param[in]  blob      Memory buffer containing the 2FA data
 * @param[in]  blob_len  Size of the memory buffer
 * @param[out] _fa1      First authentication factor, null terminated
 * @param[out] _fa1_len  Length of the first authentication factor
 * @param[out] _fa2      Second authentication factor, null terminated
 * @param[out] _fa2_len  Length of the second authentication factor
 *
 * @return     EOK       on success
 *             EINVAL    if input data is not consistent
 *             EINVAL    if no memory can be allocated
 */
errno_t sss_auth_unpack_2fa_blob(TALLOC_CTX *mem_ctx,
                                 const uint8_t *blob, size_t blob_len,
                                 char **fa1, size_t *_fa1_len,
                                 char **fa2, size_t *_fa2_len);
#endif /*  __AUTHTOK_UTILS_H__ */
