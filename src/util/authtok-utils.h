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
#include "sss_client/pam_message.h"

/**
 * @brief Fill memory buffer with Smartcard authentication blob
 *
 * @param[in]  pin         PIN, null terminated
 * @param[in]  pin_len     Length of the PIN, if 0
 *                         strlen() will be called internally
 * @param[in]  token_name  Token name, null terminated
 * @param[in]  token_name_len     Length of the token name, if 0
 *                         strlen() will be called internally
 * @param[in]  module_name Name of PKCS#11 module, null terminated
 * @param[in]  module_name_len     Length of the module name, if 0
 *                         strlen() will be called internally
 * @param[in]  key_id      Key ID of the certificate
 * @param[in]  key_id_len  Length of the key id of the certificate, if 0
 *                         strlen() will be called internally
 * @param[in]  label       Label of the certificate
 * @param[in]  label_len   Length of the label of the certificate, if 0
 *                         strlen() will be called internally
 * @param[in]  buf         memory buffer of size buf_len, may be NULL
 * @param[in]  buf_len     size of memory buffer buf
 *
 * @param[out] _sc_blob    len size of the Smartcard authentication blob
 *
 * @return     EOK         on success
 *             EINVAL      if input data is not consistent
 *             EAGAIN      if provided buffer is too small, _sc_blob_len
 *                         contains the size needed to store the SC blob
 */
errno_t sss_auth_pack_sc_blob(const char *pin, size_t pin_len,
                              const char *token_name, size_t token_name_len,
                              const char *module_name, size_t module_name_len,
                              const char *key_id, size_t key_id_len,
                              const char *label, size_t label_len,
                              uint8_t *buf, size_t buf_len,
                              size_t *_sc_blob_len);
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

/**
 * @brief Extract SC data from memory buffer
 *
 * @param[in]  mem_ctx           Talloc memory context to allocate the 2FA
 *                               data on
 * @param[in]  blob              Memory buffer containing the 2FA data
 * @param[in]  blob_len          Size of the memory buffer
 * @param[out] _pin              PIN, null terminated
 * @param[out] _pin_len          Length of the PIN
 * @param[out] _token_name       Token name, null terminated
 * @param[out] _token_name_len   Length of the token name
 * @param[out] _module_name      Name of PKCS#11 module, null terminated
 * @param[out] _module_name_len  Length of the module name
 * @param[out] _key_id           Key ID of the certificate, null terminated
 * @param[out] _key_id_len       Length of the key ID
 * @param[out] _labe l           Label of the certificate, null terminated
 * @param[out] _label_len        Length of the label
 *
 * @return     EOK       on success
 *             EINVAL    if input data is not consistent
 *             EINVAL    if no memory can be allocated
 */
errno_t sss_auth_unpack_sc_blob(TALLOC_CTX *mem_ctx,
                                 const uint8_t *blob, size_t blob_len,
                                 char **pin, size_t *_pin_len,
                                 char **token_name, size_t *_token_name_len,
                                 char **module_name, size_t *_module_name_len,
                                 char **key_id, size_t *_key_id_len,
                                 char **label, size_t *_label_len);

/**
 * @brief Return a pointer to the PIN string in the memory buffer
 *
 * @param[in]  blob              Memory buffer containing the 2FA data
 * @param[in]  blob_len          Size of the memory buffer
 *
 * @return     pointer to 0-terminate PIN string in the memory buffer
 */
const char *sss_auth_get_pin_from_sc_blob(uint8_t *blob, size_t blob_len);

/**
 * @brief Fill memory buffer with Passkey authentication blob
 *
 * @param[in]  buf         Memory buffer containing the Passkey data
 * @param[in]  uv          User verification, "true" or "false"
 * @param[in]  key         Hash table key used to lookup Passkey data
 *                         in the PAM responder.
 * @param[in]  pin         PIN provided by the user. Can be set to
 *                         NULL if no PIN is provided (user verification false)
 *
 * @param[out] _passkey_buf_len  len size of the Passkey authentication blob
 *
 * @return     EOK         on success
 *             EINVAL      if input data is not valid
 */
errno_t sss_auth_pack_passkey_blob(uint8_t *buf,
                                   const char *uv,
                                   const char *key,
                                   const char *pin);
/**
 * @brief Calculate size of Passkey authentication data
 *
 * @param[in]  uv          User verification, "true" or "false"
 * @param[in]  key         Hash table key used to lookup Passkey data
 *                         in the PAM responder.
 * @param[in]  pin         PIN provided by the user. Can be
 *                         Set to NULL if no PIN is
 *                         provided (user verification false)
 *
 * @param[out] _passkey_buf_len  len size of the Passkey authentication blob
 *
 * @return     EOK         on success
 *             EINVAL      if input data is not valid
 */
errno_t sss_auth_passkey_calc_size(const char *uv,
                                   const char *key,
                                   const char *pin,
                                   size_t *_passkey_buf_len);
#endif /*  __AUTHTOK_UTILS_H__ */
