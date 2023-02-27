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
#include "sss_client/pam_message.h"

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

errno_t sss_auth_passkey_calc_size(const char *uv,
                                   const char *key,
                                   const char *pin,
                                   size_t *_passkey_buf_len)
{
    size_t len = 0;

    if (uv == NULL || key == NULL) {
        return EINVAL;
    }

    len += strlen(key) + 1;
    len += strlen(uv) + 1;

    if (pin != NULL) {
        len += strlen(pin) + 1;
    }

    *_passkey_buf_len = len;

    return EOK;
}

errno_t sss_auth_pack_passkey_blob(uint8_t *buf,
                                   const char *uv,
                                   const char *key,
                                   const char *pin)
{
    size_t len = 0;
    size_t key_len;
    size_t uv_len;
    size_t pin_len;

    if (uv == NULL || key == NULL) {
        return EINVAL;
    }

    uv_len = strlen(uv) + 1;
    memcpy(buf + len, uv, uv_len);
    len += uv_len;

    key_len = strlen(key) + 1;
    memcpy(buf + len, key, key_len);
    len += key_len;

    /* Add provided PIN */
    if (pin != NULL) {
        pin_len = strlen(pin) + 1;
    /* User verification is false */
    } else {
        pin = "";
        pin_len = 0;
    }
    memcpy(buf + len, pin, pin_len);

    return EOK;
}

errno_t sss_auth_pack_sc_blob(const char *pin, size_t pin_len,
                              const char *token_name, size_t token_name_len,
                              const char *module_name, size_t module_name_len,
                              const char *key_id, size_t key_id_len,
                              const char *label, size_t label_len,
                              uint8_t *buf, size_t buf_len,
                              size_t *_sc_blob_len)
{
    size_t c;
    uint32_t tmp_uint32_t;

    if (pin_len > UINT32_MAX || token_name_len > UINT32_MAX
            || module_name_len > UINT32_MAX
            || (pin_len != 0 && pin == NULL)
            || (token_name_len != 0 && token_name == NULL)
            || (module_name_len != 0 && module_name == NULL)
            || (key_id_len != 0 && key_id == NULL)
            || (label_len != 0 && label == NULL)) {
        return EINVAL;
    }

    /* A missing pin is ok in the case of a reader with a keyboard */
    if (pin == NULL) {
        pin = "";
        pin_len = 0;
    }

    if (token_name == NULL) {
        token_name = "";
        token_name_len = 0;
    }

    if (module_name == NULL) {
        module_name = "";
        module_name_len = 0;
    }

    if (key_id == NULL) {
        key_id = "";
        key_id_len = 0;
    }

    if (label == NULL) {
        label = "";
        label_len = 0;
    }

    /* len should not include the trailing \0 */
    if (pin_len == 0 || pin[pin_len - 1] == '\0') {
        pin_len = strlen(pin);
    }

    if (token_name_len == 0 || token_name[token_name_len - 1] == '\0') {
        token_name_len = strlen(token_name);
    }

    if (module_name_len == 0 || module_name[module_name_len - 1] == '\0') {
        module_name_len = strlen(module_name);
    }

    if (key_id_len == 0 || key_id[key_id_len - 1] == '\0') {
        key_id_len = strlen(key_id);
    }

    if (label_len == 0 || label[label_len - 1] == '\0') {
        label_len = strlen(label);
    }

    *_sc_blob_len = pin_len + token_name_len + module_name_len + key_id_len
                            + label_len + 5 + 5 * sizeof(uint32_t);
    if (buf == NULL || buf_len < *_sc_blob_len) {
        return EAGAIN;
    }

    c = 0;
    tmp_uint32_t = (uint32_t) pin_len + 1;
    SAFEALIGN_COPY_UINT32(buf, &tmp_uint32_t, &c);
    tmp_uint32_t = (uint32_t) token_name_len + 1;
    SAFEALIGN_COPY_UINT32(buf + c, &tmp_uint32_t, &c);
    tmp_uint32_t = (uint32_t) module_name_len + 1;
    SAFEALIGN_COPY_UINT32(buf + c, &tmp_uint32_t, &c);
    tmp_uint32_t = (uint32_t) key_id_len + 1;
    SAFEALIGN_COPY_UINT32(buf + c, &tmp_uint32_t, &c);
    tmp_uint32_t = (uint32_t) label_len + 1;
    SAFEALIGN_COPY_UINT32(buf + c, &tmp_uint32_t, &c);

    memcpy(buf + c, pin, pin_len);
    buf[c + pin_len] = '\0';
    c += pin_len + 1;

    memcpy(buf + c, token_name, token_name_len);
    buf[c + token_name_len] = '\0';
    c += token_name_len + 1;

    memcpy(buf + c, module_name, module_name_len);
    buf[c + module_name_len] = '\0';
    c += module_name_len + 1;

    memcpy(buf + c, key_id, key_id_len);
    buf[c + key_id_len] = '\0';
    c += key_id_len +1;

    memcpy(buf + c, label, label_len);
    buf[c + label_len] = '\0';

    return 0;
}

const char *sss_auth_get_pin_from_sc_blob(uint8_t *blob, size_t blob_len)
{
    size_t c = 0;
    uint32_t pin_len;
    uint32_t token_name_len;
    uint32_t module_name_len;
    uint32_t key_id_len;
    uint32_t label_len;

    if (blob == NULL || blob_len == 0) {
        return NULL;
    }

    SAFEALIGN_COPY_UINT32(&pin_len, blob, &c);
    if (pin_len == 0) {
        return NULL;
    }

    SAFEALIGN_COPY_UINT32(&token_name_len, blob + c, &c);
    SAFEALIGN_COPY_UINT32(&module_name_len, blob + c, &c);
    SAFEALIGN_COPY_UINT32(&key_id_len, blob + c, &c);
    SAFEALIGN_COPY_UINT32(&label_len, blob + c, &c);

    if (blob_len != 5 * sizeof(uint32_t) + pin_len + token_name_len
                                         + module_name_len + key_id_len
                                         + label_len) {
        return NULL;
    }

    if (blob[c + pin_len - 1] != '\0') {
        return NULL;
    }

    return (const char *) blob + c;
}
