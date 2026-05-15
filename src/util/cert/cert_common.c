/*
   SSSD - certificate handling utils

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

#include "util/util.h"
#include "util/cert.h"
#include "util/crypto/sss_crypto.h"

errno_t sss_cert_derb64_to_pem(TALLOC_CTX *mem_ctx, const char *derb64,
                               char **pem, size_t *pem_size)
{
    int ret;
    unsigned char *der;
    size_t der_size;

    if (derb64 == NULL) {
        return EINVAL;
    }

    der = sss_base64_decode(mem_ctx, derb64, &der_size);
    if (der == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_base64_decode failed.\n");
        return EINVAL;
    }

    ret = sss_cert_der_to_pem(mem_ctx, der, der_size, pem, pem_size);
    talloc_free(der);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_cert_der_to_pem failed.\n");
    }

    return ret;
}

errno_t sss_cert_pem_to_derb64(TALLOC_CTX *mem_ctx, const char *pem,
                               char **derb64)
{
    int ret;
    uint8_t *der;
    size_t der_size;

    ret = sss_cert_pem_to_der(mem_ctx, pem, &der, &der_size);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_cert_pem_to_der failed.\n");
        return ret;
    }

    *derb64 = sss_base64_encode(mem_ctx, der, der_size);
    talloc_free(der);
    if (*derb64 == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_base64_encode failed.\n");
        return EINVAL;
    }

    return EOK;
}

errno_t bin_to_ldap_filter_value(TALLOC_CTX *mem_ctx,
                                 const uint8_t *blob, size_t blob_size,
                                 char **_str)
{
    int ret;
    size_t c;
    size_t len;
    char *str = NULL;
    char *p;

    if (blob == NULL || blob_size == 0 || _str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing input parameter.\n");
        return EINVAL;
    }

    len = (blob_size * 3) + 1;
    str = talloc_size(mem_ctx, len);
    if (str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }
    str[len - 1] = '\0';

    p = str;
    for (c = 0; c < blob_size; c++) {
        ret = snprintf(p, 4, "\\%02x", blob[c]);
        if (ret != 3) {
            DEBUG(SSSDBG_OP_FAILURE, "snprintf failed.\n");
            ret = EIO;
            goto done;
        }

        p += 3;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *_str = str;
    } else {
        talloc_free(str);
    }

    return ret;
}

errno_t get_ssh_key_from_derb64(TALLOC_CTX *mem_ctx, const char *derb64,
                                uint8_t **key_blob, size_t *key_size)
{
    int ret;
    uint8_t *der_blob;
    size_t der_size;

    der_blob = sss_base64_decode(mem_ctx, derb64, &der_size);
    if (der_blob == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_base64_decode failed.\n");
        return EIO;
    }

    ret = get_ssh_key_from_cert(mem_ctx, der_blob, der_size,
                                key_blob, key_size);
    talloc_free(der_blob);

    return ret;
}
