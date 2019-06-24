/*
   SSSD

   Encryption/Decryption primitives

   Authors:
       Simo Sorce <simo@redhat.com>

   Copyright (C) Simo Sorce 2016

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

#include "config.h"
#include <talloc.h>
#include <errno.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <openssl/hmac.h>
#include "sss_openssl.h"

struct cipher_mech {
    const EVP_CIPHER * (*cipher)(void);
    const EVP_MD * (*digest)(void);
} mechs[] = {
    { EVP_aes_256_cbc, EVP_sha256 }
};

int sss_encrypt(TALLOC_CTX *mem_ctx, enum encmethod enctype,
                const uint8_t *key, size_t keylen,
                const uint8_t *plaintext, size_t plainlen,
                uint8_t **ciphertext, size_t *cipherlen)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    const EVP_CIPHER *cipher;
    const EVP_MD *digest;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *out = NULL;
    int evpkeylen;
    int evpivlen;
    unsigned int hmaclen;
    int outlen, tmplen;
    unsigned int slen;
    int ret;

    if (!plaintext || !plainlen || !ciphertext || !cipherlen) return EINVAL;

    if (enctype != AES256CBC_HMAC_SHA256) return EINVAL;
    cipher = mechs[AES256CBC_HMAC_SHA256].cipher();
    digest = mechs[AES256CBC_HMAC_SHA256].digest();

    evpkeylen = EVP_CIPHER_key_length(cipher);
    if (!key || keylen != evpkeylen) return EINVAL;

    /* We have no function to return the size of the output for arbitrary HMAC
     * algorithms so we just truncate to the key size should the hmac be bigger
     * (or pad with zeros should the HMAC be smaller) */
    hmaclen = keylen;

    evpivlen = EVP_CIPHER_iv_length(cipher);
    outlen = plainlen + (2 * EVP_CIPHER_block_size(cipher))
                + evpivlen + hmaclen;
    out = talloc_zero_size(mem_ctx, outlen);
    if (out == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* First Encrypt */

    if (evpivlen != 0) {
        RAND_bytes(out, evpivlen);
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EVP_EncryptInit_ex(ctx, cipher, 0, key, evpivlen ? out : NULL);
    if (ret != 1) {
        ret = EFAULT;
        goto done;
    }

    outlen = evpivlen;
    tmplen = 0;
    ret = EVP_EncryptUpdate(ctx, out + outlen, &tmplen, plaintext, plainlen);
    if (ret != 1) {
        ret = EFAULT;
        goto done;
    }

    outlen += tmplen;

    ret = EVP_EncryptFinal_ex(ctx, out + outlen, &tmplen);
    if (ret != 1) {
        ret = EFAULT;
        goto done;
    }

    outlen += tmplen;

    /* Then HMAC */

    if (!HMAC(digest, key, (int)keylen, out, outlen, md, &slen)) {
        ret = EFAULT;
        goto done;
    }
    memcpy(&out[outlen], md, slen < hmaclen ? slen : hmaclen);
    outlen += hmaclen;

    *ciphertext = out;
    out = NULL;
    *cipherlen = outlen;
    ret = EOK;

done:
    if (out != NULL) {
        talloc_free(out);
    }
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}

int sss_decrypt(TALLOC_CTX *mem_ctx, enum encmethod enctype,
                const uint8_t *key, size_t keylen,
                const uint8_t *ciphertext, size_t cipherlen,
                uint8_t **plaintext, size_t *plainlen)
{
    const EVP_CIPHER *cipher;
    const EVP_MD *digest;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *iv = NULL;
    uint8_t *out;
    int evpkeylen;
    int evpivlen;
    int hmaclen;
    int outlen, tmplen;
    int ret;

    if (!ciphertext || !plaintext || !plainlen) return EINVAL;

    if (enctype != AES256CBC_HMAC_SHA256) return EINVAL;
    cipher = mechs[AES256CBC_HMAC_SHA256].cipher();
    digest = mechs[AES256CBC_HMAC_SHA256].digest();

    evpkeylen = EVP_CIPHER_key_length(cipher);
    if (!key || keylen != evpkeylen) return EINVAL;

    /* We have no function to return the size of the output for arbitray HMAC
     * algorithms so we just assume it was truncated to the key size should
     * the hmac be bigger (or pad with zeros should the HMAC be smaller) */
    hmaclen = keylen;

    evpivlen = EVP_CIPHER_iv_length(cipher);
    if (cipherlen <= (hmaclen + evpivlen)) return EINVAL;

    out = talloc_zero_size(mem_ctx,
                    cipherlen > EVP_MAX_MD_SIZE ? cipherlen : EVP_MAX_MD_SIZE);

    /* First check HMAC */

    if (!HMAC(digest, key, (int)keylen, ciphertext, (int)cipherlen - hmaclen,
              out, NULL)) {
        ret = EFAULT;
        goto done;
    }

    ret = CRYPTO_memcmp(&ciphertext[cipherlen - hmaclen], out, hmaclen);
    if (ret != 0) {
        ret = EFAULT;
        goto done;
    }

    /* Then Decrypt */

    if (evpivlen != 0) {
        iv = ciphertext;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EVP_DecryptInit_ex(ctx, cipher, 0, key, iv);
    if (ret != 1) {
        ret = EFAULT;
        goto done;
    }

    ret = EVP_DecryptUpdate(ctx, out, &outlen,
                            ciphertext + evpivlen,
                            cipherlen - evpivlen - hmaclen);
    if (ret != 1) {
        ret = EFAULT;
        goto done;
    }

    ret = EVP_DecryptFinal_ex(ctx, out + outlen, &tmplen);
    if (ret != 1) {
        ret = EFAULT;
        goto done;
    }

    outlen += tmplen;

    *plaintext = out;
    *plainlen = outlen;
    ret = EOK;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
