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

#include "sss_openssl.h"

struct cipher_mech {
    const EVP_CIPHER * (*cipher)(void);
    const EVP_MD * (*digest)(void);
} mechs[] = {
    { EVP_aes_256_cbc, EVP_sha256 }
};

int sss_encrypt(TALLOC_CTX *mem_ctx, enum encmethod enctype,
                uint8_t *key, size_t keylen,
                const uint8_t *plaintext, size_t plainlen,
                uint8_t **ciphertext, size_t *cipherlen)
{
    const EVP_CIPHER *cipher;
    const EVP_MD *digest;
    EVP_PKEY *hmackey = NULL;
    EVP_CIPHER_CTX *ctx;
    EVP_MD_CTX *mdctx = NULL;
    uint8_t *out = NULL;
    int evpkeylen;
    int evpivlen;
    int hmaclen;
    int outlen, tmplen;
    size_t slen;
    int ret;

    if (!plaintext || !plainlen) return EINVAL;

    if (enctype != AES256CBC_HMAC_SHA256) return EINVAL;
    cipher = mechs[AES256CBC_HMAC_SHA256].cipher();
    digest = mechs[AES256CBC_HMAC_SHA256].digest();

    evpkeylen = EVP_CIPHER_key_length(cipher);
    if (!key || keylen != evpkeylen) return EINVAL;

    hmackey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, keylen);
    if (!hmackey) return ENOMEM;

    /* We have no function to return the size of the output for arbitrary HMAC
     * algorithms so we just truncate to the key size should the hmac be bigger
     * (or pad with zeros should the HMAC be smaller) */
    hmaclen = keylen;

    evpivlen = EVP_CIPHER_iv_length(cipher);
    outlen = plainlen + (2 * EVP_CIPHER_block_size(cipher))
                + evpivlen + hmaclen;
    out = talloc_zero_size(mem_ctx, outlen);

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

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EVP_DigestInit_ex(mdctx, digest, NULL);
    if (ret != 1) {
        ret = EFAULT;
        goto done;
    }

    ret = EVP_DigestSignInit(mdctx, NULL, digest, NULL, hmackey);
    if (ret != 1) {
        ret = EFAULT;
        goto done;
    }

    ret = EVP_DigestSignUpdate(mdctx, out, outlen);
    if (ret != 1) {
        ret = EFAULT;
        goto done;
    }

    slen = hmaclen;
    ret = EVP_DigestSignFinal(mdctx, &out[outlen], &slen);
    if (ret != 1) {
        ret = EFAULT;
        goto done;
    }

    outlen += hmaclen;

    *ciphertext = out;
    *cipherlen = outlen;
    ret = EOK;

done:
    EVP_MD_CTX_free(mdctx);
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(hmackey);
    return ret;
}

int sss_decrypt(TALLOC_CTX *mem_ctx, enum encmethod enctype,
                uint8_t *key, size_t keylen,
                const uint8_t *ciphertext, size_t cipherlen,
                uint8_t **plaintext, size_t *plainlen)
{
    const EVP_CIPHER *cipher;
    const EVP_MD *digest;
    EVP_PKEY *hmackey = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_MD_CTX *mdctx;
    const uint8_t *iv = NULL;
    uint8_t *out;
    int evpkeylen;
    int evpivlen;
    int hmaclen;
    int outlen, tmplen;
    size_t slen;
    int ret;

    if (!ciphertext || !cipherlen) return EINVAL;

    if (enctype != AES256CBC_HMAC_SHA256) return EINVAL;
    cipher = mechs[AES256CBC_HMAC_SHA256].cipher();
    digest = mechs[AES256CBC_HMAC_SHA256].digest();

    evpkeylen = EVP_CIPHER_key_length(cipher);
    if (!key || keylen != evpkeylen) return EINVAL;

    hmackey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, keylen);
    if (!hmackey) return ENOMEM;

    /* We have no function to return the size of the output for arbitray HMAC
     * algorithms so we just assume it was truncated to the key size should
     * the hmac be bigger (or pad with zeros should the HMAC be smaller) */
    hmaclen = keylen;

    evpivlen = EVP_CIPHER_iv_length(cipher);
    out = talloc_zero_size(mem_ctx, cipherlen);

    /* First check HMAC */

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EVP_DigestInit_ex(mdctx, digest, NULL);
    if (ret != 1) {
        ret = EFAULT;
        goto done;
    }

    ret = EVP_DigestSignInit(mdctx, NULL, digest, NULL, hmackey);
    if (ret != 1) {
        ret = EFAULT;
        goto done;
    }

    ret = EVP_DigestSignUpdate(mdctx, ciphertext, cipherlen - hmaclen);
    if (ret != 1) {
        ret = EFAULT;
        goto done;
    }

    slen = hmaclen;
    ret = EVP_DigestSignFinal(mdctx, out, &slen);
    if (ret != 1) {
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
    EVP_MD_CTX_free(mdctx);
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(hmackey);
    return ret;
}
