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

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/crypto/nss/nss_util.h"
#include "util/crypto/nss/nss_crypto.h"

struct cipher_mech {
    struct crypto_mech_data enc;
    struct crypto_mech_data hmac;
} mechs[] = {
    { { CKM_AES_CBC_PAD, 32, 16 }, { CKM_SHA256_HMAC, 32, 16 } }
};

int sss_encrypt(TALLOC_CTX *mem_ctx, enum encmethod enctype,
                uint8_t *key, size_t keylen,
                const uint8_t *plaintext, size_t plainlen,
                uint8_t **ciphertext, size_t *cipherlen)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sss_nss_crypto_ctx *cctx;
    struct sss_nss_crypto_ctx *hctx;
    struct crypto_mech_data *enc;
    struct crypto_mech_data *hmac;
    SECStatus sret;
    uint8_t *out = NULL;
    int ivlen;
    int hmaclen;
    int outlen;
    int clen;
    union {
        unsigned int u;
        int s;
    } tmplen;
    unsigned int digestlen;
    int ret;

    if (!plaintext || !plainlen) return EINVAL;

    if (enctype != AES256CBC_HMAC_SHA256) return EINVAL;
    enc = &mechs[AES256CBC_HMAC_SHA256].enc;
    hmac = &mechs[AES256CBC_HMAC_SHA256].hmac;
    ivlen = enc->bsize;

    /* We have no function to return the size of the output for arbitray HMAC
     * algorithms so we just truncate to the key size should the hmac be bigger
     * (or pad with zeros should the HMAC be smaller) */
    hmaclen = keylen;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* initialize NSS if needed */
    ret = nspr_nss_init();
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }

    outlen = plainlen + (2 * enc->bsize) + ivlen + hmaclen;
    out = talloc_zero_size(tmp_ctx, outlen);

    /* First Encrypt */

    if (ivlen != 0) {
        ret = generate_csprng_buffer(out, ivlen);
        if (ret) return ret;
    }

    ret = nss_ctx_init(tmp_ctx, enc, key, keylen, out, ivlen, &cctx);
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }

    ret = nss_crypto_init(enc, op_encrypt, cctx);
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }

    clen = ivlen;

    sret = PK11_CipherOp(cctx->ectx, out + clen, &tmplen.s,
                         outlen - clen, plaintext, plainlen);
    if (sret != SECSuccess) {
        ret = EFAULT;
        goto done;
    }

    clen += tmplen.s;

    sret = PK11_DigestFinal(cctx->ectx, out + clen, &tmplen.u, outlen - clen);
    if (sret != SECSuccess) {
        ret = EFAULT;
        goto done;
    }

    clen += tmplen.u;
    if (clen < 0 || clen > UINT16_MAX) {
        ret = ERANGE;
        goto done;
    }

    /* Then HMAC */

    ret = nss_ctx_init(tmp_ctx, hmac, key, keylen, NULL, 0, &hctx);
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }

    ret = nss_crypto_init(hmac, op_sign, hctx);
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }

    sret = PK11_DigestBegin(hctx->ectx);
    if (sret != SECSuccess) {
        ret = EFAULT;
        goto done;
    }

    sret = PK11_DigestOp(hctx->ectx, out, clen);
    if (sret != SECSuccess) {
        ret = EFAULT;
        goto done;
    }

    sret = PK11_DigestFinal(hctx->ectx, out + clen, &digestlen,
                            outlen - clen);
    if (sret != SECSuccess) {
        ret = EFAULT;
        goto done;
    }

    *ciphertext = talloc_move(mem_ctx, &out);
    *cipherlen = clen + hmaclen;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sss_decrypt(TALLOC_CTX *mem_ctx, enum encmethod enctype,
                uint8_t *key, size_t keylen,
                const uint8_t *ciphertext, size_t cipherlen,
                uint8_t **plaintext, size_t *plainlen)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sss_nss_crypto_ctx *cctx;
    struct sss_nss_crypto_ctx *hctx;
    struct crypto_mech_data *enc;
    struct crypto_mech_data *hmac;
    SECStatus sret;
    uint8_t *out = NULL;
    uint8_t *ivbuf = NULL;
    int ivlen;
    int hmaclen;
    int outlen;
    unsigned int tmplen;
    unsigned int digestlen;
    int ret;

    if (!plaintext || !plainlen) return EINVAL;

    if (enctype != AES256CBC_HMAC_SHA256) return EINVAL;
    enc = &mechs[AES256CBC_HMAC_SHA256].enc;
    hmac = &mechs[AES256CBC_HMAC_SHA256].hmac;
    ivlen = enc->bsize;

    /* We have no function to return the size of the output for arbitray HMAC
     * algorithms so we just truncate to the key size should the hmac be bigger
     * (or pad with zeros should the HMAC be smaller) */
    hmaclen = keylen;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* initialize NSS if needed */
    ret = nspr_nss_init();
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }

    out = talloc_zero_size(tmp_ctx, cipherlen);

    /* First check HMAC */

    ret = nss_ctx_init(tmp_ctx, hmac, key, keylen, NULL, 0, &hctx);
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }

    ret = nss_crypto_init(hmac, op_sign, hctx);
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }

    sret = PK11_DigestBegin(hctx->ectx);
    if (sret != SECSuccess) {
        ret = EFAULT;
        goto done;
    }

    sret = PK11_DigestOp(hctx->ectx, ciphertext, cipherlen - hmaclen);
    if (sret != SECSuccess) {
        ret = EFAULT;
        goto done;
    }

    sret = PK11_DigestFinal(hctx->ectx, out, &digestlen, hmaclen);
    if (sret != SECSuccess) {
        ret = EFAULT;
        goto done;
    }

    ret = NSS_SecureMemcmp(&ciphertext[cipherlen - hmaclen], out, hmaclen);
    if (ret != 0) {
        ret = EFAULT;
        goto done;
    }

    /* Then Decrypt */

    if (ivlen != 0) {
        ivbuf = talloc_size(tmp_ctx, ivlen);
        if (!ivbuf) {
            ret = ENOMEM;
            goto done;
        }
        memcpy(ivbuf, ciphertext, ivlen);
    }

    ret = nss_ctx_init(tmp_ctx, enc, key, keylen, ivbuf, ivlen, &cctx);
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }

    ret = nss_crypto_init(enc, op_decrypt, cctx);
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }

    sret = PK11_CipherOp(cctx->ectx, out, &outlen, cipherlen,
                         ciphertext + ivlen, cipherlen - ivlen - hmaclen);
    if (sret != SECSuccess) {
        ret = EFAULT;
        goto done;
    }

    sret = PK11_DigestFinal(cctx->ectx, out + outlen, &tmplen,
                            cipherlen - outlen);
    if (sret != SECSuccess) {
        ret = EFAULT;
        goto done;
    }

    outlen += tmplen;

    *plaintext = talloc_move(mem_ctx, &out);
    *plainlen = outlen;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
