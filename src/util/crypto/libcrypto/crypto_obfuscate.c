/*
   SSSD

   Password obfuscation logic

   Authors:
       George McCollister <george.mccollister@gmail.com>

   Copyright (C) George McCollister 2012

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

/*
 * READ ME:
 *
 * Please note that password obfuscation does not improve security in any
 * way. It is just a mechanism to make the password human-unreadable.
 */

#include "config.h"
#include <talloc.h>
#include <errno.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#define OBF_BUFFER_SENTINEL "\0\1\2\3"
#define OBF_BUFFER_SENTINEL_SIZE    4

struct crypto_mech_data {
    const EVP_CIPHER * (*cipher)(void);
    uint16_t keylen;
    uint16_t bsize;
};

static struct crypto_mech_data cmdata[] = {
    /* AES with automatic padding, 256b key, 128b block */
    { EVP_aes_256_cbc, 32, 16 },
    /* sentinel */
    { 0, 0, 0 }
};

static struct crypto_mech_data *get_crypto_mech_data(enum obfmethod meth)
{
    if (meth >= NUM_OBFMETHODS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported cipher type\n");
        return NULL;
    }
    return &cmdata[meth];
}

int sss_password_encrypt(TALLOC_CTX *mem_ctx, const char *password, int plen,
                         enum obfmethod meth, char **obfpwd)
{
    int ret;
    EVP_CIPHER_CTX *ctx;
    struct crypto_mech_data *mech_props;
    TALLOC_CTX *tmp_ctx = NULL;
    unsigned char *keybuf;
    unsigned char *ivbuf;
    unsigned char *cryptotext;
    int ct_maxsize;
    int ctlen = 0;
    int digestlen = 0;
    int result_len;

    unsigned char *obfbuf;
    size_t obufsize = 0;
    size_t p = 0;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    mech_props = get_crypto_mech_data(meth);
    if (mech_props == NULL) {
        ret = EINVAL;
        goto done;
    }

    keybuf = talloc_array(tmp_ctx, unsigned char, mech_props->keylen);
    if (keybuf == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ivbuf = talloc_array(tmp_ctx, unsigned char, mech_props->bsize);
    if (ivbuf == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_generate_csprng_buffer((uint8_t *)keybuf, mech_props->keylen);
    if (ret != EOK) {
        goto done;
    }
    ret = sss_generate_csprng_buffer((uint8_t *)ivbuf, mech_props->bsize);
    if (ret != EOK) {
        goto done;
    }

    /* cryptotext buffer must be at least len(plaintext)+blocksize */
    ct_maxsize = plen + (mech_props->bsize);
    cryptotext = talloc_array(tmp_ctx, unsigned char, ct_maxsize);
    if (!cryptotext) {
        ret = ENOMEM;
        goto done;
    }

    if (!EVP_EncryptInit_ex(ctx, mech_props->cipher(), 0, keybuf, ivbuf)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failure to initialize cipher contex\n");
        ret = EIO;
        goto done;
    }

    /* sample data we'll encrypt and decrypt */
    if (!EVP_EncryptUpdate(ctx, cryptotext, &ctlen, (const unsigned char *)password, plen)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot execute the encryption operation\n");
        ret = EIO;
        goto done;
    }

    if (!EVP_EncryptFinal_ex(ctx, cryptotext + ctlen, &digestlen)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot finialize the encryption operation\n");
        ret = EIO;
        goto done;
    }

    result_len = ctlen + digestlen;
    if (result_len < 0 || result_len > UINT16_MAX) {
        ret = ERANGE;
        goto done;
    }

    /* Pack the obfuscation buffer */
    /* The buffer consists of:
     * uint16_t      the type of the cipher
     * uint16_t      length of the cryptotext in bytes (clen)
     * uint8_t[klen] key
     * uint8_t[blen] IV
     * uint8_t[clen] cryptotext
     * 4 bytes of "sentinel" denoting end of the buffer
     */
    obufsize = sizeof(uint16_t) + sizeof(uint16_t) +
               mech_props->keylen + mech_props->bsize +
               result_len + OBF_BUFFER_SENTINEL_SIZE;
    obfbuf = talloc_array(tmp_ctx, unsigned char, obufsize);
    if (!obfbuf) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Writing method: %d\n", meth);
    SAFEALIGN_SET_UINT16(&obfbuf[p], meth, &p);
    DEBUG(SSSDBG_TRACE_FUNC, "Writing bufsize: %d\n", result_len);
    SAFEALIGN_SET_UINT16(&obfbuf[p], result_len, &p);
    safealign_memcpy(&obfbuf[p], keybuf, mech_props->keylen, &p);
    safealign_memcpy(&obfbuf[p], ivbuf, mech_props->bsize, &p);
    safealign_memcpy(&obfbuf[p], cryptotext, result_len, &p);
    safealign_memcpy(&obfbuf[p], OBF_BUFFER_SENTINEL,
                     OBF_BUFFER_SENTINEL_SIZE, &p);

    /* Base64 encode the resulting buffer */
    *obfpwd = sss_base64_encode(mem_ctx, obfbuf, obufsize);
    if (*obfpwd == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int sss_password_decrypt(TALLOC_CTX *mem_ctx, char *b64encoded,
                         char **password)
{
    int ret;
    EVP_CIPHER_CTX *ctx;
    TALLOC_CTX *tmp_ctx = NULL;
    struct crypto_mech_data *mech_props;

    int plainlen;
    int digestlen;
    unsigned char *obfbuf = NULL;
    size_t obflen;
    char *pwdbuf;

    /* for unmarshaling data */
    uint16_t meth;
    uint16_t ctsize;
    size_t p = 0;
    unsigned char *cryptotext;
    unsigned char *keybuf;
    unsigned char *ivbuf;
    unsigned char sentinel_check[OBF_BUFFER_SENTINEL_SIZE];

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Base64 decode the incoming buffer */
    obfbuf = sss_base64_decode(tmp_ctx, b64encoded, &obflen);
    if (!obfbuf) {
        ret = ENOMEM;
        goto done;
    }

    /* unpack obfuscation buffer */
    SAFEALIGN_COPY_UINT16_CHECK(&meth, obfbuf+p, obflen, &p);
    DEBUG(SSSDBG_TRACE_FUNC, "Read method: %d\n", meth);
    SAFEALIGN_COPY_UINT16_CHECK(&ctsize, obfbuf+p, obflen, &p);
    DEBUG(SSSDBG_TRACE_FUNC, "Read bufsize: %d\n", ctsize);

    mech_props = get_crypto_mech_data(meth);
    if (mech_props == NULL) {
        ret = EINVAL;
        goto done;
    }

    /* check that we got sane mechanism properties and cryptotext size */
    memcpy(sentinel_check,
           obfbuf + p + mech_props->keylen + mech_props->bsize + ctsize,
           OBF_BUFFER_SENTINEL_SIZE);
    if (memcmp(sentinel_check, OBF_BUFFER_SENTINEL, OBF_BUFFER_SENTINEL_SIZE) != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Obfuscation buffer seems corrupt, aborting\n");
        ret = EFAULT;
        goto done;
    }

    /* copy out key, ivbuf and cryptotext */
    keybuf = talloc_array(tmp_ctx, unsigned char, mech_props->keylen);
    if (keybuf == NULL) {
        ret = ENOMEM;
        goto done;
    }
    safealign_memcpy(keybuf, obfbuf+p, mech_props->keylen, &p);

    ivbuf = talloc_array(tmp_ctx, unsigned char, mech_props->bsize);
    if (ivbuf == NULL) {
        ret = ENOMEM;
        goto done;
    }
    safealign_memcpy(ivbuf, obfbuf+p, mech_props->bsize, &p);

    cryptotext = talloc_array(tmp_ctx, unsigned char, ctsize);
    if (cryptotext == NULL) {
        ret = ENOMEM;
        goto done;
    }
    safealign_memcpy(cryptotext, obfbuf+p, ctsize, &p);

    pwdbuf = talloc_array(tmp_ctx, char, ctsize);
    if (!pwdbuf) {
        ret = ENOMEM;
        goto done;
    }

    if (!EVP_DecryptInit_ex(ctx, mech_props->cipher(), 0, keybuf, ivbuf)) {
        ret = EIO;
        goto done;
    }

    /* sample data we'll encrypt and decrypt */
    if (!EVP_DecryptUpdate(ctx, (unsigned char *)pwdbuf, &plainlen, cryptotext, ctsize)) {
        ret = EIO;
        goto done;
    }

    if (!EVP_DecryptFinal_ex(ctx, (unsigned char *)pwdbuf + plainlen, &digestlen)) {
        ret = EIO;
        goto done;
    }

    *password = talloc_move(mem_ctx, &pwdbuf);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
