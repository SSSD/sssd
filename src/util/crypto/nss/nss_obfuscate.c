/*
   SSSD

   Password obfuscation logic

   Author: Jakub Hrozek <jhrozek@redhat.com>

   Copyright (C) Red Hat, Inc 2010

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
 * way. It is just a mechanism to make the password human-unreadable. If you
 * need to secure passwords in your application, you should probably take a
 * look at storing passwords in NSS-backed database.
 */

#include "config.h"

#include <prerror.h>
#include <nss.h>
#include <pk11func.h>
#include <base64.h>
#include <talloc.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/crypto/nss/nss_util.h"

#define OBF_BUFFER_SENTINEL "\0\1\2\3"
#define OBF_BUFFER_SENTINEL_SIZE    4

#define MAKE_SECITEM(sdata, slen, sitem) do { \
    (sitem)->type = (siBuffer); \
    (sitem)->data = (sdata);    \
    (sitem)->len  = (slen);     \
} while(0)

struct sss_nss_crypto_ctx {
    PK11SlotInfo *slot;
    PK11Context  *ectx;
    PK11SymKey   *keyobj;
    SECItem      *sparam;

    SECItem      *iv;
    SECItem      *key;
};

struct crypto_mech_data {
    CK_MECHANISM_TYPE cipher;
    uint16_t keylen;
    uint16_t bsize;
};

static struct crypto_mech_data cmdata[] = {
    /* AES with automatic padding, 256b key, 128b block */
    { CKM_AES_CBC_PAD, 32, 16 },
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

static int generate_random_key(TALLOC_CTX *mem_ctx,
                               PK11SlotInfo *slot,
                               struct crypto_mech_data *mech_props,
                               SECItem **_key)
{
    SECStatus sret;
    SECItem      *randkeydata;
    SECItem      *key = NULL;
    PK11SymKey   *randkey;
    int ret;

    randkey = PK11_KeyGen(slot, mech_props->cipher,
                          NULL, mech_props->keylen, NULL);
    if (randkey == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failure to generate key (err %d)\n",
                  PR_GetError());
        ret = EIO;
        goto done;
    }

    sret = PK11_ExtractKeyValue(randkey);
    if (sret != SECSuccess) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failure to extract key value (err %d)\n",
                  PR_GetError());
        ret = EIO;
        goto done;
    }

    randkeydata = PK11_GetKeyData(randkey);
    if (randkeydata == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failure to get key data (err %d)\n",
                  PR_GetError());
        ret = EIO;
        goto done;
    }

    /* randkeydata is valid until randkey is. Copy with talloc to
     * get a nice memory hierarchy symmetrical in encrypt
     * and decrypt case */
    key = talloc_zero(mem_ctx, SECItem);
    if (!key) {
        ret = ENOMEM;
        goto done;
    }

    key->data = talloc_memdup(key, randkeydata->data, randkeydata->len);
    if (!key->data) {
        ret = ENOMEM;
        goto done;
    }
    key->len = randkeydata->len;

    *_key = key;
    ret = EOK;
done:
    if (ret != EOK) talloc_zfree(key);
    PK11_FreeSymKey(randkey);
    return ret;
}

static int sss_nss_crypto_ctx_destructor(struct sss_nss_crypto_ctx *cctx)
{
    if (cctx->ectx) PK11_DestroyContext(cctx->ectx, PR_TRUE);
    if (cctx->sparam) SECITEM_FreeItem(cctx->sparam, PR_TRUE);
    if (cctx->slot) PK11_FreeSlot(cctx->slot);
    if (cctx->keyobj) PK11_FreeSymKey(cctx->keyobj);

    return EOK;
}

static int nss_ctx_init(TALLOC_CTX *mem_ctx,
                        struct crypto_mech_data *mech_props,
                        struct sss_nss_crypto_ctx **_cctx)
{
    struct sss_nss_crypto_ctx *cctx;
    int ret;

    cctx = talloc_zero(mem_ctx, struct sss_nss_crypto_ctx);
    if (!cctx) {
        return ENOMEM;
    }
    talloc_set_destructor(cctx, sss_nss_crypto_ctx_destructor);

    cctx->slot = PK11_GetBestSlot(mech_props->cipher, NULL);
    if (cctx->slot == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to find security device (err %d)\n",
                  PR_GetError());
        ret = EIO;
        goto done;
    }

    ret = EOK;
    *_cctx = cctx;
done:
    if (ret) talloc_zfree(cctx);
    return ret;
}

static int nss_encrypt_decrypt_init(struct crypto_mech_data *mech_props,
                                    bool do_encrypt,
                                    struct sss_nss_crypto_ctx *cctx)
{
    CK_ATTRIBUTE_TYPE   op;
    int ret;

    op = do_encrypt ? CKA_ENCRYPT : CKA_DECRYPT;

    /* turn the raw key into a key object */
    cctx->keyobj = PK11_ImportSymKey(cctx->slot, mech_props->cipher,
                                     PK11_OriginUnwrap, op, cctx->key, NULL);
    if (cctx->keyobj == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failure to import key into NSS (err %d)\n",
                  PR_GetError());
        ret = EIO;
        goto done;
    }

    /* turn the raw IV into a initialization vector object */
    cctx->sparam = PK11_ParamFromIV(mech_props->cipher, cctx->iv);
    if (cctx->sparam == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failure to set up PKCS11 param (err %d)\n",
                  PR_GetError());
        ret = EIO;
        goto done;
    }

    /* Create cipher context */
    cctx->ectx = PK11_CreateContextBySymKey(mech_props->cipher, op,
                                            cctx->keyobj, cctx->sparam);
    if (cctx->ectx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create cipher context (err %d)\n",
                  PORT_GetError());
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    return ret;
}

int sss_password_encrypt(TALLOC_CTX *mem_ctx, const char *password, int plen,
                         enum obfmethod meth, char **obfpwd)
{
    SECStatus sret;
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct crypto_mech_data *mech_props;
    struct sss_nss_crypto_ctx *cctx;

    unsigned char *plaintext;

    unsigned char *cryptotext;
    int ct_maxsize;
    int ctlen;
    unsigned int digestlen;
    int result_len;

    unsigned char *obfbuf;
    size_t obufsize = 0;
    size_t p = 0;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* initialize NSS if needed */
    ret = nspr_nss_init();
    if (ret != EOK) {
        ret = EIO;
        goto done;
    }

    mech_props = get_crypto_mech_data(meth);
    if (mech_props == NULL) {
        ret = EINVAL;
        goto done;
    }

    ret = nss_ctx_init(tmp_ctx, mech_props, &cctx);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot initialize NSS context\n");
        goto done;
    }

    /* generate random encryption and IV key */
    ret = generate_random_key(cctx, cctx->slot, mech_props, &cctx->key);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not generate encryption key\n");
        goto done;
    }

    ret = generate_random_key(cctx, cctx->slot, mech_props, &cctx->iv);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not generate initialization vector\n");
        goto done;
    }

    ret = nss_encrypt_decrypt_init(mech_props, true, cctx);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot initialize NSS context properties\n");
        goto done;
    }

    plaintext = (unsigned char *) talloc_strndup(tmp_ctx, password, plen);
    if (!plaintext) {
        ret = ENOMEM;
        goto done;
    }

    /* cryptotext buffer must be at least len(plaintext)+blocksize */
    ct_maxsize = plen + (mech_props->bsize);
    cryptotext = talloc_array(tmp_ctx, unsigned char, ct_maxsize);
    if (!cryptotext) {
        ret = ENOMEM;
        goto done;
    }

    /* sample data we'll encrypt and decrypt */
    sret = PK11_CipherOp(cctx->ectx, cryptotext, &ctlen, ct_maxsize,
                         plaintext, plen);
    if (sret != SECSuccess) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot execute the encryption operation (err %d)\n",
                   PR_GetError());
        ret = EIO;
        goto done;
    }

    sret = PK11_DigestFinal(cctx->ectx, cryptotext+ctlen, &digestlen,
                            ct_maxsize-ctlen);
    if (sret != SECSuccess) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot execute the digest operation (err %d)\n",
                    PR_GetError());
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

    DEBUG(SSSDBG_TRACE_INTERNAL, "Writing method: %d\n", meth);
    SAFEALIGN_SET_UINT16(&obfbuf[p], meth, &p);
    DEBUG(SSSDBG_TRACE_INTERNAL, "Writing bufsize: %d\n", result_len);
    SAFEALIGN_SET_UINT16(&obfbuf[p], result_len, &p);
    safealign_memcpy(&obfbuf[p], cctx->key->data, mech_props->keylen, &p);
    safealign_memcpy(&obfbuf[p], cctx->iv->data, mech_props->bsize, &p);
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
    nspr_nss_cleanup();
    return ret;
}

int sss_password_decrypt(TALLOC_CTX *mem_ctx, char *b64encoded,
                         char **password)
{
    SECStatus sret;
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct crypto_mech_data *mech_props;
    struct sss_nss_crypto_ctx *cctx;

    int plainlen;
    unsigned int digestlen;
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

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* initialize NSS if needed */
    ret = nspr_nss_init();
    if (ret != EOK) {
        ret = EIO;
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
    DEBUG(SSSDBG_TRACE_INTERNAL, "Read method: %d\n", meth);
    SAFEALIGN_COPY_UINT16_CHECK(&ctsize, obfbuf+p, obflen, &p);
    DEBUG(SSSDBG_TRACE_INTERNAL, "Read bufsize: %d\n", ctsize);

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
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Obfuscation buffer seems corrupt, aborting\n");
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

    ret = nss_ctx_init(tmp_ctx, mech_props, &cctx);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot initialize NSS context\n");
        goto done;
    }

    cctx->iv = talloc_zero(cctx, SECItem);
    cctx->key = talloc_zero(cctx, SECItem);
    if (!cctx->iv || !cctx->key) {
        ret = ENOMEM;
        goto done;
    }

    MAKE_SECITEM(ivbuf, mech_props->bsize, cctx->iv);
    MAKE_SECITEM(keybuf, mech_props->keylen, cctx->key);

    ret = nss_encrypt_decrypt_init(mech_props, false, cctx);
    if (ret) {
        goto done;
    }

    pwdbuf = talloc_array(tmp_ctx, char, ctsize);
    if (!pwdbuf) {
        ret = ENOMEM;
        goto done;
    }

    sret = PK11_CipherOp(cctx->ectx, (unsigned char *) pwdbuf, &plainlen, ctsize,
                         cryptotext, ctsize);
    if (sret != SECSuccess) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot execute the encryption operation (err %d)\n",
                   PR_GetError());
        ret = EIO;
        goto done;
    }

    sret = PK11_DigestFinal(cctx->ectx, (unsigned char *) pwdbuf+plainlen, &digestlen,
                            ctsize - plainlen);
    if (sret != SECSuccess) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot execute the encryption operation (err %d)\n",
                   PR_GetError());
        ret = EIO;
        goto done;
    }

    *password = talloc_move(mem_ctx, &pwdbuf);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    nspr_nss_cleanup();
    return ret;
}
