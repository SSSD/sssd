/*
   SSSD

   NSS crypto wrappers

   Authors:
        Sumit Bose <sbose@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

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

#include <string.h>

#include "config.h"

#include <prinit.h>
#include <nss.h>

#include "util/util.h"
#include "util/crypto/nss/nss_util.h"
#include "util/crypto/nss/nss_crypto.h"

static int nspr_nss_init_done = 0;

int nspr_nss_init(void)
{
    SECStatus sret;

    /* nothing to do */
    if (nspr_nss_init_done == 1) return SECSuccess;

    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);

    sret = NSS_NoDB_Init(NULL);
    if (sret != SECSuccess) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error initializing connection to NSS [%d]\n",
                  PR_GetError());
        return EIO;
    }

    nspr_nss_init_done = 1;
    return EOK;
}

int nspr_nss_cleanup(void)
{
    SECStatus sret;

    /* nothing to do */
    if (nspr_nss_init_done == 0) return SECSuccess;

    sret = NSS_Shutdown();
    if (sret != SECSuccess) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error shutting down connection to NSS [%d]\n",
                  PR_GetError());
        return EIO;
    }

    PR_Cleanup();
    nspr_nss_init_done = 0;
    return EOK;
}

static int sss_nss_crypto_ctx_destructor(struct sss_nss_crypto_ctx *cctx)
{
    if (cctx->ectx) PK11_DestroyContext(cctx->ectx, PR_TRUE);
    if (cctx->sparam) SECITEM_FreeItem(cctx->sparam, PR_TRUE);
    if (cctx->slot) PK11_FreeSlot(cctx->slot);
    if (cctx->keyobj) PK11_FreeSymKey(cctx->keyobj);

    return EOK;
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

static inline int sss_fill_secitem(const uint8_t *sdata, int slen,
                                   SECItem *sitem)
{
    sitem->type = siBuffer;

    /* This is not public function, so no sanity checks of parameters */
    sitem->len = slen;

    if (sdata == NULL) {
        sitem->data = NULL;
    } else {
        sitem->data = talloc_memdup(sitem, sdata, slen);
        if (sitem->data == NULL) {
            return ENOMEM;
        }
    }

    return EOK;
}

int nss_ctx_init(TALLOC_CTX *mem_ctx,
                 struct crypto_mech_data *mech_props,
                 const uint8_t *key, int keylen,
                 const uint8_t *iv, int ivlen,
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

    if (keylen > 0) {
        cctx->key = talloc(cctx, SECItem);
        if (cctx->key == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to allocate Key buffer\n");
            ret = ENOMEM;
            goto done;
        }
        if (key) {
            ret = sss_fill_secitem(key, keylen, cctx->key);
            if (ret != EOK) {
                goto done;
            }
        } else {
            ret = generate_random_key(cctx, cctx->slot,
                                      mech_props, &cctx->key);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Could not generate encryption key\n");
                goto done;
            }
        }

    }

    if (ivlen > 0) {
        cctx->iv = talloc(cctx, SECItem);
        if (cctx->iv == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate IV buffer\n");
            ret = ENOMEM;
            goto done;
        }
        if (iv) {
            ret = sss_fill_secitem(iv, ivlen, cctx->iv);
            if (ret != EOK) {
                goto done;
            }
        } else {
            ret = generate_random_key(cctx, cctx->slot,
                                      mech_props, &cctx->iv);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Could not generate initialization vector\n");
                goto done;
            }
        }
    }

    ret = EOK;
    *_cctx = cctx;
done:
    if (ret) talloc_zfree(cctx);
    return ret;
}

int nss_crypto_init(struct crypto_mech_data *mech_props,
                    enum crypto_mech_op crypto_op,
                    struct sss_nss_crypto_ctx *cctx)
{
    CK_ATTRIBUTE_TYPE op;
    int ret;

    switch (crypto_op) {
    case op_encrypt:
        op = CKA_ENCRYPT;
        break;
    case op_decrypt:
        op = CKA_DECRYPT;
        break;
    case op_sign:
        op = CKA_SIGN;
        break;
    default:
        return EFAULT;
    }

    /* turn the raw key into a key object */
    cctx->keyobj = PK11_ImportSymKey(cctx->slot, mech_props->cipher,
                                     PK11_OriginUnwrap, op, cctx->key, NULL);
    if (cctx->keyobj == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failure to import key into NSS (err %d)\n",
                  PR_GetError());
        ret = EIO;
        goto done;
    }

    if (crypto_op == op_encrypt || crypto_op == op_decrypt) {
        /* turn the raw IV into a initialization vector object */
        cctx->sparam = PK11_ParamFromIV(mech_props->cipher, cctx->iv);
        if (cctx->sparam == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failure to set up PKCS11 param (err %d)\n",
                  PR_GetError());
            ret = EIO;
            goto done;
        }
    } else {
        cctx->sparam = SECITEM_AllocItem(NULL, NULL, 0);
        if (cctx->sparam == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failure to allocate SECItem\n");
            ret = ENOMEM;
            goto done;
        }
        cctx->sparam->type = siBuffer;
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
