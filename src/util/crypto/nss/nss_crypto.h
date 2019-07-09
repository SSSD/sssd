/*
   SSSD

   NSS crypto wrappers

   Authors:
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

#include <nss.h>
#include <prerror.h>
#include <pk11func.h>
#include <base64.h>
#include <talloc.h>

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

enum crypto_mech_op {
    op_encrypt,
    op_decrypt,
    op_sign
};

int nss_ctx_init(TALLOC_CTX *mem_ctx,
                 struct crypto_mech_data *mech_props,
                 const uint8_t *key, int keylen,
                 const uint8_t *iv, int ivlen,
                 struct sss_nss_crypto_ctx **_cctx);
int nss_crypto_init(struct crypto_mech_data *mech_props,
                    enum crypto_mech_op crypto_op,
                    struct sss_nss_crypto_ctx *cctx);
