/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>
        George McCollister <george.mccollister@gmail.com>

    Copyright (C) 2012 Red Hat

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

#include "sss_openssl.h"

#include "util/util.h"
#include "util/crypto/sss_crypto.h"


int sss_hmac_sha1(const unsigned char *key, size_t key_len,
                  const unsigned char *in, size_t in_len,
                  unsigned char *out)
{
    int ret = EOK;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t res_len = SSS_SHA1_LENGTH;
    const EVP_MD* md = EVP_sha1();


    if ((key == NULL) || (key_len == 0) || (in == NULL) || (in_len == 0)) {
        return EDOM;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return ENOMEM;
    }

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, key_len);
    if (pkey == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) != 1) {
        ret = EDOM;
        goto done;
    }

    if (EVP_DigestSignUpdate(ctx, in, in_len) != 1) {
        ret = EDOM;
        goto done;
    }

    if ((EVP_DigestSignFinal(ctx, out, &res_len) != 1)
        || (res_len != SSS_SHA1_LENGTH)) {
        ret = EDOM;
        goto done;
    }

done:
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
    return ret;
}
