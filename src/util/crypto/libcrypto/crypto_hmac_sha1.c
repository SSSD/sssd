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

#include "util/util.h"
#include "util/crypto/sss_crypto.h"

#include <openssl/evp.h>

#define HMAC_SHA1_BLOCKSIZE 64

int sss_hmac_sha1(const unsigned char *key,
                  size_t key_len,
                  const unsigned char *in,
                  size_t in_len,
                  unsigned char *out)
{
    int ret;
    EVP_MD_CTX ctx;
    unsigned char ikey[HMAC_SHA1_BLOCKSIZE], okey[HMAC_SHA1_BLOCKSIZE];
    size_t i;
    unsigned char hash[SSS_SHA1_LENGTH];
    unsigned int res_len;

    EVP_MD_CTX_init(&ctx);

    if (key_len > HMAC_SHA1_BLOCKSIZE) {
        /* keys longer than blocksize are shortened */
        if (!EVP_DigestInit_ex(&ctx, EVP_sha1(), NULL)) {
            ret = EIO;
            goto done;
        }

        EVP_DigestUpdate(&ctx, (const unsigned char *)key, key_len);
        EVP_DigestFinal_ex(&ctx, ikey, &res_len);
        memset(ikey + SSS_SHA1_LENGTH, 0, HMAC_SHA1_BLOCKSIZE - SSS_SHA1_LENGTH);
    } else {
        /* keys shorter than blocksize are zero-padded */
        memcpy(ikey, key, key_len);
        memset(ikey + key_len, 0, HMAC_SHA1_BLOCKSIZE - key_len);
    }

    /* HMAC(key, msg) = HASH(key XOR opad, HASH(key XOR ipad, msg)) */
    for (i = 0; i < HMAC_SHA1_BLOCKSIZE; i++) {
        okey[i] = ikey[i] ^ 0x5c;
        ikey[i] ^= 0x36;
    }

    if (!EVP_DigestInit_ex(&ctx, EVP_sha1(), NULL)) {
        ret = EIO;
        goto done;
    }

    EVP_DigestUpdate(&ctx, (const unsigned char *)ikey, HMAC_SHA1_BLOCKSIZE);
    EVP_DigestUpdate(&ctx, (const unsigned char *)in, in_len);
    EVP_DigestFinal_ex(&ctx, hash, &res_len);

    if (!EVP_DigestInit_ex(&ctx, EVP_sha1(), NULL)) {
        ret = EIO;
        goto done;
    }

    EVP_DigestUpdate(&ctx, (const unsigned char *)okey, HMAC_SHA1_BLOCKSIZE);
    EVP_DigestUpdate(&ctx, (const unsigned char *)hash, SSS_SHA1_LENGTH);
    EVP_DigestFinal_ex(&ctx, out, &res_len);
    ret = EOK;
done:
    EVP_MD_CTX_cleanup(&ctx);
    return ret;
}
