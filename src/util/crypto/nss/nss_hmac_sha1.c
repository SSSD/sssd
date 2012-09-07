/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

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
/*
    NSS does not provide public API for HMAC, so we implement it ourselves.

    See RFC 2104 for details on the algorithm.
*/

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/crypto/nss/nss_util.h"

#include <sechash.h>

#define HMAC_SHA1_BLOCKSIZE 64

int sss_hmac_sha1(const unsigned char *key,
                  size_t key_len,
                  const unsigned char *in,
                  size_t in_len,
                  unsigned char *out)
{
    int ret;
    unsigned char ikey[HMAC_SHA1_BLOCKSIZE], okey[HMAC_SHA1_BLOCKSIZE];
    size_t i;
    HASHContext *sha1;
    unsigned char hash[SSS_SHA1_LENGTH];
    unsigned int res_len;

    ret = nspr_nss_init();
    if (ret != EOK) {
        return ret;
    }

    sha1 = HASH_Create(HASH_AlgSHA1);
    if (!sha1) {
        return ENOMEM;
    }

    if (key_len > HMAC_SHA1_BLOCKSIZE) {
        /* keys longer than blocksize are shortened */
        HASH_Begin(sha1);
        HASH_Update(sha1, key, key_len);
        HASH_End(sha1, ikey, &res_len, SSS_SHA1_LENGTH);
        memset(ikey + SSS_SHA1_LENGTH, 0, HMAC_SHA1_BLOCKSIZE - SSS_SHA1_LENGTH);
    } else {
        /* keys shorter than blocksize are zero-padded */
        memcpy(ikey, key, key_len);
        if (key_len != HMAC_SHA1_BLOCKSIZE) {
            memset(ikey + key_len, 0, HMAC_SHA1_BLOCKSIZE - key_len);
        }
    }

    /* HMAC(key, msg) = HASH(key XOR opad, HASH(key XOR ipad, msg)) */
    for (i = 0; i < HMAC_SHA1_BLOCKSIZE; i++) {
        okey[i] = ikey[i] ^ 0x5c;
        ikey[i] ^= 0x36;
    }

    HASH_Begin(sha1);
    HASH_Update(sha1, ikey, HMAC_SHA1_BLOCKSIZE);
    HASH_Update(sha1, in, in_len);
    HASH_End(sha1, hash, &res_len, SSS_SHA1_LENGTH);

    HASH_Begin(sha1);
    HASH_Update(sha1, okey, HMAC_SHA1_BLOCKSIZE);
    HASH_Update(sha1, hash, SSS_SHA1_LENGTH);
    HASH_End(sha1, out, &res_len, SSS_SHA1_LENGTH);

    HASH_Destroy(sha1);

    return EOK;
}
