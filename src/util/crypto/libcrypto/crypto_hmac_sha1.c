/*
    Copyright (C) 2019 Red Hat

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
#include <openssl/hmac.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"


int sss_hmac_sha1(const unsigned char *key, size_t key_len,
                  const unsigned char *in, size_t in_len,
                  unsigned char *out)
{
    unsigned int res_len = 0;
    unsigned char md[EVP_MAX_MD_SIZE];

    if ((key == NULL) || (key_len == 0) || (key_len > INT_MAX)
         || (in == NULL) || (in_len == 0) || (in_len > INT_MAX)
         || (out == NULL)) {
        return EINVAL;
    }

    if (!HMAC(EVP_sha1(), key, (int)key_len, in, (int)in_len, md, &res_len)) {
        return EINVAL;
    }

    if (res_len != SSS_SHA1_LENGTH) {
        return EINVAL;
    }

    memcpy(out, md, SSS_SHA1_LENGTH);

    return EOK;
}
