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

#include <openssl/bio.h>
#include <openssl/evp.h>

char *sss_base64_encode(TALLOC_CTX *mem_ctx,
                        const unsigned char *in,
                        size_t insize)
{
    char *b64encoded = NULL, *outbuf = NULL;
    int i, j, b64size;
    BIO *bmem, *b64;

    b64 = BIO_new(BIO_f_base64());
    if (!b64) return NULL;

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    if (!bmem) goto done;

    b64 = BIO_push(b64, bmem);

    BIO_write(b64, in, insize);

    (void) BIO_flush(b64);

    b64size = BIO_get_mem_data(bmem, &b64encoded);
    if (b64encoded) {
        outbuf = talloc_array(mem_ctx, char, b64size+1);
        if (outbuf == NULL) goto done;

        for (i=0, j=0; i < b64size; i++) {
            if (b64encoded[i] == '\n' || b64encoded[i] == '\r') {
                continue;
            }
            outbuf[j++] = b64encoded[i];
        }
        outbuf[j++] = '\0';
    }

done:
    BIO_free_all(b64);
    return outbuf;
}

unsigned char *sss_base64_decode(TALLOC_CTX *mem_ctx,
                                 const char *in,
                                 size_t *outsize)
{
    unsigned char *outbuf = NULL;
    unsigned char *b64decoded = NULL;
    unsigned char inbuf[512];
    char * in_dup;
    int size, inlen = strlen(in);
    BIO *bmem, *b64, *bmem_out;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return NULL;
    }

    in_dup = talloc_size(tmp_ctx, inlen+1);
    if (!in_dup) goto done;
    memcpy(in_dup, in, inlen+1);

    b64 = BIO_new(BIO_f_base64());
    if (!b64) goto done;

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bmem = BIO_new_mem_buf(in_dup, -1);
    if (!bmem) {
        BIO_free(b64);
        goto done;
    }

    b64 = BIO_push(b64, bmem);

    bmem_out = BIO_new(BIO_s_mem());
    if (!bmem_out) {
        BIO_free_all(b64);
        goto done;
    }

    while((inlen = BIO_read(b64, inbuf, 512)) > 0)
        BIO_write(bmem_out, inbuf, inlen);

    (void) BIO_flush(bmem_out);

    size = BIO_get_mem_data(bmem_out, &b64decoded);

    if (b64decoded) {
        outbuf = talloc_memdup(mem_ctx, b64decoded, size);
        if (!outbuf) {
            BIO_free_all(b64);
            BIO_free(bmem_out);
            goto done;
        }

        *outsize = size;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot get decoded data\n");
    }
    BIO_free_all(b64);
    BIO_free(bmem_out);

done:
    talloc_free(tmp_ctx);
    return outbuf;
}
