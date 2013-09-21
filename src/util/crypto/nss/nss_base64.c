/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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

#include <talloc.h>

#include "util/util.h"
#include "util/crypto/nss/nss_util.h"
#include "util/crypto/sss_crypto.h"

#include <base64.h>

/* NSS wraps b64 encoded buffers with CRLF automatically after 64 chars. This
 * function strips the CRLF double-chars. The buffer can be decoded with plain
 * NSS calls */
char *sss_base64_encode(TALLOC_CTX *mem_ctx,
                        const unsigned char *inbuf,
                        size_t inbufsize)
{
    int ret;
    char *b64encoded = NULL;
    int i, j, b64size;
    char *outbuf;

    /* initialize NSS if needed */
    ret = nspr_nss_init();
    if (ret != EOK) {
        return NULL;
    }

    b64encoded = BTOA_DataToAscii(inbuf, inbufsize);
    if (!b64encoded) return NULL;

    b64size = strlen(b64encoded) + 1;
    outbuf = talloc_array(mem_ctx, char, b64size);
    if (outbuf == NULL) {
        PORT_Free(b64encoded);
        return NULL;
    }

    for (i=0, j=0; i < b64size; i++) {
        if (b64encoded[i] == '\n' || b64encoded[i] == '\r') {
            continue;
        }
        outbuf[j++] = b64encoded[i]; /* will also copy the trailing \0 char */
    }

    PORT_Free(b64encoded);
    return outbuf;
}

unsigned char *sss_base64_decode(TALLOC_CTX *mem_ctx,
                                 const char *inbuf,
                                 size_t *outbufsize)
{
    int ret;
    unsigned char *b64decoded = NULL;
    unsigned int size;
    unsigned char *outbuf;

    /* initialize NSS if needed */
    ret = nspr_nss_init();
    if (ret != EOK) {
        return NULL;
    }

    b64decoded = ATOB_AsciiToData(inbuf, &size);
    if (!b64decoded) return NULL;

    outbuf = talloc_memdup(mem_ctx, b64decoded, size);
    PORT_Free(b64decoded);
    if (!outbuf) return NULL;

    *outbufsize = size;
    return outbuf;
}
