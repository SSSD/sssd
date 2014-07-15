/*
   Unix SMB/CIFS implementation.

   Winbind client asynchronous API, utility functions

   Copyright (C) Gerald (Jerry) Carter 2007-2008


   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Required Headers */

#include "libwbclient.h"

#include "util/util.h"

static void wbcNamedBlobDestructor(void *ptr)
{
    struct wbcNamedBlob *b = (struct wbcNamedBlob *)ptr;

    while (b->name != NULL) {
        free(discard_const_p(char, b->name));
        free(b->blob.data);
        b += 1;
    }
}

/* Initialize a named blob and add to list of blobs */
wbcErr wbcAddNamedBlob(size_t *num_blobs,
               struct wbcNamedBlob **pblobs,
               const char *name,
               uint32_t flags,
               uint8_t *data,
               size_t length)
{
    wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
    struct wbcNamedBlob *blobs, *blob;

    if (name == NULL) {
        return WBC_ERR_INVALID_PARAM;
    }

    /*
     * Overallocate the b->name==NULL terminator for
     * wbcNamedBlobDestructor
     */
    blobs = (struct wbcNamedBlob *)wbcAllocateMemory(
        *num_blobs + 2, sizeof(struct wbcNamedBlob),
        wbcNamedBlobDestructor);

    if (blobs == NULL) {
        return WBC_ERR_NO_MEMORY;
    }

    if (*pblobs != NULL) {
        struct wbcNamedBlob *old = *pblobs;
        memcpy(blobs, old, sizeof(struct wbcNamedBlob) * (*num_blobs));
        if (*num_blobs != 0) {
            /* end indicator for wbcNamedBlobDestructor */
            old[0].name = NULL;
        }
        wbcFreeMemory(old);
    }
    *pblobs = blobs;

    blob = &blobs[*num_blobs];

    blob->name = strdup(name);
    BAIL_ON_PTR_ERROR(blob->name, wbc_status);
    blob->flags = flags;

    blob->blob.length = length;
    blob->blob.data    = (uint8_t *)malloc(length);
    BAIL_ON_PTR_ERROR(blob->blob.data, wbc_status);
    memcpy(blob->blob.data, data, length);

    *num_blobs += 1;
    *pblobs = blobs;
    blobs = NULL;

    wbc_status = WBC_ERR_SUCCESS;
done:
    wbcFreeMemory(blobs);
    return wbc_status;
}
