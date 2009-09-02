/*
    ELAPI

    Basic output buffer manipulation routines.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

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


#define _GNU_SOURCE
#include <errno.h>      /* for errors */
#include <stdlib.h>     /* for free() */

#include "elapi_basic.h"
#include "trace.h"
#include "config.h"

/* Function to free serialized data */
void elapi_free_serialized_data(struct elapi_data_out *out_data)
{
    TRACE_FLOW_STRING("elapi_free_serialized_data", "Entry");

    if (out_data) {
        free(out_data->buffer);
        free(out_data);
    }

    TRACE_FLOW_STRING("elapi_free_serialized_data", "Exit");
}

/* Allocate data structure */
int elapi_alloc_serialized_data(struct elapi_data_out **out_data)
{
    int error;

    TRACE_FLOW_STRING("elapi_alloc_serialized_data", "Entry");

    if (!out_data) {
        TRACE_ERROR_STRING("Invalid argument", "");
        error = EINVAL;
    }
    else {
        *out_data = (struct elapi_data_out *)calloc(1,
                                             sizeof(struct elapi_data_out));
        if (*out_data == NULL) {
            TRACE_ERROR_STRING("Failed to allocate memory", "");
            error = ENOMEM;
        }
        else error = EOK;
    }

    TRACE_FLOW_NUMBER("elapi_alloc_serialized_data. Exit. Returning", error);
    return error;
}


/* Grow buffer */
int elapi_grow_data(struct elapi_data_out *out_data,
                    uint32_t len,
                    uint32_t block)
{
    int error = EOK;
    unsigned char *newbuf = NULL;

    TRACE_FLOW_STRING("elapi_grow_data", "Entry");

    TRACE_INFO_NUMBER("Current length: ", out_data->length);
    TRACE_INFO_NUMBER("Current size: ", out_data->size);
    TRACE_INFO_NUMBER("Length to have: ", len);
    TRACE_INFO_NUMBER("Increment length: ", block);

    /* Grow buffer if needed */
    while (out_data->length + len >= out_data->size) {
        newbuf = realloc(out_data->buffer, out_data->size + block);
        if (newbuf == NULL) {
            TRACE_ERROR_NUMBER("Error. Failed to allocate memory.", ENOMEM);
            return ENOMEM;
        }
        out_data->buffer = newbuf;
        out_data->size += block;
        TRACE_INFO_NUMBER("New size: ", out_data->size);
    }

    TRACE_INFO_NUMBER("Final size: ", out_data->size);
    TRACE_FLOW_NUMBER("elapi_grow_data. Exit. Returning", error);
    return error;
}
