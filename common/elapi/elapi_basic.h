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

#ifndef ELAPI_BASIC_H
#define ELAPI_BASIC_H

#include <stdint.h>

#ifndef EOK
#define EOK 0
#endif

/* Generic data structure for the data output */
struct elapi_data_out {
    unsigned char *buffer;
    uint32_t size;
    uint32_t length;
    uint32_t written;
};

/* Function to free serialized data */
void elapi_free_serialized_data(struct elapi_data_out *out_data);

/* Allocate data structure */
int elapi_alloc_serialized_data(struct elapi_data_out **out_data);

/* Function to add memory to the output buffer */
int elapi_grow_data(struct elapi_data_out *out_data,
                    uint32_t len,
                    uint32_t block);

#endif
