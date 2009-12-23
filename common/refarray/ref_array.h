/*
    REF ARRAY

    Header file for of the dynamic array with reference count.

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

#ifndef REF_ARRAY_H
#define REF_ARRAY_H

#include <stdint.h>
#include <stdlib.h>

struct ref_array;

#ifndef EOK
#define EOK 0
#endif

/*************************************/
/* Interface to the referenced array */
/*************************************/

typedef enum
{
    REF_ARRAY_DESTROY,
    REF_ARRAY_DELETE,
} ref_array_del_enum;

/* Callback that can be provided by caller
 * to free data when the storage is actually destroyed
 */
typedef void (*ref_array_fn)(void *elem,
                             ref_array_del_enum type,
                             void *data);


/* Create referenced array */
int ref_array_create(struct ref_array **ra,
                     size_t elem,
                     uint32_t grow_by,
                     ref_array_fn cb,
                     void *data);

/* Get new reference to an array */
struct ref_array *ref_array_getref(struct ref_array *ra);

/* Delete the array */
void ref_array_destroy(struct ref_array *ra);

/* Add new element to the array */
int ref_array_append(struct ref_array *ra, void *element);

/* Get element */
void *ref_array_get(struct ref_array *ra, uint32_t idx, void *acptr);

/* Get array length */
int ref_array_getlen(struct ref_array *ra, uint32_t *len);

/* Alternative function to get length.
 * Returns 0 if the array is invalid
 */
uint32_t ref_array_len(struct ref_array *ra);


/* In future in might make sense to add entry points
 * to insert and delete elements from the array.
 * Current use cases do not require this kind of
 * functionality so it is left out of the implementation
 */

#endif
