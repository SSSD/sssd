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

/** @mainpage The Referenced Array Interface
 *
 * The referenced array interface is a dynamically allocated
 * array of data of any type. The array can be shared by
 * multiple objects to avoid data duplication.
 *
 * The array is created once and then any number of
 * the references can be requested. The references are pointers
 * to the array. Each reference must be freed after use.
 * Freeing last reference to the array would free the array's storage.
 *
 * The array does not have any knowledge of the data type
 * of the actual data stored in the array. All elements of the array
 * are of the same size as prescribed by caller when the array is created.
 * The caller can potentially mix different types of data in the array
 * but this should be done with caution.
 *
 * At the moment the interface is not complete.
 * It provides basic functionality required to support other
 * components. In future it might make sense to add entry points
 * to insert and delete elements from the array.
 * Current use cases do not require this kind of
 * functionality so it is left out of the implementation.
 *
 */

/**
 * @defgroup ref_array Interface
 * @{
 */

/**
 * @brief Enumeration of the delete modes
 *
 * When the array is destroyed each element of the array
 * most likely needs to be freed. Same is true when an element
 * is removed from the array. However the caller might need
 * to do different things with the data depending on whether
 * the array is destroyed or whether the element is removed.
 * This enumeration defines constants that you used to indicate
 * which operation was performed.
 */
typedef enum
{
    REF_ARRAY_DESTROY,
    REF_ARRAY_DELETE,
} ref_array_del_enum;

/**
 * @brief Element cleanup callback
 *
 * Callback that can be provided by a caller
 * to free data when the storage is actually destroyed.
 */
typedef void (*ref_array_fn)(void *elem,
                             ref_array_del_enum type,
                             void *data);


/**
 * @brief Create referenced array
 *
 * @param[out] ra               Newly created array object.
 * @param[in]  elem             Element size in bytes.
 * @param[in]  grow_by          Defines how many elements
 *                              should be allocated together
 *                              as one chunk.
 * @param[in]  cb               Cleanup callback.
 * @param[in]  data             Caller supplied data
 *                              passed to cleanup callback.
 *
 * @return 0 - Success.
 * @return ENOMEM - No memory.
 * @return EINVAL - Invalid argument.
 */
int ref_array_create(struct ref_array **ra,
                     size_t elem,
                     uint32_t grow_by,
                     ref_array_fn cb,
                     void *data);

/**
 * @brief Get new reference to an array
 *
 * @param[in]  ra        Existing array object.
 *
 * @return A new reference to an array object.
 * @return NULL - Invalid argument.
 */
struct ref_array *ref_array_getref(struct ref_array *ra);

/**
 * @brief Delete the array
 *
 * @param[in]  ra        Existing array object
 *                       or a reference.
 *
 */
void ref_array_destroy(struct ref_array *ra);

/**
 * @brief Add new element to the array
 *
 * Appends an element to the end of the array.
 *
 * @param[in]  ra        Existing array object.
 * @param[in]  element   Pointer to data.
 *                       The number of bytes
 *                       defined at the array creation
 *                       as the array size will be copied
 *                       into the array element.
 *
 * @return 0 - Success.
 * @return ENOMEM - No memory.
 * @return EINVAL - Invalid argument.
 */
int ref_array_append(struct ref_array *ra, void *element);

/**
 * @brief Get element data
 *
 * Retrieves data from the array element.
 *
 * @param[in]  ra        Existing array object.
 * @param[in]  idx       Index of the array element.
 * @param[in]  acptr     Pointer to the memory
 *                       where the element's data
 *                       will be copied. Can be NULL.
 *                       In this case nothing is copied.
 *
 * @return Pointer to the data stored in the element.
 *         Conventionally it should be a const pointer,
 *         however such declaration would make using
 *         variable that receives the result of this
 *         function immutable. This is very inconvenient
 *         because such variable should be able to
 *         point to data related to multiple elements
 *         of the array.
 *
 * @return Pointer to the element's data.
 * @return NULL if index is out of range.
 */
void *ref_array_get(struct ref_array *ra, uint32_t idx, void *acptr);

/**
 * @brief Get array length
 *
 * Determines length of the array.
 *
 * @param[in]  ra        Existing array object.
 * @param[out] len       Variable will receive
 *                       the length of the array.
 *
 * @return 0 - Success.
 * @return EINVAL - Invalid argument.
 */
int ref_array_getlen(struct ref_array *ra, uint32_t *len);

/**
 * @brief Array length
 *
 * Alternative function to get length.
 *
 * @param[in]  ra        Existing array object.
 *
 * @return Length of the array. Returns 0 if the array is invalid.
 */
uint32_t ref_array_len(struct ref_array *ra);

/**
 * @}
 */


#endif
