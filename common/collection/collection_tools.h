/*
    COLLECTION LIBRARY

    Header file for supplementary functions that provide
    printing and debugging of collections.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

    Collection Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Collection Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Collection Library.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef COLLECTION_TOOLS_H
#define COLLECTION_TOOLS_H

#include "collection.h"

/**
 * @defgroup tools TOOLS interface
 *
 * Additional functions retaed to tracing,
 * printing, debugging and serializaing collections.
 *
 * Functions in this module are more a sample implementation
 * than a part of the interface. There is a chance they will
 * change over time.
 *
 * @{
 */

#ifdef  HAVE_TRACE
#define COL_DEBUG_COLLECTION(collection) col_debug_collection(collection,COL_TRAVERSE_DEFAULT);
#else
#define COL_DEBUG_COLLECTION(collection) ;
#endif

/** @brief Name used for string type. */
#define COL_TYPE_NAME_STRING     "string"
/** @brief Name used for binary type. */
#define COL_TYPE_NAME_BINARY     "bin"
/** @brief Name used for integer type. */
#define COL_TYPE_NAME_INTEGER    "int"
/** @brief Name used for unsigned integer type. */
#define COL_TYPE_NAME_UNSIGNED   "uint"
/** @brief Name used for long type. */
#define COL_TYPE_NAME_LONG       "long"
/** @brief Name used for unsigned long type. */
#define COL_TYPE_NAME_ULONG      "ulong"
/** @brief Name used for floating point type. */
#define COL_TYPE_NAME_DOUBLE     "double"
/** @brief Name used for boolean type. */
#define COL_TYPE_NAME_BOOL       "bool"
/** @brief Name used for unknown type. */
#define COL_TYPE_NAME_UNKNOWN    "unknown"

/** @brief Literal used in the default serialization. */
#define TEXT_COLLECTION "SET"
/** @brief Length of the \ref TEXT_COLLECTION literal. */
#define TEXT_COLLEN 3

/**
 * @brief The data will be allocated in BLOCK_SIZE
 * blocks during serialization.
 */
#define BLOCK_SIZE 1024

/**
 * @struct col_serial_data
 * @brief Structure is used to incrementaly serialize collection.
 */
struct col_serial_data {
    char *buffer;
    int size;
    int length;
    int nest_level;
};


/**
 * @brief Calculate the potential size of the item.
 *
 * @param[in] type        Type of the value.
 * @param[in] length      Length of the value.
 *
 * @return Maximum length the value would occupy when serialized.
 */
int col_get_data_len(int type, int length);

/**
 * @brief Grow serialization buffer.
 *
 * @param[in] buf_data    Serialization object.
 * @param[in] len         For how much the serialization storage
 *                        should be incrementally increased.
 *
 * @return 0      - Success.
 * @return ENOMEM - No memory.
 */
int col_grow_buffer(struct col_serial_data *buf_data, int len);

/**
 * @brief Add special data to the serialization output.
 *
 * @param[in] buf_data    Serialization object.
 * @param[in] data        Pointer to special data.
 * @param[in] len         Length of the data to insert.
 *
 * @return 0      - Success.
 * @return ENOMEM - No memory.
 */
int col_put_marker(struct col_serial_data *buf_data,
                   const void *data, int len);

/**
 * @brief Serialization of data callback.
 *
 * @param[in] property_in     Property to serialize.
 * @param[in] property_len_in Length of the property to serialize.
 * @param[in] type            Type of the value.
 * @param[in] data_in         Value to serialize.
 * @param[in] length_in       Length of the value.
 * @param[in] custom_data     State data passed to callback.
 *                            It is actually a serialization object.
 * @param[in] dummy           Not used. It is here because
 *                            the callback needs to comply
 *                            to the functions signature.
 *
 * @return 0      - Success.
 * @return ENOMEM - No memory.
 */
int col_serialize(const char *property_in,
                  int property_len_in,
                  int type,
                  void *data_in,
                  int length_in,
                  void *custom_data,
                  int *dummy);

/**
 * @brief Debug property callback.
 *
 * @param[in] property        Property to debug.
 * @param[in] property_len    Length of the property to debug.
 * @param[in] type            Type of the value.
 * @param[in] data            Value to serialize.
 * @param[in] length          Length of the value.
 * @param[in] custom_data     State data passed to the callback.
 * @param[in] dummy           Not used. It is here because
 *                            the callback needs to comply
 *                            to the functions signature.
 *
 * @return 0      - Success.
 * @return ENOMEM - No memory.
 */
int col_debug_handle(const char *property,
                     int property_len,
                     int type,
                     void *data,
                     int length,
                     void *custom_data,
                     int *dummy);

/**
 * @brief Convenience function to debug an item.
 *
 * Prints item internals.
 *
 * @param[in] item            Item to print.
 *
 * @return 0      - Success.
 * @return ENOMEM - No memory.
 */
int col_debug_item(struct collection_item *item);

/**
 * @brief Print collection for debugging purposes.
 *
 * Prints collection internals.
 *
 * @param[in] handle            Collection to debug.
 * @param[in] flag              See traverse flags.
 *
 * @return 0      - Success.
 * @return ENOMEM - No memory.
 */
int col_debug_collection(struct collection_item *handle,
                         int flag);

/**
 * @brief Print collection data.
 *
 * Prints collection data.
 * Uses traverse function to iterate through
 * the collection.
 *
 * @param[in] handle            Collection to print.
 *
 * @return 0      - Success.
 * @return ENOMEM - No memory.
 */
int col_print_collection(struct collection_item *handle);

/**
 * @brief Print collection data.
 *
 * Prints collection data.
 * Uses iterator to process the collection.
 *
 * @param[in] handle            Collection to print.
 *
 * @return 0      - Success.
 * @return ENOMEM - No memory.
 */
int col_print_collection2(struct collection_item *handle);

/**
 * @brief Find and print one property.
 *
 * Prints item data.
 *
 * @param[in] handle            Collection to search.
 * @param[in] name              Item to find and print.
 *
 * @return 0      - Success.
 * @return ENOMEM - No memory.
 */
int col_print_item(struct collection_item *handle, const char *name);

/**
 * @brief Convert collection to the array of properties.
 *
 * @param[in] handle            Collection to convert.
 * @param[in] size              Will receive the number of
 *                              the strings in the array.
 *                              Can be NULL if caller is not interested
 *                              in the size of the array.
 * @param[in] error             Will receive error value if any.
 *                              Can be NULL if the caller does
 *                              not care about error codes.
 *                              - 0      - Success.
 *                              - ENOMEM - No memory.
 *
 * @return List of strings that constitute
 *         the properties in the collection.
 *         Collection name is not included.
 */
char **col_collection_to_list(struct collection_item *handle,
                              int *size,
                              int *error);

/**
 * @brief Free list of properties.
 *
 * @param[in] str_list          List to free.
 */
void col_free_property_list(char **str_list);

#endif
