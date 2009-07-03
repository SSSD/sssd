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

#include "trace.h"
#include "collection.h"

#ifdef  HAVE_TRACE
#define COL_DEBUG_COLLECTION(collection) col_debug_collection(collection,COL_TRAVERSE_DEFAULT);
#else
#define COL_DEBUG_COLLECTION(collection) ;
#endif

#define COL_TYPE_NAME_STRING     "string"
#define COL_TYPE_NAME_BINARY     "bin"
#define COL_TYPE_NAME_INTEGER    "int"
#define COL_TYPE_NAME_UNSIGNED   "uint"
#define COL_TYPE_NAME_LONG       "long"
#define COL_TYPE_NAME_ULONG      "ulong"
#define COL_TYPE_NAME_DOUBLE     "double"
#define COL_TYPE_NAME_BOOL       "bool"
#define COL_TYPE_NAME_UNKNOWN    "unknown"

#define TEXT_COLLECTION "SET"
#define TEXT_COLLEN 3

#define BLOCK_SIZE 1024

struct col_serial_data {
    char *buffer;
    int size;
    int length;
    int nest_level;
};


/* Calculate the potential size of the item */
int col_get_data_len(int type, int length);

/* Grow buffer to accomodate more space */
int col_grow_buffer(struct col_serial_data *buf_data, int len);

/* Specail function to add different formatting symbols to the output */
int col_put_marker(struct col_serial_data *buf_data, const void *data, int len);

/* Serialization of data user handler */
int col_serialize(const char *property_in,
                  int property_len_in,
                  int type,
                  void *data_in,
                  int length_in,
                  void *custom_data,
                  int *dummy);

/* Debug handle */
int col_debug_handle(const char *property,
                     int property_len,
                     int type,
                     void *data,
                     int length,
                     void *custom_data,
                     int *dummy);

/* Convenience function to debug an item */
int col_debug_item(struct collection_item *item);

/* Print collection for debugging purposes */
int col_debug_collection(struct collection_item *handle,int flag);

/* Print the collection using default serialization */
int col_print_collection(struct collection_item *handle);

/* Print the collection using iterator */
int col_print_collection2(struct collection_item *handle);


/* Find and print one item using default serialization */
int col_print_item(struct collection_item *handle, const char *name);

/* Convert collection to list of properties */
char **col_collection_to_list(struct collection_item *handle, int *size, int *error);

/* Function to free the list of properties. */
void col_free_property_list(char **str_list);

#endif
