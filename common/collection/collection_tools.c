/*
    COLLECTION LIBRARY

    Additional functions for printing and debugging collections.

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


#include <stdio.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include "trace.h"
#include "collection_priv.h"
#include "collection.h"
#include "collection_tools.h"

/* Debug handle */
int debug_handle(char *property,
                 int property_len,
                 int type,
                 void *data,
                 int length,
                 void *custom_data,
                 int *dummy)
{
    int i;
    int nest_level;

    TRACE_FLOW_STRING("debug_handle", "Entry.");


    nest_level = *(int *)(custom_data);
    TRACE_INFO_NUMBER("We are getting this pointer:", custom_data);
    TRACE_INFO_NUMBER("Nest level:", nest_level);

    switch (type) {
    case COL_TYPE_STRING:
        printf("%*s %s[%d] str: %s (%d)\n",
               (nest_level -1) * 4, "",
               property,
               length,
               (char *)(data),
               nest_level);
        break;
    case COL_TYPE_BINARY:
        printf("%*s %s[%d] bin: ",
               (nest_level -1) * 4, "",
               property,
               length);
        for (i = 0; i < length; i++)
            printf("%02X", ((unsigned char *)(data))[i]);
        printf(" (%d)\n", nest_level);
        break;
    case COL_TYPE_INTEGER:
        printf("%*s %s[%d] int: %d (%d)\n",
               (nest_level -1) * 4, "",
               property,
               length,
               *((int *)(data)),
               nest_level);
        break;
    case COL_TYPE_UNSIGNED:
        printf("%*s %s[%d] uint: %u (%d)\n",
               (nest_level -1) * 4, "",
               property,
               length,
               *((unsigned int *)(data)),
               nest_level);
        break;
    case COL_TYPE_LONG:
        printf("%*s %s[%d] long: %ld (%d)\n",
               (nest_level -1) * 4, "",
               property,
               length,
               *((long *)(data)),
               nest_level);
        break;
    case COL_TYPE_ULONG:
        printf("%*s %s[%d] ulong: %lu (%d)\n",
               (nest_level -1) * 4, "",
               property,
               length,
               *((unsigned long *)(data)),
               nest_level);
        break;
    case COL_TYPE_DOUBLE:
        printf("%*s %s[%d] double: %.4f (%d)\n",
               (nest_level -1) * 4, "",
               property,
               length,
               *((double *)(data)),
               nest_level);
        break;
    case COL_TYPE_BOOL:
        printf("%*s %s[%d] bool: %s (%d)\n",
               (nest_level -1) * 4, "",
               property,
               length,
               (*((unsigned char *)(data)) == '\0') ? "flase" : "true",
               nest_level);
        break;
    case COL_TYPE_COLLECTION:
        nest_level++;
        printf("%*s %s[%d] header: count %d, ref_count %d class %d data: ",
               (nest_level -1) * 4, "",
               property,
               length,
               ((struct collection_header *)(data))->count,
               ((struct collection_header *)(data))->reference_count,
               ((struct collection_header *)(data))->cclass);
        for (i = 0; i < length; i++)
            printf("%02X", ((unsigned char *)(data))[i]);
        printf(" (%d)\n", nest_level);
        break;
    case COL_TYPE_COLLECTIONREF:
        printf("%*s %s[%d] external link: ",
               (nest_level -1) * 4, "",
               property,
               length);
        for (i = 0; i < length; i++)
            printf("%02X", ((unsigned char *)(data))[i]);
        printf(" (%d)\n", nest_level);
        break;
    case COL_TYPE_END:
        nest_level--;
        /* printf("Reduced nest level\n");*/
        break;
    default:
        printf("Not implemented yet.\n");
        break;
    }
    *(int *)(custom_data) = nest_level;
    TRACE_INFO_NUMBER("Nest level at the end:", nest_level);
    TRACE_FLOW_STRING("debug_handle", "Success exit.");
    return EOK;
}

/* Convenience function to debug an item */
inline int debug_item(struct collection_item *item)
{
    int dummy = 0;
    int nest_level = 0;
    return debug_handle(item->property,
                        item->property_len,
                        item->type,
                        item->data,
                        item->length,
                        (void *)(&nest_level),
                        &dummy);
}


/* Print collection for debugging purposes */
int debug_collection(struct collection_item *handle, int flag)
{
    int error = EOK;
    int nest_level = 0;

    TRACE_FLOW_STRING("debug_collection", "Entry.");

    printf("DEBUG COLLECTION %s\n", handle->property);

    flag |= COL_TRAVERSE_END;

    printf("Traverse flags %d\n", flag);

    /* Traverse collection */
    error = traverse_collection(handle, flag,
                                debug_handle, (void *)(&nest_level));
    if (error) printf("Error debuging collection %d\n", error);

    TRACE_FLOW_STRING("debug_collection", "Exit.");
    return error;
}


/* Return a static string based on type of the element */
static inline const char *get_type(int type)
{
    switch (type) {
    case COL_TYPE_STRING:
        return COL_TYPE_NAME_STRING;

    case COL_TYPE_INTEGER:
        return COL_TYPE_NAME_INTEGER;

    case COL_TYPE_UNSIGNED:
        return COL_TYPE_NAME_UNSIGNED;

    case COL_TYPE_LONG:
        return COL_TYPE_NAME_LONG;

    case COL_TYPE_ULONG:
        return COL_TYPE_NAME_ULONG;

    case COL_TYPE_BINARY:
        return COL_TYPE_NAME_BINARY;

    case COL_TYPE_DOUBLE:
        return COL_TYPE_NAME_DOUBLE;

    case COL_TYPE_BOOL:
        return COL_TYPE_NAME_BOOL;

    default:
        return COL_TYPE_NAME_UNKNOWN;
    }

}

/* Calculate the potential size of the item */
int get_data_len(int type, int length)
{
    int len = 0;

    TRACE_FLOW_STRING("util_get_item_len", "Entry point");

    switch (type) {
    case COL_TYPE_INTEGER:
    case COL_TYPE_UNSIGNED:
    case COL_TYPE_LONG:
    case COL_TYPE_ULONG:
        len = 15;
        break;

    case COL_TYPE_STRING:
    case COL_TYPE_BINARY:
        len = length * 2 + 2;
        break;

    case COL_TYPE_DOUBLE:
        len = 64;
        break;

    case COL_TYPE_BOOL:
        len = 6;
        break;

    default:
        len = 0;
        break;
    }

    TRACE_FLOW_STRING("util_get_item_len","Exit point");

    return len;
}

/* Copy data escaping characters */
static int copy_esc(char *dest, char *source, char esc)
{
    int i = 0;
    int j = 0;

    dest[j] = esc;
    j++;

    while (source[i]) {
        if ((source[i] == '\\') ||
            (source[i] == esc)) {

            dest[j] = '\\';
            j++;

        }
        dest[j] = source[i];
        i++;
        j++;
    }
    dest[j] = esc;
    j++;

    return j;
}

/* Grow buffer to accomodate more space */
int grow_buffer(struct serial_data *buf_data, int len)
{
    char *tmp;

    TRACE_FLOW_STRING("grow_buffer", "Entry point");
    TRACE_INFO_NUMBER("Current length: ", buf_data->length);
    TRACE_INFO_NUMBER("Increment length: ", len);
    TRACE_INFO_NUMBER("Expected length: ", buf_data->length+len);
    TRACE_INFO_NUMBER("Current size: ", buf_data->size);

    /* Grow buffer if needed */
    while (buf_data->length+len >= buf_data->size) {
        errno = 0;
        tmp = realloc(buf_data->buffer, buf_data->size + BLOCK_SIZE);
        if (tmp == NULL) {
            TRACE_ERROR_NUMBER("Error. Failed to allocate memory. Errno: ", errno);
            return errno;
        }
        buf_data->buffer = tmp;
        buf_data->size += BLOCK_SIZE;
        TRACE_INFO_NUMBER("New size: ", buf_data->size);

    }

    TRACE_INFO_NUMBER("Final size: ", buf_data->size);
    TRACE_FLOW_STRING("grow_buffer", "Success Exit.");
    return EOK;
}

/* Specail function to add different formatting symbols to the output */
int put_marker(struct serial_data *buf_data, void *data, int len)
{
    int error = EOK;

    TRACE_FLOW_STRING("put_marker", "Entry point");
    TRACE_INFO_NUMBER("Marker length: ", len);

    error = grow_buffer(buf_data, len);
    if (error) {
        TRACE_ERROR_NUMBER("grow_buffer failed with: ", error);
        return error;
    }
    memcpy(buf_data->buffer + buf_data->length, data, len);
    buf_data->length += len;
    buf_data->buffer[buf_data->length] = '\0';

    TRACE_FLOW_STRING("put_marker","Success exit");
    return error;
}

/* Add item's data */
int serialize(char *property_in,
              int property_len_in,
              int type,
              void *data_in,
              int length_in,
              void *custom_data,
              int *dummy)
{
    int len;
    struct serial_data *buf_data;
    char *property;
    void *data;
    int  property_len;
    int length;
    int error = EOK;
    int i;

    TRACE_FLOW_STRING("serialize","Entry point");

    *dummy = 0;

    /* Check is there is buffer. If not allocate */
    buf_data = (struct serial_data *)custom_data;
    if (buf_data == NULL) {
        TRACE_ERROR_STRING("Error.", "Storage data is not passed in!");
        return EINVAL;
    }
    if (buf_data->buffer == NULL) {
        TRACE_INFO_STRING("First time use.", "Allocating buffer.");
        errno = 0;
        buf_data->buffer = malloc(BLOCK_SIZE);
        if (buf_data->buffer == NULL) {
            TRACE_ERROR_NUMBER("Error. Failed to allocate memory. Errno: ", errno);
            return errno;
        }
        buf_data->buffer[0] = '\0';
        buf_data->length = 0;
        buf_data->size = BLOCK_SIZE;
    }

    TRACE_INFO_NUMBER("Buffer len: ", buf_data->length);
    TRACE_INFO_NUMBER("Buffer size: ", buf_data->size);
    TRACE_INFO_STRING("Buffer: ", buf_data->buffer);

    /* Check the beginning of the collection */
    if (type == COL_TYPE_COLLECTION) {
        TRACE_INFO_STRING("Serializing collection: ", property_in);
        TRACE_INFO_STRING("First header. ", "");
        error = put_marker(buf_data, "(", 1);
        if (error != EOK) return error;
        property = TEXT_COLLECTION;
        property_len = TEXT_COLLEN;
        data = property_in;
        length = property_len_in + 1;
        type = COL_TYPE_STRING;
        buf_data->nest_level++;
    }
    /* Check for subcollections */
    else if (type == COL_TYPE_COLLECTIONREF) {
        /* Skip */
        TRACE_FLOW_STRING("serialize", "skip reference return");
        return EOK;
    }
    /* Check for the end of the collection */
    else if (type == COL_TYPE_END) {
        if ((buf_data->length > 0) &&
            (buf_data->buffer[buf_data->length-1] == ',')) {
            buf_data->length--;
            buf_data->buffer[buf_data->length] = '\0';
        }
        if (buf_data->nest_level > 0) {
            buf_data->nest_level--;
            error = put_marker(buf_data, ")", 1);
            if (error != EOK) return error;
        }
        TRACE_FLOW_STRING("serialize", "end collection item processed returning");
        return EOK;
    }
    else {
        property = property_in;
        property_len = property_len_in;
        data = data_in;
        length = length_in;
    }

    TRACE_INFO_STRING("Property: ", property);
    TRACE_INFO_NUMBER("Property length: ", property_len);

    /* Start with property and "=" */
    if ((error = put_marker(buf_data, property, property_len)) ||
        (error = put_marker(buf_data, "=", 1))) {
        TRACE_ERROR_NUMBER("put_marker returned error: ", error);
        return error;
    }
    /* Get projected length of the item */
    len = get_data_len(type,length);
    TRACE_INFO_NUMBER("Expected data length: ",len);
    TRACE_INFO_STRING("Buffer so far: ", buf_data->buffer);

    /* Make sure we have enough space */
    if ((error = grow_buffer(buf_data, len))) {
        TRACE_ERROR_NUMBER("grow_buffer returned error: ", error);
        return error;
    }

    /* Add the value */
    switch (type) {
    case COL_TYPE_STRING:
        /* Escape double quotes */
        len = copy_esc(&buf_data->buffer[buf_data->length], (char *)(data), '"');
        break;

    case COL_TYPE_BINARY:
        buf_data->buffer[buf_data->length] = '\'';
        for (i = 0; i < length; i++)
            sprintf(&buf_data->buffer[buf_data->length + i *2] + 1,
                    "%02X", (unsigned int)(((unsigned char *)(data))[i]));
        len = length * 2 + 1;
        buf_data->buffer[buf_data->length + len] = '\'';
        len++;
        break;

    case COL_TYPE_INTEGER:
        len = sprintf(&buf_data->buffer[buf_data->length],
                      "%d", *((int *)(data)));
        break;

    case COL_TYPE_UNSIGNED:
        len = sprintf(&buf_data->buffer[buf_data->length],
                      "%u", *((unsigned int *)(data)));
        break;

    case COL_TYPE_LONG:
        len = sprintf(&buf_data->buffer[buf_data->length],
                      "%ld", *((long *)(data)));
        break;

    case COL_TYPE_ULONG:
        len = sprintf(&buf_data->buffer[buf_data->length],
                      "%lu", *((unsigned long *)(data)));
        break;

    case COL_TYPE_DOUBLE:
        len = sprintf(&buf_data->buffer[buf_data->length],
                      "%.4f", *((double *)(data)));
        break;

    case COL_TYPE_BOOL:
        len = sprintf(&buf_data->buffer[buf_data->length],
                      "%s", (*((unsigned char *)(data))) ? "true" : "false");
        break;

    default:
        buf_data->buffer[buf_data->length] = '\0';
        len = 0;
        break;
    }

    /* Adjust length */
    buf_data->length += len;
    buf_data->buffer[buf_data->length] = '\0';

    /* Always put a comma at the end */
    error = put_marker(buf_data, ",", 1);
    if (error != EOK) {
        TRACE_ERROR_NUMBER("put_marker returned error: ", error);
        return error;
    }

    TRACE_INFO_STRING("Data: ", buf_data->buffer);
    TRACE_FLOW_STRING("serialize", "Exit point");
    return EOK;

}

/* Print the collection using default serialization */
int print_collection(struct collection_item *handle)
{
    struct serial_data buf_data;
    int error = EOK;

    TRACE_FLOW_STRING("print_collection", "Entry");

    printf("COLLECTION:\n");

    buf_data.buffer = NULL;
    buf_data.length = 0;
    buf_data.size = 0;
    buf_data.nest_level = 0;

    /* Traverse collection */
    error = traverse_collection(handle,
                                COL_TRAVERSE_DEFAULT | COL_TRAVERSE_END ,
                                serialize, (void *)(&buf_data));
    if (error)
        printf("Error traversing collection %d\n", error);
    else
        printf("%s\n", buf_data.buffer);

    free(buf_data.buffer);

    TRACE_FLOW_NUMBER("print_collection returning", error);
    return error;
}

/* Print the collection using iterator */
int print_collection2(struct collection_item *handle)
{
    struct collection_iterator *iterator = NULL;
    int error = EOK;
    struct collection_item *item = NULL;
    int nest_level = 0;
    int dummy = 0;
    int line = 1;

    TRACE_FLOW_STRING("print_collection2", "Entry");

    /* If we have something to print print it */
    if (handle == NULL) {
        TRACE_ERROR_STRING("No error list", "");
        return EINVAL;
    }

    /* Bind iterator */
    error = bind_iterator(&iterator, handle,
                          COL_TRAVERSE_DEFAULT| COL_TRAVERSE_END| COL_TRAVERSE_SHOWSUB);
    if (error) {
        TRACE_ERROR_NUMBER("Error (bind):", error);
        return error;
    }

    do {
        /* Loop through a collection */
        error = iterate_collection(iterator, &item);
        if (error) {
            TRACE_ERROR_NUMBER("Error (iterate):", error);
            unbind_iterator(iterator);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) break;

        if (item->type != COL_TYPE_END) printf("%05d", line);

        debug_handle(item->property,
                     item->property_len,
                     item->type,
                     item->data,
                     item->length,
                     (void *)(&nest_level),
                     &dummy);
        line++;
    }
    while(1);

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    unbind_iterator(iterator);

    TRACE_INFO_STRING("print_collection2", "Exit");
    return EOK;
}

/* Find and print one item using default serialization */
int print_item(struct collection_item *handle, char *name)
{
    struct serial_data buf_data;
    int error = EOK;

    TRACE_FLOW_STRING("print_item", "Entry");

    printf("FIND ITEM:\n");

    buf_data.buffer = NULL;
    buf_data.length = 0;
    buf_data.size = 0;
    buf_data.nest_level = 0;

    error =  get_item_and_do(handle, name, COL_TYPE_ANY,
                             COL_TRAVERSE_DEFAULT, serialize, &buf_data);
    if(error) printf("Error searching collection %d\n", error);
    else {
        if (buf_data.buffer != NULL) {
            if (buf_data.length > 0) buf_data.length--;
            buf_data.buffer[buf_data.length] = '\0',
            printf("%s\n", buf_data.buffer);
            free(buf_data.buffer);
        }
        else {
            printf("Name %s is not found in the collection %s.\n",
                   name, handle->property);
        }
    }

    TRACE_FLOW_NUMBER("print_item returning", error);
    return error;
}


