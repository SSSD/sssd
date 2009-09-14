/*
    COLLECTION LIBRARY

    Function to compare items.

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

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include "config.h"
#include "trace.h"

/* The collection should use the real structures */
#include "collection_priv.h"
#include "collection.h"

#define NONZERO 1
#define PROP_MSK    0x000000007


#define TYPED_MATCH(type) \
    do { \
        if (*((type *)(first->data)) != *((type *)(second->data))) { \
            result = NONZERO; \
            if ((out_flags) && \
                (*((type *)(first->data)) < *((type *)(second->data)))) { \
                *out_flags |= COL_CMPOUT_DATA; \
            } \
        } \
    } while(0)


/* Function to compare two items */
int col_compare_items(struct collection_item *first,
                      struct collection_item *second,
                      unsigned in_flags,
                      unsigned *out_flags)
{
    int result = 0;
    unsigned mode;
    int cmpres = 0;
    char *substr;

    TRACE_FLOW_STRING("col_compare_items", "Entry.");

    /* If any of the arguments is NULL return
     * that they are different.
     */
    if ((first == NULL) || (second == NULL)) {
        TRACE_INFO_STRING("One of the items is NULL", "");
        return NONZERO;
    }

    /* Check if we are told to compare something */
    if (!in_flags) {
        TRACE_INFO_NUMBER("No flags specified", in_flags);
        return NONZERO;
    }

    if (out_flags) *out_flags = 0;

    /* Start comparison */
    mode = in_flags & PROP_MSK;
    if (mode > 0 ) {
        /* We are told to compare the properties */
        switch(mode) {

        case COL_CMPIN_PROP_EQU: /* looking for exact match */

            /* Compare hashes and lengths first */
            if ((first->phash == first->phash) &&
                (first->property_len == second->property_len)) {
                /* Collections are case insensitive, sorry... */
                cmpres = strncasecmp(first->property,
                                     second->property,
                                     second->property_len);
                if (cmpres != 0) {
                    result = NONZERO;
                    if (cmpres < 0) {
                        /* Second is greater */
                        if (out_flags) *out_flags |= COL_CMPOUT_PROP_STR;
                    }
                }
            }
            else {
                result = NONZERO;
                /* They are different so check if we need to compare? */
                if (out_flags) {
                    cmpres = strncasecmp(first->property,
                                         second->property,
                                         second->property_len);
                    if (cmpres < 0) {
                        /* Second is greater */
                            *out_flags |= COL_CMPOUT_PROP_STR;
                    }
                }
            }
            break;

        case COL_CMPIN_PROP_BEG: /* looking for beginning */

            /* Compare lengths first */
            if (first->property_len >= second->property_len) {
                cmpres = strncasecmp(first->property,
                                     second->property,
                                     second->property_len);
	            if (cmpres == 0) {
                    /* Check we need to validate for dot */
                    if (in_flags & COL_CMPIN_PROP_DOT) {
                        if ((first->property[second->property_len] != '\0') &&
                            (first->property[second->property_len] != '.')) {
                            result = NONZERO;
                        }
                    }
                }
                else result = NONZERO;
            }
            else result = NONZERO;
            break;

        case COL_CMPIN_PROP_MID: /* looking for middle */

            /* Compare lengths first */
            if (first->property_len >= second->property_len) {
                substr = strcasestr(first->property, second->property);
                if (substr != NULL) {
                    /* Check we need to validate for dot */
                    if (in_flags & COL_CMPIN_PROP_DOT) {
                        /* Check if we have a dot before or after */
                        if (((substr != first->property) &&
                             (first->property[(substr - first->property) - 1] != '.')) ||
                            ((substr[second->property_len] != '\0') &&
                             (substr[second->property_len] != '.'))) {
                            result = NONZERO;
                        }
                    }
                }
                else result = NONZERO;
            }
            else result = NONZERO;
            break;

        case COL_CMPIN_PROP_END: /* looking for end */

            /* Compare lengths first */
            if (first->property_len >= second->property_len) {
                substr = first->property + (first->property_len - second->property_len);
                cmpres = strncasecmp(substr,
                                     second->property,
                                     second->property_len);
	            if (cmpres == 0) {
                    /* Check we need to validate for dot */
                    if (in_flags & COL_CMPIN_PROP_DOT) {
                        if ((substr != first->property) &&
                            (first->property[(substr - first->property) - 1] != '.')) {
                            result = NONZERO;
                        }
                    }
                }
                else result = NONZERO;
            }
            else result = NONZERO;
            break;

        default: result = NONZERO;
            break;
        }
    }

    /* Check if we are told to compare property lengths */
    if (in_flags & COL_CMPIN_PROP_LEN) {
        if (first->property_len != second->property_len) {
            result = NONZERO;
            /* Do we need to tell who is greater? */
            if ((out_flags) && (first->property_len < second->property_len)) {
                    *out_flags |= COL_CMPOUT_PROP_LEN;
            }
        }
    }

    /* Check if we are told to compare types */
    if (in_flags & COL_CMPIN_TYPE) {
        if (first->type != second->type) result = NONZERO;
    }

    /* Check if we need to compare data length */
    if (in_flags & COL_CMPIN_DATA_LEN) {
        if (first->length != second->length) {
            result = NONZERO;
            /* Do we need to tell who is greater? */
            if ((out_flags) && (first->length < second->length)) {
                    *out_flags |= COL_CMPOUT_DATA_LEN;
            }
        }
    }

    /* Check if we need to compare data */
    if (in_flags & COL_CMPIN_DATA) {
        if (first->type == second->type) {
            switch(first->type) {

            case COL_TYPE_STRING:
                if (first->length == second->length) {
                    cmpres = strncmp((const char *)first->data,
                                     (const char *)second->data,
                                     first->length);

                    if (cmpres != 0) {
                        result = NONZERO;
                        if (cmpres < 0) {
                            /* Second is greater */
                            if (out_flags) *out_flags |= COL_CMPOUT_DATA;
                        }
                    }

                }
                else result = NONZERO;
                break;

            case COL_TYPE_BINARY:
                if (first->length == second->length) {
                    cmpres = memcmp(first->data,
                                    second->data,
                                    first->length);

                    if (cmpres != 0) result = NONZERO;
                }
                else result = NONZERO;
                break;

            case COL_TYPE_INTEGER:
                /* Use macro to match data */
                TYPED_MATCH(int);
                break;

            case COL_TYPE_UNSIGNED:
                /* Use macro to match data */
                TYPED_MATCH(unsigned);
                break;

            case COL_TYPE_LONG:
                /* Use macro to match data */
                TYPED_MATCH(long);
                break;

            case COL_TYPE_ULONG:
                /* Use macro to match data */
                TYPED_MATCH(unsigned long);
                break;

            case COL_TYPE_DOUBLE:
                /* Use macro to match data */
                TYPED_MATCH(double);
                break;

            case COL_TYPE_BOOL:
                /* Use macro to match data */
                TYPED_MATCH(unsigned char);
                break;

            /* These are never same */
            case COL_TYPE_COLLECTION:
            case COL_TYPE_COLLECTIONREF:
            case COL_TYPE_END:
            default:
                result = NONZERO;
                break;
            }

        }
        else result = NONZERO;
    }

    TRACE_FLOW_NUMBER("col_compare_items. Exit. Returning:", result);
    return result;
}

/* Sort collection */
int col_sort_collection(struct collection_item *col,
                        unsigned cmp_flags,
                        unsigned sort_flags)
{
    int error = EOK;

    struct collection_item *current;
    struct collection_header *header;
    struct collection_item **array;
    struct collection_item *temp_item;
    struct collection_item *other;
    size_t size;
    int ind, last;
    int i, j;
    int res;
    unsigned out_flags;

    TRACE_FLOW_STRING("col_sort_collection", "Entry.");

    TRACE_INFO_NUMBER("Comparison flags:", cmp_flags);
    TRACE_INFO_NUMBER("Sort flags:", sort_flags);

    if ((col == NULL) || (col->type != COL_TYPE_COLLECTION)) {
        TRACE_ERROR_STRING("Collecton must not ne NULL", "");
        return EINVAL;
    }

    /* This will be a fast and simple implementation for now */
    header = (struct collection_header *)(col->data);

    if ((sort_flags & COL_SORT_SUB) &&
        (sort_flags & COL_SORT_MYSUB) &&
        (header->reference_count > 1)) {
        TRACE_FLOW_STRING("col_sort_collection", "Exit.");
        return error;
    }

    size = sizeof(struct collection_item *) * (header->count - 1);
    array = (struct collection_item **)malloc(size);
    if (array == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate memory", ENOMEM);
        return ENOMEM;
    }

    /* Fill array */
    current = col->next;
    ind = 0;
    while (current != NULL) {
        TRACE_INFO_STRING("Item:", current->property);
        array[ind] = current;
        if ((sort_flags & COL_SORT_SUB) &&
            (array[ind]->type == COL_TYPE_COLLECTIONREF)) {
            /* If we found a subcollection and we need to sort it
             * then sort it.
             */
            other = *((struct collection_item **)(array[ind]->data));
            error = col_sort_collection(other, cmp_flags, sort_flags);
            if (error) {
                TRACE_ERROR_NUMBER("Subcollection sort failed", error);
                free(array);
                return error;
            }
        }
        ind++;
        current = current->next;
    }

    last = ind - 1;

    for (i = 0; i < last; i++) {

        TRACE_INFO_STRING("Arg1:", array[i]->property);
        TRACE_INFO_STRING("Arg2:", array[i + 1]->property);

        res = col_compare_items(array[i],
                                array[i + 1],
                                cmp_flags,
                                &out_flags);

        TRACE_INFO_STRING("Result:", ((res == 0) ? "same" : "different"));
        TRACE_INFO_NUMBER("Out flags", out_flags);

        /* If they are not same and second is not greater
         * in any way then we need to swap them */
        if ((res != 0) && (out_flags == 0)) {
            /* Swap */
            TRACE_INFO_STRING("Swapping:", "");
            TRACE_INFO_STRING("Item:", array[i]->property);
            TRACE_INFO_STRING("Item:", array[i + 1]->property);

            temp_item = array[i];
            array[i] = array[i + 1];
            array[i + 1] = temp_item;

            /* But we need to go up bubbling this item
             */
            j = i;
            while (j > 0) {
                res = col_compare_items(array[j - 1],
                                        array[j],
                                        cmp_flags,
                                        &out_flags);
                /* If they are not same and second is not greater
                 * in any way then we need to swap them */
                if ((res != 0) && (out_flags == 0)) {
                    /* Swap */
                    temp_item = array[j - 1];
                    array[j - 1] = array[j];
                    array[j] = temp_item;
                }
                else break;
                j--;
            }
        }
    }

    /* Build the chain back */
    if (sort_flags & COL_SORT_DESC) {
        col->next = array[last];
        for (i = last; i > 0 ; i--) {
            array[i]->next = array[i - 1];
        }
        array[0]->next = NULL;
        header->last = array[0];
    }
    else {
        col->next = array[0];
        for (i = 0; i < last ; i++) {
            array[i]->next = array[i + 1];
        }
        array[last]->next = NULL;
        header->last = array[last];
    }

    free(array);

    TRACE_FLOW_STRING("col_sort_collection", "Exit.");
    return error;

}
