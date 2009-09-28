/*
    ELAPI

    Module contains functions related to format substitution

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
#include <string.h>
#include <stdio.h>
#include "elapi_priv.h"
#include "trace.h"
#include "config.h"

/* Reasonable size for one event */
/* FIXME: may be it would make sense to make it configurable ? */
#define ELAPI_SUBST_BLOCK      256

/* Calculate the potential size of the item */
static unsigned elapi_get_item_len(int type, int raw_len)
{
    int serialized_len = 0;

    TRACE_FLOW_STRING("elapi_get_item_len", "Entry point");

    switch (type) {
    case COL_TYPE_INTEGER:
    case COL_TYPE_UNSIGNED:
    case COL_TYPE_LONG:
    case COL_TYPE_ULONG:
        serialized_len = MAX_LONG_STRING_LEN;
        break;

    case COL_TYPE_STRING:
        serialized_len = raw_len;
        break;

    case COL_TYPE_BINARY:
        serialized_len = raw_len * 2;
        break;

    case COL_TYPE_DOUBLE:
        serialized_len = MAX_DOUBLE_STRING_LEN;
        break;

    case COL_TYPE_BOOL:
        serialized_len = MAX_BOOL_STRING_LEN;
        break;

    default:
        serialized_len = 0;
        break;
    }

    TRACE_FLOW_STRING("elapi_get_item_len", "Exit point");
    return (uint32_t)serialized_len;
}


/* Function to serialize one item */
static int elapi_sprintf_item(struct elapi_data_out *out_data,
                              struct collection_item *item)
{
    int error = EOK;
    uint32_t projected_len;
    uint32_t used_len;
    uint32_t item_len;
    void *data;
    int type;
    int i;

    TRACE_FLOW_STRING("elapi_sprintf_item", "Entry");

    /* Get projected length of the item */
    item_len = col_get_item_length(item);
    type = col_get_item_type(item);
    projected_len = elapi_get_item_len(type, item_len);

    TRACE_INFO_NUMBER("Expected data length: ", projected_len);

    /* Make sure we have enough space */
    if (out_data->buffer == NULL) {
        TRACE_INFO_STRING("First time use.", "");
        /* Add null terminating zero */
        projected_len++;
    }

    /* Grow buffer if needed */
    error = elapi_grow_data(out_data,
                            projected_len,
                            ELAPI_SUBST_BLOCK);
    if (error) {
        TRACE_ERROR_NUMBER("Error. Failed to allocate memory.", error);
        return error;
    }

    data = col_get_item_data(item);

    /* Add the value */
    switch (type) {
    case COL_TYPE_STRING:

        /* Item's length includes trailing 0 for data items */
        used_len = item_len - 1;
        memcpy(&out_data->buffer[out_data->length],
                (const char *)(data),
                used_len);
        out_data->buffer[out_data->length + used_len] = '\0';
        break;

    case COL_TYPE_BINARY:

        for (i = 0; i < item_len; i++) {
            sprintf((char *)&out_data->buffer[out_data->length + i * 2],
                    "%02X", (unsigned int)(((const unsigned char *)(data))[i]));
        }
        used_len = item_len * 2;
        /* We need it here for the case item_len = 0 */
        out_data->buffer[out_data->length + used_len] = '\0';
        break;

    case COL_TYPE_INTEGER:
        used_len = sprintf((char *)&out_data->buffer[out_data->length],
                           "%d", *((const int *)(data)));
        break;

    case COL_TYPE_UNSIGNED:
        used_len = sprintf((char *)&out_data->buffer[out_data->length],
                           "%u", *((const unsigned int *)(data)));
        break;

    case COL_TYPE_LONG:
        used_len = sprintf((char *)&out_data->buffer[out_data->length],
                           "%ld", *((const long *)(data)));
        break;

    case COL_TYPE_ULONG:
        used_len = sprintf((char *)&out_data->buffer[out_data->length],
                           "%lu", *((const unsigned long *)(data)));
        break;

    case COL_TYPE_DOUBLE:
        used_len = sprintf((char *)&out_data->buffer[out_data->length],
                           "%.4f", *((const double *)(data)));
        break;

    case COL_TYPE_BOOL:
        used_len = sprintf((char *)&out_data->buffer[out_data->length],
                           "%s",
                           (*((const unsigned char *)(data))) ? "true" : "false");
        break;

    default:
        out_data->buffer[out_data->length] = '\0';
        used_len = 0;
        break;
    }

    /* Adjust length */
    out_data->length += used_len;

    TRACE_INFO_STRING("Data: ", (char *)out_data->buffer);

    TRACE_FLOW_STRING("elapi_sprintf_item", "Exit");
    return error;

}

/* Lookup item hoping that items in message are somewhat ordered.
 * If there is some ordering we will save on performance.
 * If not we will not loos against a standard lookup.
 */
static struct collection_item *elapi_lookup_item(const char *start,
                                                 int length,
                                                 struct collection_iterator *iterator)
{
    int error = EOK;
    struct collection_item *found = NULL;
    const char *property;
    int property_len;
    uint64_t hash;

    TRACE_FLOW_STRING("elapi_lookup_item", "Entry");

    /* Prepare hash */
    hash = col_make_hash(start, length, NULL);

    /* NOTE: This iteration loop uses advanced iterator
     * capabilities. Read more about it before you decide
     * to use this code as an example.
     */
    while (1) {

        /* Advance to next item in the list */
        error = col_iterate_collection(iterator,
                                       &found);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to iterate collection", error);
            return NULL;
        }

        /* Are we done ? This means we looped and did not find
         * the item. */
        if (found == NULL) break;

        property = col_get_item_property(found, &property_len);

        /* Compare item and the property */
        if ((hash == col_get_item_hash(found)) &&
            (length == property_len) &&
            (strncasecmp(start, property, length) == 0)) {
            /* This is our item !!! */
            /* Pin down the iterator here */
            col_pin_iterator(iterator);

            /* Break out of loop */
            break;
        }
    }

    TRACE_FLOW_STRING("elapi_lookup_item", "Exit");
    return found;
}


/* Function to parse format string */
static const char *elapi_parse_format(const char *start,
                                      int *length,
                                      struct collection_item **item,
                                      struct collection_iterator *iterator)
{
    const char *runner;
    const char *bracket;
    const char *name_start;

    TRACE_FLOW_STRING("elapi_parse_format", "Entry");
    if ((start == NULL) || (*start == '\0')) {
        TRACE_FLOW_STRING("String is empty", "Return");
        return NULL;
    }

    runner = start;

    while (1) {
        /* First check for end of the string */
        if (*runner == '\0') {
            TRACE_FLOW_STRING("Found last token", start);
            *length = runner - start;
            return runner;
        }

        /* Is it the beginning of the field substitution? */
        if (*runner == '%') {
            /* Check for bracket */
            if (*(runner + 1) == '(') {
                /* Search for closing one */
                name_start = runner + 2;
                bracket = name_start;
                while (1) {
                    /* Check for the end */
                    if (*bracket == '\0') {
                        TRACE_FLOW_STRING("No closing bracket", start);
                        *length = bracket - start;
                        return bracket;
                    }
                    /* Did we find closing backet? */
                    if (*bracket == ')') {
                        TRACE_FLOW_STRING("Bracket is found: ", name_start);
                        /* There might be specific format specifiers */
                        if (*name_start == '!') {
                            /* Force rewind of the
                             * iterator */
                            col_rewind_iterator(iterator);
                            name_start++;
                        }

                        /* FIXME: Add other specifiers here...
                         * Specifier that can be supported in future
                         * might expand multi value property
                         * to a list of values separated by
                         * provided symbol.
                         */

                        *item = elapi_lookup_item(name_start,
                                                  bracket - name_start,
                                                  iterator);
                        bracket++;
                        if (*item == NULL) {
                            /* The item is not known (or error) */
                            TRACE_FLOW_STRING("No item in event", name_start);
                            *length = bracket - start;
                            return bracket;
                        }

                        /* Item is found */
                        TRACE_FLOW_STRING("Item found: ", name_start);
                        *length = runner - start;
                        return bracket;
                    }
                    bracket++;
                }
            }
        }
        runner++;
    }
    /* This point is unreachable */
}

/* Function to place the event items into the formatted string */
int elapi_sprintf(struct elapi_data_out *out_data,
                  const char *format_str,
                  struct collection_item *event)
{
    const char *start;
    int length;
    struct collection_item *item;
    struct collection_iterator *iterator = NULL;
    const char *result;
    int error;

    TRACE_FLOW_STRING("elapi_sprintf", "Entry");

    /* Create iterator - by thus time cevent is resolved and should
     * be a flattened collection. At least this is the assumption.
     */
    error = col_bind_iterator(&iterator, event, COL_TRAVERSE_IGNORE);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to bind iterator", error);
        return error;
    }

    start = format_str;

    while(1) {

        item = NULL;
        length = 0;

        /* Parse format definition */
        result = elapi_parse_format(start, &length, &item, iterator);
        if (result == NULL) {
            TRACE_INFO_STRING("Done parsing string", "");
            break;
        }

        /* Apply parsed data */
        if (length > 0) {
            error = elapi_grow_data(out_data,
                                    length + 1,
                                    ELAPI_SUBST_BLOCK);
            if (error) {
                TRACE_ERROR_NUMBER("Error. Failed to allocate memory.", error);
                col_unbind_iterator(iterator);
                return error;
            }

            memcpy(&out_data->buffer[out_data->length],
                    (const char *)(start),
                    length);

            out_data->length += length;
            /* We asked for this one extra byte above */
            out_data->buffer[out_data->length] = '\0';
        }

        if (item != NULL) {
            TRACE_INFO_NUMBER("Need to output item", error);
            error = elapi_sprintf_item(out_data, item);
            if (error) {
                TRACE_ERROR_NUMBER("Error. Failed to allocate memory.", error);
                col_unbind_iterator(iterator);
                return error;
            }
        }

        start = result;
    }

    col_unbind_iterator(iterator);

    TRACE_FLOW_STRING("elapi_sprintf", "Exit");
    return error;
}
