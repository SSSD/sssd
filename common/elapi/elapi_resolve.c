/*
    ELAPI

    Module contains functions to resolve the event.

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
#include <errno.h>  /* for errors */
#include <string.h> /* for strcmp() */

#include "elapi_priv.h"
#include "elapi_event.h"
/* #include "elapi_subst.h" */
#include "trace.h"
#include "config.h"

/*****************************************/
/* Individual callbacks are defined here */
/*****************************************/
/* Timestamp resoltion callback */
int elapi_timestamp_cb(struct elapi_resolve_data *resolver,
                       struct collection_item *item,
                       int *skip)
{
    int error = EOK;
    char timestamp[TIME_ARRAY_SIZE + 1];
    int length;

    TRACE_FLOW_STRING("elapi_timestamp_cb", "Entry");

    /* Construct the time stamp */
    length = strftime(timestamp,
                        TIME_ARRAY_SIZE,
                        (const char *)(col_get_item_data(item)),
                        &(resolver->local_time));

    /* Update the time stamp item */
    error = col_modify_str_item(item,
                                NULL,
                                timestamp,
                                length + 1);

    TRACE_FLOW_NUMBER("elapi_timestamp_cb. Exit. Returning", error);
    return error;
}

/* UTC time resolution callback */
int elapi_utctime_cb(struct elapi_resolve_data *resolver,
                       struct collection_item *item,
                       int *skip)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_utctime_cb", "Entry");

    /* Update the UTC item */
    error = col_modify_int_item(item,
                                NULL,
                                (int)(resolver->tm));

    TRACE_FLOW_NUMBER("elapi_utctime_cb. Exit. Returning", error);
    return error;
}

/* Offset resolution callback */
int elapi_offset_cb(struct elapi_resolve_data *resolver,
                       struct collection_item *item,
                       int *skip)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_offset_cb", "Entry");

    /* Update the offset item */
    error = col_modify_int_item(item,
                                NULL,
                                (int)(resolver->offset));

    TRACE_FLOW_NUMBER("elapi_offset_cb. Exit. Returning", error);
    return error;
}


/* Message resolution callback */
int elapi_message_cb(struct elapi_resolve_data *resolver,
                       struct collection_item *item,
                       int *skip)
{
    int error = EOK;
    /* int length; */
    /* char *result; */

    TRACE_FLOW_STRING("elapi_message_cb", "Entry");

    /* FIXME: Resolve message here */
    /* Function is not yet implemented ...
    error = elapi_sprintf(&result,
                          &length,
                          (const char *)col_get_item_data(item),
                          resolver->event);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to build message", error);
        return error;
    }

    error = col_modify_str_item(item,
                                NULL,
                                result;
                                length + 1);
    free(result);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to modify message item", error);
        return error;
    }
    */

    TRACE_FLOW_NUMBER("elapi_message_cb. Exit. Returning", error);
    return error;
}


/*****************************************/
/* Array of structures for resolution of
 * the different event properties.
 */
struct elapi_resolve_list elapi_known_fields[] = {
    { E_TIMESTAMP, { COL_TYPE_STRING,   elapi_timestamp_cb }},
    { E_UTCTIME,   { COL_TYPE_INTEGER,  elapi_utctime_cb   }},
    { E_OFFSET,    { COL_TYPE_INTEGER,  elapi_offset_cb    }},
    { E_MESSAGE,   { COL_TYPE_STRING,   elapi_message_cb   }},
    /* ADD NEW CALLBACKS HERE */
    { NULL,        { COL_TYPE_ANY,      NULL }}
};




/*****************************************/
/* A callback function to do substitutions
 * of different properties as we copy the event.
 */
static int elapi_resolve_item(struct collection_item *item,
                              void *ext_data,
                              int *skip)
{
    int error = EOK;
    struct elapi_resolve_data *resolver;
    struct collection_item *res_item;
    struct elapi_rslv_item_data *rslv_pair;
    int res;

    TRACE_FLOW_STRING("elapi_resolve_item", "Entry");

    /* Do we care about this field ? */
    if (strncmp(col_get_item_property(item, NULL),
                E_PREFIX,
                E_PREFIX_LEN) != 0) {
        TRACE_FLOW_STRING("elapi_resolve_item. Skipping resoltion.", "Exit");
        return EOK;
    }

    /* This is an internal field that might need resolution */
    resolver = (struct elapi_resolve_data *)ext_data;

    /* NOTE: This iteration loop uses advanced iterator
     * capabilities. Read more about it before you decide
     * to use this code as an example.
     */
    while (1) {

        /* Advance to next item in the list */
        error = col_iterate_collection(resolver->handle->resolve_list,
                                       &res_item);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to iterate collection", error);
            return error;
        }

        /* Are we done ? This means we looped and did not find
         * the item. */
        if (res_item == NULL) break;

        /* Compare items */
        res = col_compare_items(item,
                                res_item,
                                COL_CMPIN_PROP_EQU,
                                NULL);
        if (res == 0) {
            /* Item names are the same, so drill down and get expected type. */
            rslv_pair = *((struct elapi_rslv_item_data **)col_get_item_data(res_item));
            /* Make sure that types matched too */
            if (rslv_pair->type == col_get_item_type(item)) {
                /* This is the item we need to resolve so resolve */
                error = rslv_pair->resolve_cb(resolver,
                                              item,
                                              skip);
                if (error) {
                    TRACE_ERROR_NUMBER("Failed to resolve item", error);
                    return error;
                }

                /* Pin down the iterator here */
                col_pin_iterator(resolver->handle->resolve_list);

                /* Break out of loop */
                break;
            }
        }
    }
    TRACE_FLOW_STRING("elapi_resolve_item", "Exit");
    return error;
}


/* Resolve event */
int elapi_resolve_event(struct collection_item **final_event,
                        struct collection_item *event,
                        struct elapi_dispatcher *handle)
{
    int error = EOK;
    struct elapi_resolve_data resolver;
    struct collection_item *new_event;
    time_t local;
    time_t utc;

    TRACE_FLOW_STRING("elapi_create_event_ctx", "Entry");

    /* Prepeare the resolver */
    resolver.event = event;
    resolver.handle = handle;
    /* Get seconds */
    resolver.tm = time(NULL);
    /* Convert to local and UTC structured time */
    localtime_r(&resolver.tm, &(resolver.local_time));
    gmtime_r(&resolver.tm, &(resolver.utc_time));
    /* Convert back */
    utc = mktime(&(resolver.utc_time));
    local = mktime(&(resolver.local_time));
    /* Get offset - it is safe to typecast to int here */
    resolver.offset = (int)(difftime(local, utc));

    /* NOTE: We will use FLATDOT mode.
     * We will see what people have to say
     * about this approach...
     */
    error = col_copy_collection_with_cb(&new_event,
                                        event,
                                        NULL,
                                        COL_COPY_FLATDOT,
                                        elapi_resolve_item,
                                        (void *)&resolver);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to resolve the event", error);
        return error;
    }

    *final_event = new_event;

    TRACE_FLOW_STRING("elapi_create_event_ctx", "Exit");
    return error;
}

/* Function to initialize resolution list */
int elapi_init_resolve_list(struct collection_iterator **list)
{
    int error = EOK;
    struct elapi_resolve_list *current;
    struct collection_item *col = NULL;
    struct collection_iterator *iterator;
    struct elapi_rslv_item_data *bin_data;

    TRACE_FLOW_STRING("elapi_init_resolve_list", "Entry");

    /* Create collection of fields that we know how to process */
    error = col_create_collection(&col,
                                  ELAPI_RESOLVE_ITEM,
                                  COL_CLASS_ELAPI_RES_ITEM);

    if (error) {
        TRACE_ERROR_NUMBER("Failed to create collection", error);
        return error;
    }

    /* Loop through the static array and turn it into a collection */
    current = elapi_known_fields;
    while (current->name) {
        bin_data = &(current->resolve_item);
        error = col_add_binary_property(col,
                                        NULL,
                                        current->name,
                                        (void *)&bin_data,
                                        sizeof(struct elapi_rslv_item_data *));
        if (error) {
            TRACE_ERROR_NUMBER("Failed to add item resolver", error);
            col_destroy_collection(col);
            return error;
        }

        current++;
    }

    /* Now bind iterator */
    error = col_bind_iterator(&iterator, col, COL_TRAVERSE_FLAT);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to bind collection", error);
        col_destroy_collection(col);
        return error;
    }

    /* We do not need the collection itself - we have iterator */
    col_destroy_collection(col);

    *list = iterator;

    TRACE_FLOW_STRING("elapi_init_resolve_list", "Exit");
    return error;
}
