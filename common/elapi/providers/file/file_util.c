/*
    ELAPI

    Module contains internal utility functions for the file provider.

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
#include <string.h>     /* for strlen() */

/* To be able to serialize on needs to know the guts
 * of the collection structure so have to include
 * private header here.
 */
#include "collection_priv.h"
#include "file_provider.h"
#include "file_util.h"
#include "ini_config.h"
#include "trace.h"
#include "config.h"

#ifdef ELAPI_VERBOSE
/* FIXME: remove when api is stable */
#include "collection_tools.h"
#endif

char empty[] = "";

/* Callback to prepare set for splitting */
static int file_set_clean_cb(const char *property,
                             int property_len,
                             int type,
                             void *data,
                             int length,
                             void *custom_data,
                             int *stop)
{
    int error = EOK;
    TRACE_FLOW_STRING("file_set_clean_cb", "Entry");

    /* Skip header */
    if (type == COL_TYPE_COLLECTION) return EOK;

    /* Clean data */
    *((struct collection_item **)(data)) = NULL;

    TRACE_FLOW_STRING("file_set_clean_cb", "Exit");
    return error;
}

/* Function to split event into two parts by given set */
static int file_split_by_set(struct collection_item **leftovers,
                             struct file_prvdr_cfg *cfg,
                             struct collection_item *event)
{
    int error = EOK;
    struct collection_item *item_event;
    struct collection_item *item_set;
    struct collection_iterator *it_event;
    struct collection_iterator *it_set;
    struct collection_item *lo = NULL;
    int found = 0;
    TRACE_FLOW_STRING("file_split_by_set", "Entry");

    /* First prepare set for use */
    error = col_traverse_collection(cfg->set,
                                    COL_TRAVERSE_ONELEVEL,
                                    file_set_clean_cb,
                                    NULL);
    if (error) {
        TRACE_ERROR_NUMBER("Traverse set failed.", error);
        return error;
    }

    /* If we are going to use leftovers create a collection */
    if (cfg->use_leftovers) {
        error = col_create_collection(&lo,
                                      FILE_LO_NAME,
                                      FILE_LO_CLASS);
        if (error) {
            TRACE_ERROR_NUMBER("Faild to create collection.", error);
            return error;
        }
    }

    /* Now all items from the set are NULLs */
    /* Split the event in two parts */
    /* We need to iterate through the event rather than use a callback. */
    /* Bind iterator */
    error =  col_bind_iterator(&it_event, event, COL_TRAVERSE_FLAT);
    if (error) {
        TRACE_ERROR_NUMBER("Error bind iterator for event failed:", error);
        /* Here and below it is safe to destroy it event if is NULL. */
        col_destroy_collection(lo);
        return error;
    }

    while(1) {
        /* Loop through the event */
        error = col_iterate_collection(it_event, &item_event);
        if (error) {
            TRACE_ERROR_NUMBER("Error iterating event:", error);
            col_unbind_iterator(it_event);
            col_destroy_collection(lo);
            return error;
        }

        /* Are we done ? */
        if (item_event == NULL) break;

        /* Skip headers */
        if (item_event->type == COL_TYPE_COLLECTION) continue;

        /* For each item in the event find an item in the set */
        error =  col_bind_iterator(&it_set, cfg->set, COL_TRAVERSE_ONELEVEL);
        if (error) {
            TRACE_ERROR_NUMBER("Error bind iterator for set failed:", error);
            col_unbind_iterator(it_event);
            col_destroy_collection(lo);
            return error;
        }

        found = 0;
        while(1) {
            /* Loop through the event */
            error = col_iterate_collection(it_set, &item_set);
            if (error) {
                TRACE_ERROR_NUMBER("Error iterating set:", error);
                col_unbind_iterator(it_event);
                col_unbind_iterator(it_set);
                col_destroy_collection(lo);
                return error;
            }

            /* Are we done ? */
            if (item_set == NULL) break;

            /* Skip headers */
            if (item_set->type == COL_TYPE_COLLECTION) continue;

            /* Hashes should match and the data in the set should be NULL,
             * and legths should be same.
             */
            if ((item_event->phash == item_set->phash) &&
                (*((struct collection_item **)(item_set->data)) == NULL) &&
                (item_event->property_len == item_set->property_len)) {
                /* This is a candidate for match - compare strings */
                TRACE_INFO_STRING("Found a good candidate for match.","");
                TRACE_INFO_STRING("Set item:", item_set->property);
                TRACE_INFO_STRING("Event:", item_event->property);

                if (strncasecmp(item_set->property,
                                item_event->property,
                                item_event->property_len) == 0) {
                    TRACE_INFO_STRING("Match found!","");
                    TRACE_INFO_STRING("Set item:", item_set->property);
                    TRACE_INFO_STRING("Event:", item_event->property);

                    *((struct collection_item **)(item_set->data)) = item_event;
                    found = 1;
                    break;
                }
            }
        }
        /* Done with the set */
        col_unbind_iterator(it_set);

        /* Is it a leftover ? */
        if ((!found) && (cfg->use_leftovers)) {
            /* We need to put it in the leftovers pile */
            /* To save time and space we do not care about property name.
             * The property name is going to be in the referenced item.
             */
            error = col_add_binary_property(lo,
                                            NULL,
                                            "",
                                            (void *)(&item_event),
                                            sizeof(struct collection_item *));
            if (error) {
                TRACE_ERROR_NUMBER("Error addding item to leftovers:", error);
                col_unbind_iterator(it_event);
                col_destroy_collection(lo);
                return error;
            }
        }
    }

    /* Done with the event */
    col_unbind_iterator(it_event);

    /* Save leftovers if any */
    *leftovers = lo;

    TRACE_FLOW_STRING("file_spserialized_lo->bufferlit_by_set", "Exit");
    return error;
}

/* Function to serialize one item */
static int file_serialize_item(struct elapi_data_out *out_data,
                               int type,
                               int length,
                               void *data,
                               uint32_t mode,
                               void *mode_cfg)
{
    int error = EOK;
    TRACE_FLOW_STRING("file_serialize_item", "Entry");

    switch(mode) {
    case FILE_MODE_CSV:
        error = file_serialize_csv(out_data,
                                   type,
                                   length,
                                   data,
                                   mode_cfg);
        break;
/* FIXME : add other iterative formats later */
/*
    case FILE_MODE_HTML:
        error = file_serialize_html(out_data,
                                    type,
                                    length,
                                    data,
                                    mode_cfg);
        break;
    case FILE_MODE_XML:
        error = file_serialize_xml(out_data,
                                   type,
                                   length,
                                   data,
                                   mode_cfg);
        break;
    case FILE_MODE_JSON:
        error = file_serialize_json(out_data,
                                    type,
                                    length,
                                    data,
                                    mode_cfg);
        break;
    case FILE_MODE_KVP:
        error = file_serialize_kvp(out_data,
                                   type,
                                   length,
                                   data,
                                   mode_cfg);
        break;
*/
    default:
        TRACE_ERROR_STRING("Unsupported mode", "Fatal error!");
        error = EINVAL;

    }

    TRACE_FLOW_STRING("file_serialize_item", "Exit");
    return error;

}



/* Function to serialize the list */
static int file_serialize_list(struct elapi_data_out **out_data,
                               int append,
                               int reference,
                               struct collection_item *input,
                               uint32_t mode,
                               void *mode_cfg)
{
    int error = EOK;
    struct elapi_data_out *allocated = NULL;
    struct elapi_data_out *to_use = NULL;
    struct collection_iterator *iterator;
    struct collection_item *item;

    TRACE_FLOW_STRING("file_serialize_list", "Entry");

    /* Allocate storage if we are not appending */
    if (!append) {
        error = elapi_alloc_serialized_data(&allocated);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to allocated serialized data", error);
            return error;
        }
        TRACE_INFO_STRING("Allocated new out data", "");
        to_use = allocated;
    }
    else {
        TRACE_INFO_STRING("Appening, use passed in output data", "");
        to_use = *out_data;
    }

    /* FIXME: This logic works for iterative formats only. */
    /* When we implement the free form format this
     * logic should be augmented. */

#ifdef ELAPI_VERBOSE
    /* FIXME: remove when stable */
    col_debug_collection(input, COL_TRAVERSE_FLAT);
#endif


    /* Start iterating */
    error =  col_bind_iterator(&iterator, input, COL_TRAVERSE_FLAT);
    if (error) {
        TRACE_ERROR_NUMBER("Error bind iterator failed:", error);
        return error;
    }

    while(1) {
        /* Loop through the collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            TRACE_ERROR_NUMBER("Error iterating event:", error);
            col_unbind_iterator(iterator);
            /* Free allocated data if we allocated it */
            elapi_free_serialized_data(allocated);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) break;

        /* Skip headers */
        if (item->type == COL_TYPE_COLLECTION) continue;

        /* Got item */
        if (reference) {
            /* Derefernce the item before using */
            item = *((struct collection_item **)(item->data));
        }

        if (item) {
            TRACE_ERROR_NUMBER("Item property", item->property);

            /* Serialize this item */
            error = file_serialize_item(to_use,
                                        item->type,
                                        item->length,
                                        item->data,
                                        mode,
                                        mode_cfg);
        }
        else {
            /* Serialize this item */
            error = file_serialize_item(to_use,
                                        COL_TYPE_BINARY,
                                        0,
                                        NULL,
                                        mode,
                                        mode_cfg);
        }

        if (error) {
            TRACE_ERROR_NUMBER("Failed to serialize item", error);
            col_unbind_iterator(iterator);
            /* Free allocated data if we allocated it */
            elapi_free_serialized_data(allocated);
            return error;
        }
    }
    col_unbind_iterator(iterator);

    *out_data = to_use;

    TRACE_FLOW_STRING("file_serialize_list", "Exit");
    return error;
}

/* Function to log event into sink */
int file_prep_data(struct elapi_data_out **out_data,
                   struct file_prvdr_ctx *ctx,
                   struct collection_item *event)
{
    int error = EOK;
    struct elapi_data_out *serialized = NULL;
    struct elapi_data_out *serialized_lo = NULL;
    struct collection_item *leftovers = NULL;

    TRACE_FLOW_STRING("file_prep_data", "Entry");

    /* Do we need to split the data into two parts by set ? */
    if (ctx->config.set) {
        /* Split collection based on the configured set of fields */
        error = file_split_by_set(&leftovers,
                                  &(ctx->config),
                                  event);
        if (error) {
            TRACE_ERROR_NUMBER("Split collection returned error", error);
            return error;
        }

        /* Serialize main items */
        error = file_serialize_list(&serialized,
                                    FILE_SER_NEW,
                                    FILE_ITEM_REF,
                                    ctx->config.set,
                                    ctx->config.outmode,
                                    ctx->config.main_fmt_cfg);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to serialize main set", error);
            col_destroy_collection(leftovers);
            return error;
        }

        if (ctx->config.use_leftovers) {
            /* Do we have to jam leftovers? */
            if (ctx->config.jam_leftovers) {
                /* Serialise leftovers into one field */
                error = file_serialize_list(&serialized_lo,
                                            FILE_SER_NEW,
                                            FILE_ITEM_REF,
                                            leftovers,
                                            ctx->config.mode_leftovers,
                                            ctx->config.lo_fmt_cfg);
                if (error) {
                    TRACE_ERROR_NUMBER("Failed to serialize main set", error);
                    col_destroy_collection(leftovers);
                    elapi_free_serialized_data(serialized);
                    return error;
                }

                /* Check if we go anything */
                if (serialized_lo->length) {
                    /* Append leftovers item */
                    error = file_serialize_item(serialized,
                                                COL_TYPE_STRING,
                                                serialized_lo->length + 1,
                                                serialized_lo->buffer,
                                                ctx->config.outmode,
                                                ctx->config.main_fmt_cfg);
                }
                else {
                    /* Put empty item */
                    error = file_serialize_item(serialized,
                                                COL_TYPE_BINARY,
                                                0,
                                                NULL,
                                                ctx->config.outmode,
                                                ctx->config.main_fmt_cfg);
                }
                if (error) {
                    TRACE_ERROR_NUMBER("Failed to serialize main set", error);
                    col_destroy_collection(leftovers);
                    elapi_free_serialized_data(serialized);
                    elapi_free_serialized_data(serialized_lo);
                    return error;
                }

                /* Done with the jammed leftovers */
                elapi_free_serialized_data(serialized_lo);
            }
            else {
                /* Leftovers are added as normal fields */
                error = file_serialize_list(&serialized,
                                            FILE_SER_APPEND,
                                            FILE_ITEM_REF,
                                            leftovers,
                                            ctx->config.outmode,
                                            ctx->config.main_fmt_cfg);
                if (error) {
                    TRACE_ERROR_NUMBER("Failed to serialize main set", error);
                    col_destroy_collection(leftovers);
                    elapi_free_serialized_data(serialized);
                    return error;
                }
            }
            /* Do not need leftovers */
            col_destroy_collection(leftovers);
        }
    }
    else {
        /* No set is defined - the whole event is processed */
        error = file_serialize_list(&serialized,
                                    FILE_SER_NEW,
                                    FILE_ITEM_DIRECT,
                                    event,
                                    ctx->config.outmode,
                                    ctx->config.main_fmt_cfg);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to serialize event", error);
            return error;
        }
    }

    *out_data = serialized;

    TRACE_FLOW_STRING("file_prep_data", "Exit");
    return error;

}
