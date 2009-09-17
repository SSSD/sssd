/*
    ELAPI

    Implementation of the ELAPI logging interface.

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
#include <stdio.h>      /* for printf() - temporarily */
#include <stdlib.h>     /* for malloc() */

#include "elapi_priv.h"
#include "elapi_event.h"
#include "elapi_sink.h"
#include "trace.h"
#include "config.h"
#include "ini_config.h"

#include "collection_tools.h" /*temporarily */

/* Buffer size for time string */
#define MAX_TIMESTR         200

/* I was told during review that I have to hard code the name.
 * So it is hardcoded now.
 */
#define ELAPI_DEFAULT_ERROR_FILE "elapiconf.err"

/* Handler for logging through the targets */
int elapi_tgt_cb(const char *target,
                 int target_len,
                 int type,
                 void *data,
                 int length,
                 void *passed_data,
                 int *stop)
{
    int error = EOK;
    struct elapi_tgt_data *target_data;
    struct elapi_tgt_ctx *context;

    TRACE_FLOW_STRING("elapi_tgt_cb", "Entry.");

    /* Skip header */
    if (type == COL_TYPE_COLLECTION) {
        TRACE_FLOW_STRING("elapi_tgt_cb - skip header", "Exit.");
        return EOK;
    }

    target_data = (struct elapi_tgt_data *)(passed_data);
    context = *((struct elapi_tgt_ctx **)(data));

    /* Check if we need to log this event into this target */
    TRACE_INFO_NUMBER("EVENT IS LOGGED INTO:", target_data->target_mask);
    TRACE_INFO_NUMBER("TARGET VALUE IS:", context->target_value);

    if ((target_data->target_mask & context->target_value) == 0) {
        TRACE_INFO_STRING("Current event will NOT be logged into the target:", target);
        return EOK;
    }

    TRACE_INFO_STRING("Current event will be logged into the target:", target);

    /* FIXME THIS IS A PLACEHOLDER FUNCTION FOR NOW */

    printf("\n\n\nPROCESSING EVENT:\n");
    col_debug_collection(target_data->event, COL_TRAVERSE_DEFAULT);

    /* Log event */
    error = elapi_tgt_submit(target_data->handle, context, target_data->event);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to submit event to target", error);
        return error;
    }


    TRACE_FLOW_STRING("elapi_tgt_cb", "Exit.");
    return EOK;
}

/* Internal target cleanup function */
int elapi_tgt_free_cb(const char *target,
                      int target_len,
                      int type,
                      void *data,
                      int length,
                      void *passed_data,
                      int *stop)
{
    TRACE_FLOW_STRING("elapi_tgt_free_cb", "Entry.");

    /* Skip header */
    if (type == COL_TYPE_COLLECTION) {
        TRACE_FLOW_STRING("elapi_tgt_free_cb - skip header", "Exit.");
        return EOK;
    }

    elapi_tgt_destroy(*((struct elapi_tgt_ctx **)(data)));

    TRACE_FLOW_STRING("elapi_tgt_free_cb", "Exit.");
    return EOK;
}

/* Function to add a sink to the collection */
/* This function belongs to this module.
 * It adds sink into the collection
 * of sinks inside dispatcher and puts
 * reference into the target's reference list.
 */
/* FIXME - other arguments might be added later */
int elapi_sink_add(struct collection_item **sink_ref,
                   const char *sink,
                   struct elapi_dispatcher *handle)
{
    int error = EOK;
    struct elapi_sink_ctx *sink_context = NULL;

    TRACE_FLOW_STRING("elapi_sink_add", "Entry");

    TRACE_INFO_STRING("Evaluating sink:", sink);
    TRACE_INFO_NUMBER("Sink reference before call:", *sink_ref);

    /* Get the sink from the list */
    error = col_get_item(handle->sink_list,
                         sink,
                         COL_TYPE_ANY,
                         COL_TRAVERSE_DEFAULT,
                         sink_ref);

    TRACE_INFO_NUMBER("Sink evaluation returned", error);
    TRACE_INFO_NUMBER("Sink reference after call:", *sink_ref);

    if (error) {
        TRACE_ERROR_NUMBER("Search returned error", error);
        return error;
    }

    if (!(*sink_ref)) {
        TRACE_FLOW_STRING("No such sink yet, adding new sink:", sink);

        /* Create a sink object */
        error = elapi_sink_create(&sink_context, sink, handle->ini_config, handle->appname);
        if (error != 0) {
            TRACE_ERROR_NUMBER("Failed to add sink data as property", error);
            /* If create failed there is nothing to destroy */
            return error;
        }

        /* If there was an internal error but sink is optional
         * no error is returned but context is NULL.
         * We need to check for this situation.
         */
        if (sink_context) {
            TRACE_FLOW_STRING("Loaded sink:", sink);
            /* We got a valid sink so add it to the collection */
            error = col_add_binary_property_with_ref(handle->sink_list,
                                                     NULL,
                                                     sink,
                                                     (void *)(&sink_context),
                                                     sizeof(struct elapi_sink_ctx *),
                                                     sink_ref);
            if (error != 0) {
                TRACE_ERROR_NUMBER("Failed to add sink data as property", error);
                elapi_sink_destroy(sink_context);
                return error;
            }
        }
        else {
            *sink_ref = NULL;
            TRACE_FLOW_STRING("Setting sink reference to NULL", "");
        }
    }

    TRACE_FLOW_NUMBER("elapi_sink_add returning", error);
    return error;
}

/* Destroy target object */
void elapi_tgt_destroy(struct elapi_tgt_ctx *context)
{
    TRACE_FLOW_STRING("elapi_tgt_destroy", "Entry.");

    TRACE_INFO_NUMBER("Target address in cleanup:", context);

    if (context) {
        TRACE_INFO_STRING("Deleting the list of references to sinks", "");
        col_destroy_collection(context->sink_ref_list);
        /* FIXME - add other cleanup for other things that will be a part
         * of the target context.
         */
        free(context);
    }

    TRACE_FLOW_STRING("elapi_tgt_destroy", "Exit.");

}

/* Allocate target context and load sinks to it */
int elapi_tgt_create(struct elapi_tgt_ctx **context,
                     const char *target,
                     struct elapi_dispatcher *handle)
{
    int error = EOK;
    struct collection_item *sink_cfg_item = NULL;
    struct collection_item *value_cfg_item = NULL;
    struct elapi_tgt_ctx *target_context;
    char **sinks;
    char **current_sink;
    struct collection_item *sink_ref;
    unsigned count;

    TRACE_FLOW_STRING("elapi_tgt_create", "Entry.");

    /* Get list of sinks for this target from config */
    error = get_config_item(target,
                            ELAPI_SINKS,
                            handle->ini_config,
                            &sink_cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read configuration returned error", error);
        return error;
    }

    /* Do we have sinks? */
    if (sink_cfg_item == NULL) {
        /* There is no list of targets this is bad configuration - return error */
        TRACE_ERROR_STRING("Required key is missing in the configuration.", "Fatal Error!");
        return ENOENT;
    }

    /* Allocate context */
    target_context = (struct elapi_tgt_ctx *)calloc(1, sizeof(struct elapi_tgt_ctx));
    if (target_context == NULL) {
        TRACE_ERROR_NUMBER("Memory allocation failed. Error", ENOMEM);
        return ENOMEM;
    }

    /* Assign target's value */
    error = get_config_item(target,
                            ELAPI_TARGET_VALUE,
                            handle->ini_config,
                            &value_cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read configuration returned error", error);
        elapi_tgt_destroy(target_context);
        return error;
    }

    /* Do we have value? */
    if (value_cfg_item == NULL) {
        TRACE_INFO_STRING("Value for target is not defined.", "Assume ANY.");
        target_context->target_value = ELAPI_TARGET_ALL;
    }
    else {
        target_context->target_value = (uint32_t)get_unsigned_config_value(value_cfg_item,
                                                                           1,
                                                                           ELAPI_TARGET_ALL,
                                                                           &error);
        /* NOTE: I will check and fail here on error rather than do a best effort
         * for now. We can switch to less rigorous checking when the INI
         * validation library/utility becomes available.
         */
        if (error) {
            TRACE_ERROR_NUMBER("Failed to convert value form INI file", error);
            elapi_tgt_destroy(target_context);
            return error;
        }
    }

    TRACE_INFO_NUMBER("Value for target is:", target_context->target_value);


    /* Allocate collection to store sink references for this target */
    error = col_create_collection(&(target_context->sink_ref_list),
                                  ELAPI_SINK_REFS,
                                  COL_CLASS_ELAPI_SINK_REF);
    if (error != 0) {
        TRACE_ERROR_NUMBER("Failed to create sink collection. Error", error);
        elapi_tgt_destroy(target_context);
        return error;
    }

    /* Get list of sinks from config. Make sure we free it later */
    sinks = get_string_config_array(sink_cfg_item, NULL, NULL, NULL);

    /* For each sink in the list create sink context object and load sink */
    current_sink = sinks;
    while (*current_sink != NULL) {

        TRACE_INFO_STRING("Current sink", *current_sink);

        /* Load sink if it is not loaded yet */
        sink_ref = NULL;
        error = elapi_sink_add(&sink_ref,
                               *current_sink,
                               handle);
        if (error) {
            /* NOTE - we might decide to lax some of the checks
             * like this later and be satisfied with at least one
             * sink in the list. Subject for discussion...
             */
            TRACE_ERROR_NUMBER("Failed to add sink", error);
            elapi_tgt_destroy(target_context);
            free_string_config_array(sinks);
            return error;
        }

        /* It might be that is was an error wit the optional sink so
         * we need to check if the reference is not NULL;
         */
        if (sink_ref) {
            /* Add reference to it into the target object */
            error = col_add_binary_property(target_context->sink_ref_list, NULL,
                                            *current_sink, (void *)(&sink_ref),
                                            sizeof(struct collection_item *));
            if (error != 0) {
                TRACE_ERROR_NUMBER("Failed to add sink reference", error);
                elapi_tgt_destroy(target_context);
                free_string_config_array(sinks);
                return error;
            }
        }
        else {
            TRACE_INFO_STRING("Sink reference is NULL.", "Skipping the sink");
        }
        current_sink++;
    }

    free_string_config_array(sinks);

    /* Get count of the references in the list */
    error = col_get_collection_count(target_context->sink_ref_list, &count);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to get count", error);
        elapi_tgt_destroy(target_context);
        return error;
    }

    /* Check count */
    if (count <= 1) {
        /* Nothing but header? - Bad! */
        TRACE_ERROR_NUMBER("No sinks loaded for target!", "This is a fatal error!");
        elapi_tgt_destroy(target_context);
        return ENOENT;
    }

    *context = target_context;

    TRACE_FLOW_STRING("elapi_tgt_create", "Exit.");
    return EOK;
}


/* Function to create a list of targets */
int elapi_tgt_mklist(struct elapi_dispatcher *handle)
{
    int error = EOK;
    char **current_target;
    struct elapi_tgt_ctx *context;


    TRACE_FLOW_STRING("elapi_tgt_mklist", "Entry");

    /* Allocate collection to store target */
    error = col_create_collection(&(handle->target_list),
                                  ELAPI_TARGETS,
                                  COL_CLASS_ELAPI_TARGET);
    if (error != 0) {
        TRACE_ERROR_NUMBER("Failed to create target collection. Error", error);
        /* No cleanup here.
         * The calling function will call a cleanup
         * of the dispatcher as a whole.*/
        return error;
    }

    /* Allocate collection to store sinks */
    error = col_create_collection(&(handle->sink_list),
                                  ELAPI_SINKS,
                                  COL_CLASS_ELAPI_SINK);
    if (error != 0) {
        TRACE_ERROR_NUMBER("Failed to create sink collection. Error", error);
        /* No cleanup here.
         * The calling function will call a cleanup
         * of the dispatcher as a whole.*/
        return error;
    }

    current_target = handle->targets;
    handle->target_counter = 0;

    /* Add targets as properties to the target collection */
    while (*current_target != NULL) {

        TRACE_INFO_STRING("Current target", *current_target);

        /* Allocate target context and load sinks to it */
        context = NULL;
        error = elapi_tgt_create(&context,
                                 *current_target,
                                 handle);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to create target", error);
            return error;
        }

        TRACE_INFO_NUMBER("Target address:", context);

        /* Add created target to the list of targets */
        error = col_add_binary_property(handle->target_list, NULL,
                                        *current_target, (void *)(&context),
                                        sizeof(struct elapi_tgt_ctx *));
        if (error != 0) {
            TRACE_ERROR_NUMBER("Failed to add sink data as property", error);
            /* Need to clean allocated context here if we failed to add it */
            elapi_tgt_destroy(context);
            return error;
        }

        handle->target_counter++;
        current_target++;
    }

    /* Check if we have any targets available */
    if (handle->target_counter == 0) {
        TRACE_ERROR_STRING("No targets", "");
        return ENOENT;
    }

    TRACE_FLOW_STRING("elapi_tgt_mklist", "Returning success");
    return EOK;
}

/* Submit event into the target */
/* FIXME: do we need the whole dispatcher here?
 * probably not.
 * Need to sort out what parts of it we actually
 * need and pass them explicitely.
 * The point is that the target should not
 * know or care about the dispatcher internals
 * passing it here is a violation of the
 * several desing patterns so it should be
 * eventually fixed.
 */
int elapi_tgt_submit(struct elapi_dispatcher *handle,
                     struct elapi_tgt_ctx *context,
                     struct collection_item *event)
{
    int error = EOK;
    struct collection_iterator *iterator;
    struct collection_item *sink_item;
    struct elapi_sink_ctx *ctx;

    TRACE_FLOW_STRING("elapi_tgt_submit", "Entry");

    /* FIXME: General logic of the function
     * should be the following:
     * Get the list of the sinks
     * For each sink
     *    Get its status
     *    Check if the sink is active
     *    If it is active log into it
     *        In error fail over to the next one
     *        else done
     *    else (not active) is it revivable?
     *        If so is it time to revive?
     *            If so mark as active and log into it
     *                If error fail over
     *                else done
     *            else fail over
     *        else fail over
     *    else fail over
     * End for each sink
     *
     * This logic will be implemented
     * in the later patches
     * for now we will try
     * all the sinks without checking status.
     */

    error = col_bind_iterator(&iterator, context->sink_ref_list,
                              COL_TRAVERSE_DEFAULT);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to bind iterator.", error);
        return error;
    }

    while(1) {
        /* Loop through the sink references */
        error = col_iterate_collection(iterator, &sink_item);
        if (error) {
            TRACE_ERROR_NUMBER("Error iterating event:", error);
            col_unbind_iterator(iterator);
            return error;
        }

        /* Are we done ? */
        if (sink_item == NULL) break;

        /* Skip headers */
        if (col_get_item_type(sink_item) == COL_TYPE_COLLECTION) continue;


        /* Dereference the sink item to get context */
        sink_item = *((struct collection_item **)(col_get_item_data(sink_item)));
        ctx = *((struct elapi_sink_ctx **)(col_get_item_data(sink_item)));

        /* FIXME: Check the sink status */

        /* FIXME other parameters might be required... */
        error = elapi_sink_submit(ctx, event);
        if (error) {
            TRACE_ERROR_NUMBER("Error submitting event:", error);
            col_unbind_iterator(iterator);
            return error;
        }

    }

    col_unbind_iterator(iterator);

    TRACE_FLOW_STRING("elapi_tgt_submit", "Exit");
    return EOK;

}


/* If we failed to read configuration record this in the local file */
void elapi_dump_ini_err(struct collection_item *error_list)
{
    FILE *efile;
    char timestr[MAX_TIMESTR];
    time_t time_in_sec;
    struct tm *time_as_struct;
    struct tm time_data;

    TRACE_FLOW_STRING("elapi_dump_ini_err", "Entry point");

    efile = fopen(ELAPI_DEFAULT_ERROR_FILE, "a");
    if (efile == NULL) {
        TRACE_ERROR_STRING("No output available.", "Returning.");
        return;
    }

    time_in_sec = time(NULL);
    time_as_struct = localtime_r(&time_in_sec, &time_data);

    fprintf(efile, "\n\n%*s\n\n", 80, "=");

    if ((time_as_struct != NULL) &&
        (strftime(timestr, sizeof(timestr), E_TIMESTAMP_FORMAT, time_as_struct) == 0)) {
        fprintf(efile, "%s\n", timestr);
    }
    else {
        TRACE_FLOW_STRING("elapi_internal_dump_errors_to_file", "Was not able to process time.");
    }

    fprintf(efile, "\n");
    print_file_parsing_errors(efile, error_list);

    fclose(efile);
    TRACE_FLOW_STRING("elapi_dump_ini_err", "Exit");
}

/****************************************************************************/
/* Functions below are added for debugging purposes                         */
/****************************************************************************/
#ifdef ELAPI_VERBOSE

void elapi_print_sink_ctx(struct elapi_sink_ctx *sink_context)
{
    /* This will not print well on 64 bit but it is just debugging
     * so it is OK to have it.
     */
    printf("Printing sink context using address %p\n", sink_context);

    printf("Mode: %s\n", sink_context->async_mode ? "true" : "false");
    if (sink_context->in_queue) col_print_collection(sink_context->in_queue);
    else printf("Queue is not initialized.\n");

    if (sink_context->pending) col_print_collection(sink_context->pending);
    else printf("Pending list is not initialized.\n");

    if (sink_context->sink_cfg.provider) printf("Provider: %s\n",
                                                sink_context->sink_cfg.provider);
    else printf("Provider is not defined.\n");

    printf("Is provider required? %s\n", ((sink_context->sink_cfg.required > 0) ? "Yes" : "No"));
    printf("On error: %s\n", ((sink_context->sink_cfg.onerror == 0) ? "retry" : "fail"));
    printf("Timout: %d\n", sink_context->sink_cfg.timeout);
    printf("Sync configuration: %s\n", sink_context->sink_cfg.synch ? "true" : "false");

    if (sink_context->sink_cfg.priv_ctx) printf("Private context allocated.\n");
    else printf("Private context is NULL.\n");

    if (sink_context->sink_cfg.libhandle) printf("Lib handle is allocated.\n");
    else printf("Lib handle is NULL.\n");

    if (sink_context->sink_cfg.ability) printf("Capability function is present\n");
    else printf("NO capability function.\n");

    if (sink_context->sink_cfg.cpb_cb.init_cb)  printf("Init callback is OK.\n");
    else printf("Init callback is missing.\n");

    if (sink_context->sink_cfg.cpb_cb.submit_cb)  printf("Submit callback is OK.\n");
    else printf("Submit callback is missing.\n");

    if (sink_context->sink_cfg.cpb_cb.close_cb)  printf("Close callback is OK.\n");
    else printf("Close callback is missing.\n");


}

/* Handler for printing target internals */
static int elapi_sink_ref_dbg_cb(const char *sink,
                                 int sink_len,
                                 int type,
                                 void *data,
                                 int length,
                                 void *passed_data,
                                 int *stop)
{
    struct collection_item *sink_item;
    struct elapi_sink_ctx *sink_context;

    /* Skip header */
    if (type == COL_TYPE_COLLECTION) {
        return EOK;
    }

    sink_item = *((struct collection_item **)(data));

    printf("\nReferenced sink name is: %s\n", col_get_item_property(sink_item, NULL));

    sink_context = *((struct elapi_sink_ctx **)(col_get_item_data(sink_item)));

    elapi_print_sink_ctx(sink_context);


    return EOK;
}

/* Handler for printing sink internals */
static int elapi_sink_dbg_cb(const char *sink,
                             int sink_len,
                             int type,
                             void *data,
                             int length,
                             void *passed_data,
                             int *stop)
{
    struct elapi_sink_ctx *sink_context;

    /* Skip header */
    if (type == COL_TYPE_COLLECTION) {
        return EOK;
    }

    sink_context = *((struct elapi_sink_ctx **)(data));

    printf("\nSink name is: %s\n", sink);

    elapi_print_sink_ctx(sink_context);

    return EOK;
}

/* Handler for printing target internals */
static int elapi_tgt_dbg_cb(const char *target,
                            int target_len,
                            int type,
                            void *data,
                            int length,
                            void *passed_data,
                            int *stop)
{
    struct elapi_tgt_ctx *context;

    /* Skip header */
    if (type == COL_TYPE_COLLECTION) {
        return EOK;
    }

    context = *((struct elapi_tgt_ctx **)(data));

    printf("\nTarget value for target \"%s\" is %d\n", target, context->target_value);
    printf("\nReferenced sinks:\n\n");

    (void)col_traverse_collection(context->sink_ref_list,
                                  COL_TRAVERSE_ONELEVEL,
                                  elapi_sink_ref_dbg_cb,
                                  NULL);

    return EOK;
}



/* Internal function to print dispatcher internals - useful for testing */
void elapi_print_dispatcher(struct elapi_dispatcher *handle)
{
    char **current_target;

    printf("\nPRINTING DISPATCHER INTERNALS\n\n");

    printf("Application name: %s\n", handle->appname != NULL ? handle->appname : "(null)");
    printf("List of target names:\n");

    current_target = handle->targets;
    while (*current_target != NULL) {
        printf("   %s\n",*current_target);
        current_target++;
    }

    printf("Target counter: %d\n", handle->target_counter);
    printf("\n\nTarget collection:\n\n");
    if (handle->target_list) col_debug_collection(handle->target_list, COL_TRAVERSE_DEFAULT);


    printf("\n\nSink collection:\n\n");
    if (handle->sink_list) col_debug_collection(handle->sink_list, COL_TRAVERSE_DEFAULT);
    printf("\n\nConfig collection:\n\n");
    if (handle->ini_config) col_debug_collection(handle->ini_config, COL_TRAVERSE_DEFAULT);
    printf("\nDefault template:\n\n");
    if (handle->default_template) col_debug_collection(handle->default_template, COL_TRAVERSE_DEFAULT);

    printf("\n\nDeep target inspection:\n\n");
    if (handle->target_list) {
        (void)col_traverse_collection(handle->target_list,
                                      COL_TRAVERSE_ONELEVEL,
                                      elapi_tgt_dbg_cb,
                                      NULL);
    }
    printf("\n\nDeep sink inspection:\n\n");
    if (handle->sink_list) {
        (void)col_traverse_collection(handle->sink_list,
                                      COL_TRAVERSE_ONELEVEL,
                                      elapi_sink_dbg_cb,
                                      NULL);
    }
    /* FIXME: Async data... */

    printf("DISPATCHER END\n\n");
    fflush(stdout);
}

#endif
