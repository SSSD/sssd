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
int elapi_internal_target_handler(const char *target,
                                  int target_len,
                                  int type,
                                  void *data,
                                  int length,
                                  void *passed_data,
                                  int *stop)
{
    struct elapi_target_pass_in_data *target_data;
    struct elapi_target_context *context;

    TRACE_FLOW_STRING("elapi_internal_target_handler", "Entry.");

    /* Skip header */
    if (type == COL_TYPE_COLLECTION) {
        TRACE_FLOW_STRING("elapi_internal_target_handler - skip header", "Exit.");
        return EOK;
    }

    target_data = (struct elapi_target_pass_in_data *)(passed_data);
    context = *((struct elapi_target_context **)(data));

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

    TRACE_FLOW_STRING("elapi_internal_target_handler", "Exit.");
    return EOK;
}

/* Internal target cleanup function */
int elapi_internal_target_cleanup_handler(const char *target,
                                          int target_len,
                                          int type,
                                          void *data,
                                          int length,
                                          void *passed_data,
                                          int *stop)
{
    TRACE_FLOW_STRING("elapi_internal_target_cleanup_handler", "Entry.");

    /* Skip header */
    if (type == COL_TYPE_COLLECTION) {
        TRACE_FLOW_STRING("elapi_internal_target_cleanup_handler - skip header", "Exit.");
        return EOK;
    }

    elapi_internal_destroy_target(*((struct elapi_target_context **)(data)));

    TRACE_FLOW_STRING("elapi_internal_target_cleanup_handler", "Exit.");
    return EOK;
}



int elapi_internal_sink_handler(const char *sink,
                                int sink_len,
                                int type,
                                void *data,
                                int length,
                                void *passed_data,
                                int *stop)
{
    TRACE_FLOW_STRING("elapi_internal_sink_handler", "Entry.");

    /* FIXME THIS IS A PLACEHOLDER FUNCTION FOR NOW */

    /* Skip header */
    if (type == COL_TYPE_COLLECTION) {
        TRACE_FLOW_STRING("elapi_internal_sink_handler - skip header", "Exit.");
        return EOK;
    }

    printf("Sink: %s\n", sink);

    TRACE_FLOW_STRING("elapi_internal_sink_handler", "Exit.");
    return EOK;
}

/* Internal sink cleanup function */
int elapi_internal_sink_cleanup_handler(const char *sink,
                                        int sink_len,
                                        int type,
                                        void *data,
                                        int length,
                                        void *passed_data,
                                        int *stop)
{
    TRACE_FLOW_STRING("elapi_internal_sink_cleanup_handler", "Entry.");

    /* FIXME THIS IS A PLACEHOLDER FUNCTION FOR NOW */

    printf("Cleaning Sink: %s\n", sink);

    TRACE_FLOW_STRING("elapi_internal_sink_cleanup_handler", "Exit.");
    return EOK;
}

/* Function to add a sink to the collection */
/* FIXME - other arguments might be added later */
int elapi_internal_add_sink(struct collection_item **sink_ref,
                            char *sink,
                            struct elapi_dispatcher *handle)
{
    int error = EOK;
    struct elapi_sink_context sink_context;
    struct collection_item *provider_cfg_item = NULL;

    TRACE_FLOW_STRING("elapi_internal_add_sink", "Entry");

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

        /* First check if this sink is properly configured and get its provider */
        error = get_config_item(sink,
                                ELAPI_SINK_PROVIDER,
                                handle->ini_config,
                                &provider_cfg_item);
        if (error) {
            TRACE_ERROR_NUMBER("Attempt to read provider attribute returned error", error);
            return error;
        }

        /* Do we have provider? */
        if (provider_cfg_item == NULL) {
            /* There is no provider - return error */
            TRACE_ERROR_STRING("Required key is missing in the configuration.", "Fatal Error!");
            return ENOKEY;
        }


        /* FIXME: PLACEHOLDER
            * This is the area where the actual sink is loaded.
            * CODE WILL BE ADDED HERE...
            */
        sink_context.async_mode = 0;
        sink_context.in_queue = NULL;
        sink_context.pending = NULL;

        /* We got a valid sink so add it to the collection */
        error = col_add_binary_property_with_ref(handle->sink_list,
                                                 NULL,
                                                 sink,
                                                 (void *)(&sink_context),
                                                 sizeof(struct elapi_sink_context),
                                                 sink_ref);
        if (error != 0) {
            TRACE_ERROR_NUMBER("Failed to add sink data as property", error);
            return error;
        }
    }

    TRACE_FLOW_NUMBER("elapi_internal_add_sink returning", error);
    return error;
}

/* Destroy target object */
void elapi_internal_destroy_target(struct elapi_target_context *context)
{
    TRACE_FLOW_STRING("elapi_internal_destroy_target", "Entry.");

    TRACE_INFO_NUMBER("Target address in cleanup:", context);

    if (context) {
        TRACE_INFO_STRING("Deleting the list of references to sinks", "");
        col_destroy_collection(context->sink_ref_list);
        /* FIXME - add other cleanup for other things that will be a part
         * of the target context.
         */
        free(context);
    }

    TRACE_FLOW_STRING("elapi_internal_destroy_target", "Exit.");

}

/* Allocate target context and load sinks to it */
int elapi_internal_create_target(struct elapi_target_context **context,
                                 char *target,
                                 struct elapi_dispatcher *handle)
{
    int error = EOK;
    struct collection_item *sink_cfg_item = NULL;
    struct collection_item *value_cfg_item = NULL;
    struct elapi_target_context *target_context;
    char **sinks;
    char **current_sink;
    struct collection_item *sink_ref;

    TRACE_FLOW_STRING("elapi_internal_create_target", "Entry.");

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
        return ENOKEY;
    }

    /* Allocate context */
    target_context = (struct elapi_target_context *)malloc(sizeof(struct elapi_target_context));
    if (target_context == NULL) {
        TRACE_ERROR_NUMBER("Memory allocation failed. Error", target_context);
        return ENOMEM;
    }

    /* Initialize the allocatable items so that we can call destroy function
     * in case of error.
     * FIXME - add initialization here for other elements as they are added.
     */

    target_context->sink_ref_list = NULL;

    /* Assign target's value */
    error = get_config_item(target,
                            ELAPI_TARGET_VALUE,
                            handle->ini_config,
                            &value_cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read configuration returned error", error);
        elapi_internal_destroy_target(target_context);
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
            elapi_internal_destroy_target(target_context);
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
        elapi_internal_destroy_target(target_context);
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
        error = elapi_internal_add_sink(&sink_ref,
                                        *current_sink,
                                        handle);
        if (error) {
            /* NOTE - we might decide to lax some of the checks
             * like this later and be satisfied with at least one
             * sink in the list. Subject for discussion...
             */
            TRACE_ERROR_NUMBER("Failed to add sink", error);
            elapi_internal_destroy_target(target_context);
            free_string_config_array(sinks);
            return error;
        }

        /* Add reference to it into the target object */
        error = col_add_binary_property(target_context->sink_ref_list, NULL,
                                        *current_sink, (void *)(&sink_ref),
                                        sizeof(struct collection_item *));
        if (error != 0) {
            TRACE_ERROR_NUMBER("Failed to add sink reference", error);
            elapi_internal_destroy_target(target_context);
            free_string_config_array(sinks);
            return error;
        }

        current_sink++;
    }

    free_string_config_array(sinks);

    *context = target_context;

    TRACE_FLOW_STRING("elapi_internal_create_target", "Exit.");
    return EOK;
}


/* Function to create a list of targets */
int elapi_internal_construct_target_list(struct elapi_dispatcher *handle)
{
    int error = EOK;
    char **current_target;
    struct elapi_target_context *context;


    TRACE_FLOW_STRING("elapi_internal_construct_target_list", "Entry");

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
        error = elapi_internal_create_target(&context,
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
                                        sizeof(struct elapi_target_context *));
        if (error != 0) {
            TRACE_ERROR_NUMBER("Failed to add sink data as property", error);
            /* Need to clean allocated context here if we failed to add it */
            elapi_internal_destroy_target(context);
            return error;
        }

        handle->target_counter++;
        current_target++;
    }

    /* Check if we have any targets available */
    if (handle->target_counter == 0) {
        TRACE_ERROR_STRING("No targets", "");
        return ENOKEY;
    }

    TRACE_FLOW_STRING("elapi_internal_construct_target_list", "Returning success");
    return EOK;
}



/* If we failed to read configuration record this in the local file */
void elapi_internal_dump_errors_to_file(struct collection_item *error_list)
{
    FILE *efile;
    char timestr[MAX_TIMESTR];
    time_t time_in_sec;
    struct tm *time_as_struct;
    struct tm time_data;

    TRACE_FLOW_STRING("elapi_internal_dump_errors_to_file", "Entry point");

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
    TRACE_FLOW_STRING("elapi_internal_dump_errors_to_file", "Exit");
}


/* Handler for printing target internals */
static int elapi_internal_sink_ref_debug_handler(const char *sink,
                                                 int sink_len,
                                                 int type,
                                                 void *data,
                                                 int length,
                                                 void *passed_data,
                                                 int *stop)
{
    struct collection_item *sink_item;
    struct elapi_sink_context *sink_context;

    /* Skip header */
    if (type == COL_TYPE_COLLECTION) {
        return EOK;
    }

    sink_item = *((struct collection_item **)(data));

    printf("\nReferenced sink name is: %s\n", col_get_item_property(sink_item, NULL));

    sink_context = (struct elapi_sink_context *)(col_get_item_data(sink_item));

    printf("Mode: %s\n", sink_context->async_mode ? "true" : "false");
    if (sink_context->in_queue) col_print_collection(sink_context->in_queue);
    else printf("Queue is not initialized.\n");

    if (sink_context->pending) col_print_collection(sink_context->pending);
    else printf("Pending list is not initialized.\n");

    return EOK;
}



/* Handler for printing target internals */
static int elapi_internal_target_debug_handler(const char *target,
                                               int target_len,
                                               int type,
                                               void *data,
                                               int length,
                                               void *passed_data,
                                               int *stop)
{
    struct elapi_target_context *context;

    /* Skip header */
    if (type == COL_TYPE_COLLECTION) {
        return EOK;
    }

    context = *((struct elapi_target_context **)(data));

    printf("\nTarget value for target \"%s\" is %d\n", target, context->target_value);
    printf("\nReferenced sinks:\n\n");

    (void)col_traverse_collection(context->sink_ref_list,
                                  COL_TRAVERSE_ONELEVEL,
                                  elapi_internal_sink_ref_debug_handler,
                                  NULL);

    return EOK;
}


/* Internal function to print dispatcher internals - useful for testing */
void elapi_internal_print_dispatcher(struct elapi_dispatcher *handle)
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
                                      elapi_internal_target_debug_handler,
                                      NULL);
    }
    /* FIXME: Async data... */

    printf("DISPATCHER END\n\n");
}
