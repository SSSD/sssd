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

/* Handler for logging through the sinks */
int elapi_internal_sink_handler(const char *sink,
                                int sink_len,
                                int type,
                                void *data,
                                int length,
                                void *passed_data,
                                int *stop)
{
    struct elapi_sink_context *sink_env;
    TRACE_FLOW_STRING("elapi_internal_sink_handler", "Entry.");

    /* FIXME THIS IS A PLACEHOLDER FUNCTION FOR NOW */

    sink_env = (struct elapi_sink_context *)(passed_data);

    if (type == COL_TYPE_COLLECTION) {
        printf("\n\n\nPROCESSING EVENT:\n");
        col_debug_collection(sink_env->event, COL_TRAVERSE_DEFAULT);
    }
    else printf("Sink: %s\n", sink);

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

    if (type != COL_TYPE_COLLECTION) printf("Cleaning Sink: %s\n", sink);

    TRACE_FLOW_STRING("elapi_internal_sink_cleanup_handler", "Exit.");
    return EOK;
}

/* Function to add a sink to the collection */
int elapi_internal_add_sink_to_collection(struct collection_item *sink_list,
                                          char *sink,
                                          char *appname)
{
    int error = EOK;
    int found = 0;
    struct sink_descriptor sink_data;

    TRACE_FLOW_STRING("elapi_internal_add_sink_to_collection", "Entry");
    error = col_is_item_in_collection(sink_list,
                                      sink,
                                      COL_TYPE_ANY,
                                      COL_TRAVERSE_DEFAULT,
                                      &found);
    if (error) {
        TRACE_ERROR_NUMBER("Search returned error", error);
        return error;
    }

    /* Check if it was found */
    if (found) {
        TRACE_ERROR_NUMBER("Attempt to add an exiting sink.", "");
        return EINVAL;
    }

    /* Save the pointer to application name into the sink's data block */
    sink_data.dblock.appname = appname;
    TRACE_INFO_STRING("add_sink_to_list - saving appname:", sink_data.dblock.appname);

    /* Try to load the sink library */

    /* FIXME - we need to have at least one sink implemented to enable this code.
     * It is a placeholder for now.
    error = load_sink(&sink_data, sink);
    if (error != 0) {
        DEBUG_NUMBER("Failed to load sink", error);
        return error;
    }
    */


    /* We got a valid sink so add it to the collection */
    error = col_add_binary_property(sink_list, NULL,
                                    sink, (void *)(&sink_data),
                                    sizeof(struct sink_descriptor));
    if (error != 0) {
        TRACE_ERROR_NUMBER("Failed to add sink data as property", error);
        return error;
    }

    TRACE_FLOW_NUMBER("elapi_internal_add_sink_to_collection returning", error);
    return error;
}

/* Function to create a list of sinks */
int elapi_internal_construct_sink_list(struct elapi_dispatcher *handle)
{
    int error = EOK;
    char **current_sink;

    TRACE_FLOW_STRING("elapi_internal_construct_sink_list", "Entry");

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

    current_sink = handle->sinks;
    handle->sink_counter = 0;

    /* Add sinks as properties to the sink collection */
    while (*current_sink != NULL) {

        TRACE_INFO_STRING("Current sink", *current_sink);
        TRACE_INFO_STRING("Will use appname:", handle->appname);

        /* Load sink */
        error = elapi_internal_add_sink_to_collection(handle->sink_list,
                                                      *current_sink,
                                                      handle->appname);
        if ((error != 0) && (error != ELIBACC)) {
            TRACE_ERROR_NUMBER("Failed to add sink", error);
            /* No cleanup here. */
            return error;
        }

        handle->sink_counter++;
        current_sink++;
    }

    /* Check if we have any sinks available */
    if (handle->sink_counter == 0) {
        TRACE_ERROR_NUMBER("No sinks", ELIBACC);
        /* No cleanup here. */
        /* Return "Cannot access a needed shared library" */
        return ELIBACC;
    }

    TRACE_FLOW_STRING("elapi_internal_construct_sink_list", "Returning success");
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
