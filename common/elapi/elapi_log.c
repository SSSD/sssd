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
#include <sys/types.h>  /* for stat() */
#include <sys/stat.h>   /* for stat() */
#include <unistd.h>     /* for stat() */
#include <errno.h>      /* for errors */
#include <string.h>     /* for memset() and other */
#include <stdarg.h>     /* for va_arg() */
#include <stdlib.h>     /* for free() */


#include "elapi_priv.h"
#include "elapi_event.h"
#include "elapi_log.h"
#include "ini_config.h"
#include "trace.h"
#include "config.h"


/* Pointer to default global dispatcher */
struct elapi_dispatcher *global_dispatcher = NULL;

/* Deafult sink names */
char remote_sink[]      = "remote";
char altremote_sink[]   = "altremote";
char syslog_sink[]      = "syslog";
char db_sink[]          = "db";
char file_sink[]        = "file";
char failover_sink[]    = "failover";
char stderr_sink[]      = "stderr";

/* Deafult sink list */
char *default_sinks[] = { remote_sink,
                          altremote_sink,
                          syslog_sink,
                          db_sink,
                          file_sink,
                          failover_sink,
                          stderr_sink,
                          NULL };

/* Per review I was told to hard cord this name. So be it... */
#define ELAPI_CONFIG_FILE_NAME  "elapi.conf"

/* Default config file */
static char default_config_file[] = ELAPI_DEFAULT_CONFIG_DIR "/" ELAPI_CONFIG_FILE_NAME;
/* Default config dir */
static char default_config_dir[] = ELAPI_DEFAULT_CONFIG_APP_DIR;


/* Was a cleanup callback registered ? */
static int elapi_close_registered = 0;


/* Internal function to log message using args */
static int elapi_dsp_msg_with_vargs(uint32_t target,
                                    struct elapi_dispatcher *dispatcher,
                                    struct collection_item *template,
                                    va_list args)
{
	int error = EOK;
    struct collection_item *event;

    TRACE_FLOW_STRING("elapi_dsp_msg_with_vargs", "Entry");

    if (!dispatcher) {
        TRACE_ERROR_NUMBER("Invalid argument", EINVAL);
        return EINVAL;
    }

    /* Create event */
    error = elapi_create_event_with_vargs(&event,
                                          template,
                                          NULL,
                                          0,
                                          args);

    if (error) {
        TRACE_ERROR_NUMBER("Failed to create event", error);
        return error;
    }

    /* Now log event */
    error = elapi_dsp_log(target, dispatcher, event);

    /* Destroy event */
    elapi_destroy_event(event);

    if (error) {
        TRACE_ERROR_NUMBER("Failed to log event", error);
        return error;
    }

    TRACE_FLOW_STRING("elapi_dsp_msg_with_vargs", "Exit");
    return error;
}


/********** Main functions of the interface **********/

/* Function to create a dispatcher */
int elapi_create_dispatcher_adv(struct elapi_dispatcher **dispatcher,
                                const char *appname,
                                const char *config_path,
                                elapi_add_fd add_fd_add_fn,
                                elapi_rem_fd add_fd_rem_fn,
                                elapi_add_timer add_timer_fn,
                                void *callers_data)
{
    struct elapi_dispatcher *handle = NULL;
    struct collection_item *error_set = NULL;
    int error = EOK;
	struct collection_item *item = NULL;
    const char *config_file = NULL;
    const char *config_dir = NULL;
    struct stat stat_data;
    int prm_cnt = 0;

    TRACE_FLOW_STRING("elapi_create_dispatcher_adv", "Entry point");

    /* Make sure the memory for handle is passed in */
    if (dispatcher == NULL) {
        TRACE_ERROR_STRING("elapi_create_dispatcher_adv", "Invalid parameter.");
        return EINVAL;
    }

    /* Make sure we got the right constant */
    TRACE_INFO_NUMBER("ELAPI_DEFAULT_APP_NAME_SIZE = ", ELAPI_DEFAULT_APP_NAME_SIZE);

    if ((appname != NULL) && (strlen(appname) > ELAPI_DEFAULT_APP_NAME_SIZE)) {
        TRACE_ERROR_STRING("elapi_create_dispatcher", "Application name is too long.");
        return EINVAL;
    }

    /* Check that all the async data is present */
    if (add_fd_add_fn) prm_cnt++;
    if (add_fd_rem_fn) prm_cnt++;
    if (add_timer_fn) prm_cnt++;
    if (callers_data) prm_cnt++;

    if ((prm_cnt > 0) && (prm_cnt < 4)) {
        /* We got a mixture of NULLs and not NULLs.
         * This is bad since all should be either provided
         * or all should be NULL.
         */
        TRACE_ERROR_STRING("Invalid sync parameters.", "At least one is NULL while others are not.");
        return EINVAL;
    }

    /* Check what is passed in the config_path */
    if (config_path) {
        /* What is it ? */
        if(stat(config_path, &stat_data)) {
            error = errno;
            TRACE_ERROR_NUMBER("Invalid path assume defaults. Error", error);
            config_file = default_config_file;
            config_dir = default_config_dir;
        }
        else {
            if (S_ISREG(stat_data.st_mode)) {
                config_file = config_path;
                config_dir = NULL;
                TRACE_INFO_STRING("Will use config file", config_file);
            }
            else if (S_ISDIR(stat_data.st_mode)) {
                config_file = NULL;
                config_dir = config_path;
                TRACE_INFO_STRING("Will use directory", config_dir);
            }
            else {
                config_file = default_config_file;
                config_dir = default_config_dir;
            }
        }
    }
    else {
        config_file = default_config_file;
        config_dir = default_config_dir;
    }

    TRACE_INFO_STRING("FILE:", config_file);
    TRACE_INFO_STRING("DIR:", config_dir);

    /* Allocate memory */
    handle = (struct elapi_dispatcher *) malloc(sizeof(struct elapi_dispatcher));
    if (handle == NULL) {
        TRACE_ERROR_NUMBER("Memory allocation failed. Error", ENOMEM);
        return ENOMEM;
    }

    /* Clean memory - we need it to be able to destroy the dispatcher at any moment */
    /* FIXME - eventually remove the memset from here when the structure finalizes */
    /* Valgrind requires explicit initialization of the structure member, otherwise
     * it complains about jump or move based on the uninitialized variable.
     */
    memset(handle, 0, sizeof(struct elapi_dispatcher *));
    handle->ini_config = NULL;
    handle->target_list = NULL;
    handle->sink_list = NULL;
    handle->targets = NULL;
    handle->default_template = NULL;

    /* Save application name in the handle */
    if (appname != NULL) handle->appname = strdup(appname);
    else handle->appname = strdup(ELAPI_DEFAULT_APP_NAME);

    TRACE_FLOW_STRING("Application name:", handle->appname);

    /* Check error */
    if (handle->appname == NULL) {
        TRACE_ERROR_NUMBER("Memory allocation failed. Error", ENOMEM);
        elapi_destroy_dispatcher(handle);
        return ENOMEM;
    }

    /* Read the ELAPI configuration and store it in the dispatcher handle */
    error = config_for_app(handle->appname,
                           config_file,
                           config_dir,
                           &(handle->ini_config),
                           INI_STOP_ON_ANY,
                           &error_set);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read configuration returned error", error);
        elapi_destroy_dispatcher(handle);
        if (error_set) {
            elapi_internal_dump_errors_to_file(error_set);
            free_ini_config_errors(error_set);
        }
        return error;
    }

    /* Have to clean error set anyways */
    free_ini_config_errors(error_set);

    /* Get target list from configuration */
    error = get_config_item(ELAPI_DISPATCHER,
                            ELAPI_TARGETS,
                            handle->ini_config,
                            &item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read configuration returned error", error);
        elapi_destroy_dispatcher(handle);
        return error;
    }

    /* Do we have targets? */
    if (item == NULL) {
        /* There is no list of targets this is bad configuration - return error */
        TRACE_ERROR_STRING("No targets in the config file.", "Fatal error!");
        elapi_destroy_dispatcher(handle);
        return ENOENT;
    }

    /* Get one from config but make sure we free it later */
    handle->targets = get_string_config_array(item, NULL, NULL, NULL);

    /* Create the list of targets */
    error = elapi_internal_construct_target_list(handle);
    if (error != EOK) {
        TRACE_ERROR_NUMBER("Failed to create target list. Error", error);
        elapi_destroy_dispatcher(handle);
        return error;
    }

    /* Populate async processing data if any */
    if (prm_cnt) {
        TRACE_INFO_STRING("Async data is present", "");
        handle->add_fd_add_fn = add_fd_add_fn;
        handle->add_fd_rem_fn = add_fd_rem_fn;
        handle->add_timer_fn = add_timer_fn;
        handle->callers_data = callers_data;
        handle->async_mode = 1;
    }

    *dispatcher = handle;

    TRACE_FLOW_STRING("elapi_create_dispatcher_adv", "Returning Success.");
    return EOK;

}

/* Simple dispatcher */
int elapi_create_dispatcher(struct elapi_dispatcher **dispatcher,
                            const char *appname,
                            const char *config_path)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_create_dispatcher", "Entry.");

    /* Will have more parmeters in future */
    error = elapi_create_dispatcher_adv(dispatcher,
                                        appname,
                                        config_path,
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL);

    TRACE_FLOW_STRING("elapi_create_dispatcher", "Exit.");
    return error;

}

/* Function to clean memory associated with the dispatcher */
void elapi_destroy_dispatcher(struct elapi_dispatcher *dispatcher)
{
    TRACE_FLOW_STRING("elapi_destroy_dispatcher", "Entry.");

    if (dispatcher) {
        TRACE_INFO_STRING("Deleting template if any...", "");
        col_destroy_collection(dispatcher->default_template);

        if (dispatcher->target_list) {
            TRACE_INFO_STRING("Closing target list.", "");
            (void)col_traverse_collection(dispatcher->target_list,
                                          COL_TRAVERSE_ONELEVEL,
                                          elapi_internal_target_cleanup_handler,
                                          NULL);

            TRACE_INFO_STRING("Deleting target list.", "");
            col_destroy_collection(dispatcher->target_list);
        }

        if (dispatcher->sink_list) {
            TRACE_INFO_STRING("Closing sink list.", "");
            (void)col_traverse_collection(dispatcher->sink_list,
                                          COL_TRAVERSE_ONELEVEL,
                                          elapi_internal_sink_cleanup_handler,
                                          NULL);
            TRACE_INFO_STRING("Deleting target list.", "");
            col_destroy_collection(dispatcher->sink_list);
        }

		TRACE_INFO_STRING("Freeing application name.", "");
        free(dispatcher->appname);
        TRACE_INFO_STRING("Freeing config.", "");
        free_ini_config(dispatcher->ini_config);
        TRACE_INFO_STRING("Deleting targets name array.", "");
        free_string_config_array(dispatcher->targets);
		TRACE_INFO_STRING("Freeing dispatcher.", "");
        free(dispatcher);
    }

    TRACE_FLOW_STRING("elapi_destroy_dispatcher", "Exit.");
}

/* Function to log an event */
int elapi_dsp_log(uint32_t target,
                  struct elapi_dispatcher *dispatcher,
                  struct collection_item *event)
{
    int error = EOK;
    struct elapi_target_pass_in_data target_data;

    TRACE_FLOW_STRING("elapi_dsp_log", "Entry");

    if ((dispatcher == NULL) ||
       (event == NULL)) {
        TRACE_ERROR_STRING("elapi_dsp_log", "ERROR Invalid argument");
        return EINVAL;
    }

    /* Wrap parameters into one argument and pass on */
    target_data.handle = dispatcher;
    target_data.event = event;
    target_data.target_mask = target;

    TRACE_INFO_NUMBER("Target mask is:", target_data.target_mask);

    /* Logging an event is just iterating through the targets and calling the sink_handler */
    error = col_traverse_collection(dispatcher->target_list,
                                    COL_TRAVERSE_ONELEVEL,
                                    elapi_internal_target_handler,
                                    (void *)(&target_data));

    TRACE_FLOW_NUMBER("elapi_dsp_log Exit. Returning", error);
    return error;
}

/* Initializes default internal template */
int elapi_set_default_template(unsigned base, ...)
{
    int error = EOK;
    struct collection_item *tpl = NULL;
    va_list args;

    TRACE_FLOW_STRING("elapi_set_default_template", "Entry");

    if (global_dispatcher == NULL) {
        error = elapi_init(NULL, NULL);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to init ELAPI", error);
            return error;
        }
    }

    /* Clean previous instance of the default template */
    elapi_destroy_event_template(global_dispatcher->default_template);
    global_dispatcher->default_template = NULL;

    /* Process varible arguments */
    va_start(args, base);

    /* Create template out of base and args */
    error = elapi_create_event_template_with_vargs(&tpl,
                                                   base,
                                                   args);
    va_end(args);

    if (error) {
        TRACE_ERROR_NUMBER("Failed to create template. Error", error);
        return error;
    }

    global_dispatcher->default_template = tpl;

    TRACE_FLOW_STRING("elapi_set_default_template", "Exit");
    return error;
}

/* There is one default template associated with the dispatcher */
int elapi_get_default_template(struct collection_item **template)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_get_default_template", "Entry");

    if ((global_dispatcher == NULL) ||
        (global_dispatcher->default_template == NULL)) {
        TRACE_INFO_STRING("Default template does not exit", "");

        error = elapi_set_default_template(E_BASE_DEFV1);
        if (error) {
            TRACE_ERROR_NUMBER("Set default template returned error", error);
            return error;
        }
    }

    *template = global_dispatcher->default_template;
    TRACE_FLOW_NUMBER("elapi_get_default_template. Exit returning", error);
    return error;
}



/* Function to log raw key value pairs without creating an event */
int elapi_dsp_msg(uint32_t target,
                  struct elapi_dispatcher *dispatcher,
                  struct collection_item *template,
                  ...)
{
    int error = EOK;
    va_list args;

    TRACE_FLOW_STRING("elapi_dsp_msg", "Entry");

    va_start(args, template);

    error = elapi_dsp_msg_with_vargs(target, dispatcher, template, args);

    va_end(args);

    TRACE_FLOW_STRING("elapi_dsp_msg.", "Exit");
    return error;
}

/********** Advanced dispatcher managment functions **********/

/* Managing the sink collection */
int elapi_alter_dispatcher(struct elapi_dispatcher *dispatcher,
                           const char *target,
                           const char *sink,
                           int action)
{

    /* FIXME: FUNCTION IS NOT IMPLEMENTED YET */
    return EOK;
}

/* Get sink list */
char **elapi_get_sink_list(struct elapi_dispatcher *dispatcher, char *target)
{

    /* FIXME: FUNCTION IS NOT IMPLEMENTED YET */
    return NULL;
}

/* Free sink list */
void elapi_free_sink_list(char **sink_list)
{

    /* FIXME: FUNCTION IS NOT IMPLEMENTED YET */

}

/* Get target list */
char **elapi_get_target_list(struct elapi_dispatcher *dispatcher)
{

    /* FIXME: FUNCTION IS NOT IMPLEMENTED YET */
    return NULL;
}

/* Free target list */
void elapi_free_target_list(char **target_list)
{

    /* FIXME: FUNCTION IS NOT IMPLEMENTED YET */

}


/******************** High level interface ************************************/
/* This interface is not thread safe but hides the dispatcher. */

/* This function will use internal default template */
int elapi_create_simple_event(struct collection_item **event, ...)
{
    int error = EOK;
    struct collection_item *evt = NULL;
    va_list args;
    struct collection_item *template = NULL;

    TRACE_FLOW_STRING("elapi_create_simple_event", "Entry");

    /* Check storage */
    if (event == NULL ) {
        TRACE_ERROR_STRING("Event storage must be provided", "");
        return EINVAL;
    }

    *event = NULL;

    /* Get default template */
    error = elapi_get_default_template(&template);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to get default template. Error", error);
        return error;
    }

    va_start(args, event);

    /* Create event */
    error = elapi_create_event_with_vargs(&evt,
                                          template,
                                          NULL,
                                          0,
                                          args);

    va_end(args);

    if (error) {
        TRACE_ERROR_NUMBER("Failed to create event using arg list. Error", error);
        col_destroy_collection(evt);
        return error;
    }

    *event = evt;

    TRACE_FLOW_STRING("elapi_create_simple_event", "Exit");
    return error;
}

/* Log key value pairs  */
int elapi_msg(uint32_t target, struct collection_item *template, ...)
{
    int error = EOK;
    va_list args;
    struct collection_item *use_template;

    TRACE_FLOW_STRING("elapi_msg", "Entry");

    if (!template) {
        /* Get default template */
        error = elapi_get_default_template(&use_template);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to get default template. Error", error);
            return error;
        }
    }
    else use_template = template;

    va_start(args, template);

    error = elapi_dsp_msg_with_vargs(target,
                                     global_dispatcher,
                                     use_template,
                                     args);

    va_end(args);

    TRACE_FLOW_NUMBER("elapi_msg Exit:", error);
    return error;
}

/* Log event  */
int elapi_log(uint32_t target, struct collection_item *event)
{
    int error;

    TRACE_FLOW_STRING("elapi_log", "Entry");

    /* If dispatcher was not initialized do it automatically */
    if (global_dispatcher == NULL) {
        error = elapi_init(NULL, NULL);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to init ELAPI", error);
            return error;
        }
    }
    error = elapi_dsp_log(target, global_dispatcher, event);

    TRACE_FLOW_NUMBER("elapi_log Exit:", error);
    return error;
}

/* Get dispatcher if you want to add sink to a default dispatcher or do some advanced operations */
struct elapi_dispatcher *elapi_get_dispatcher(void)
{
    TRACE_FLOW_STRING("elapi_get_dispatcher was called.", "Returning default dispatcher.");
    return global_dispatcher;

}

/* Close ELAPI */
void elapi_close(void)
{
    TRACE_FLOW_STRING("elapi_close","Entry");

    /* Destroy global dispatcher */
    elapi_destroy_dispatcher(global_dispatcher);
    global_dispatcher = NULL;

    TRACE_FLOW_STRING("elapi_close","Exit");
}

/* Function to initialize ELAPI library in the single threaded applications */
int elapi_init(const char *appname, const char *config_path)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_init","Entry");

    /* Clean the dispatcher if needed */
    elapi_close();

    /* Create global dispatcher */
    error = elapi_create_dispatcher(&global_dispatcher, appname, config_path);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to create default dispatcher. Error", error);
        return error;
    }

    /* Install a cleanup callback */
    if (!elapi_close_registered) {
        if (atexit(elapi_close)) {
            TRACE_ERROR_NUMBER("Failed to install cleanup callback. Error", ENOSYS);
            /* NOTE: Could not find a better error for this case */
            return ENOSYS;
        }
        elapi_close_registered = 1;
    }

    TRACE_FLOW_NUMBER("elapi_init Exit:",error);
    return error;
}
