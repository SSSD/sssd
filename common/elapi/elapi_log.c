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
                                    struct collection_item *tpl,
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
                                          tpl,
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
/* Function to free the async context */
void elapi_destroy_asctx(struct elapi_async_ctx *ctx)
{
    TRACE_FLOW_STRING("elapi_destroy_asctx", "Entry");

    free(ctx);

    TRACE_FLOW_STRING("elapi_destroy_asctx", "Exit");
}

/* Function to validate the consistency of the
 * async context */
static int elapi_check_asctx(struct elapi_async_ctx *ctx)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_check_asctx", "Entry");

    /* Check callbacks */
    if ((ctx->add_fd_cb == NULL) ||
        (ctx->rem_fd_cb == NULL) ||
        (ctx->set_fd_cb == NULL) ||
        (ctx->add_tm_cb == NULL) ||
        (ctx->rem_tm_cb == NULL)) {
        TRACE_ERROR_NUMBER("One of the callbacks is missing. Error", EINVAL);
        return EINVAL;
    }

    /* We do not check the data pointers.
     * Why? Becuase thought it is a bad approach
     * the data the callbacks will use
     * can be a global (bad but can be!).
     * So forcing caller to provide non-NULL
     * data pointers is a bit too much.
     */

    TRACE_FLOW_STRING("elapi_check_asctx", "Exit");
    return error;
}

/* Interface to create the async context */
int elapi_create_asctx(struct elapi_async_ctx **ctx,
                       elapi_add_fd add_fd_cb,
                       elapi_rem_fd rem_fd_cb,
                       elapi_set_fd set_fd_cb,
                       void *ext_fd_data,
                       elapi_add_tm add_tm_cb,
                       elapi_rem_tm rem_tm_cb,
                       void *ext_tm_data)
{
    int error = EOK;
    struct elapi_async_ctx *ctx_new;

    TRACE_FLOW_STRING("elapi_create_asctx", "Entry");

    /* Allocate data, copy it and then check.
     * Why this order? Why not check first
     * without allocating memory and wasting
     * cycles for it?
     * Becuase the check function can be used
     * in other place to validate that the context
     * is correct. Allocating and freeing
     * data is not an overhead since
     * it is going to catch development
     * error that would not exist in the final
     * product. Otherwise the progam just
     * would not run.
     */

    ctx_new = (struct elapi_async_ctx *)malloc(sizeof(struct elapi_async_ctx));
    if (ctx_new == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate memory for the context", ENOMEM);
        return ENOMEM;
    }

    ctx_new->add_fd_cb = add_fd_cb;
    ctx_new->rem_fd_cb = rem_fd_cb;
    ctx_new->set_fd_cb = set_fd_cb;
    ctx_new->add_tm_cb = add_tm_cb;
    ctx_new->rem_tm_cb = rem_tm_cb;
    ctx_new->ext_fd_data = ext_fd_data;
    ctx_new->ext_tm_data = ext_tm_data;

    error = elapi_check_asctx(ctx_new);
    if (error) {
        TRACE_ERROR_NUMBER("Check context failed", error);
        elapi_destroy_asctx(ctx_new);
        return error;
    }

    *ctx = ctx_new;

    TRACE_FLOW_STRING("elapi_create_asctx", "Exit");
    return error;
}

/* Function to create a dispatcher */
int elapi_create_dispatcher_adv(struct elapi_dispatcher **dispatcher,
                                const char *appname,
                                const char *config_path,
                                struct elapi_async_ctx *async_ctx)
{
    struct elapi_dispatcher *handle = NULL;
    struct collection_item *error_set = NULL;
    int error = EOK;
	struct collection_item *item = NULL;
    const char *config_file = NULL;
    const char *config_dir = NULL;
    struct stat stat_data;

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

    /* Check if context is valid */
    if (async_ctx) {
        error = elapi_check_asctx(async_ctx);
        if (error) {
            TRACE_ERROR_NUMBER("Check context failed", error);
            return error;
        }
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
    handle = (struct elapi_dispatcher *) calloc(1, sizeof(struct elapi_dispatcher));
    if (handle == NULL) {
        TRACE_ERROR_NUMBER("Memory allocation failed. Error", ENOMEM);
        return ENOMEM;
    }

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
            elapi_dump_ini_err(error_set);
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
    error = elapi_tgt_mklist(handle);
    if (error != EOK) {
        TRACE_ERROR_NUMBER("Failed to create target list. Error", error);
        elapi_destroy_dispatcher(handle);
        return error;
    }

    /* Populate async processing data if any */
    if (async_ctx) {
        TRACE_INFO_STRING("Async data is present", "");
        handle->async_ctx = malloc(sizeof(struct elapi_async_ctx));
        if (handle->async_ctx != NULL) {
            TRACE_ERROR_NUMBER("Failed to allocate async context", ENOMEM);
            elapi_destroy_dispatcher(handle);
            return ENOMEM;
        }
        /* Copy async data */
        memcpy(handle->async_ctx, async_ctx, sizeof(struct elapi_async_ctx));
    }
    else {
        TRACE_INFO_STRING("No async data present", "");
        handle->async_ctx = NULL;
    }

    /* Build the list of the items we know how to resolve */
    error = elapi_init_resolve_list(&(handle->resolve_list));
    if (error != EOK) {
        TRACE_ERROR_NUMBER("Failed to create list of resolvers. Error", error);
        elapi_destroy_dispatcher(handle);
        return error;
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
        col_destroy_collection(dispatcher->default_tpl);

        if (dispatcher->target_list) {
            TRACE_INFO_STRING("Closing target list.", "");
            (void)col_traverse_collection(dispatcher->target_list,
                                          COL_TRAVERSE_ONELEVEL,
                                          elapi_tgt_free_cb,
                                          NULL);

            TRACE_INFO_STRING("Deleting target list.", "");
            col_destroy_collection(dispatcher->target_list);
        }

        if (dispatcher->sink_list) {
            TRACE_INFO_STRING("Closing sink list.", "");
            (void)col_traverse_collection(dispatcher->sink_list,
                                          COL_TRAVERSE_ONELEVEL,
                                          elapi_sink_free_cb,
                                          NULL);
            TRACE_INFO_STRING("Deleting target list.", "");
            col_destroy_collection(dispatcher->sink_list);
        }

		TRACE_INFO_STRING("Freeing application name.", "");
        free(dispatcher->appname);
		TRACE_INFO_STRING("Freeing async context.", "");
        free(dispatcher->async_ctx);
        TRACE_INFO_STRING("Freeing config.", "");
        free_ini_config(dispatcher->ini_config);
        TRACE_INFO_STRING("Deleting targets name array.", "");
        free_string_config_array(dispatcher->targets);
        TRACE_INFO_STRING("Unbind resolver iterator.", "");
        col_unbind_iterator(dispatcher->resolve_list);
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
    struct elapi_tgt_data target_data;
    struct collection_item *resolved_event;

    TRACE_FLOW_STRING("elapi_dsp_log", "Entry");

    if ((dispatcher == NULL) ||
       (event == NULL)) {
        TRACE_ERROR_STRING("elapi_dsp_log", "ERROR Invalid argument");
        return EINVAL;
    }

    /* Create a resolved event */
    error = elapi_resolve_event(&resolved_event, event, dispatcher);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to create event context. Error", error);
        return error;
    }

    /* Wrap parameters into one argument and pass on */
    target_data.handle = dispatcher;
    target_data.event = resolved_event;
    target_data.target_mask = target;

    TRACE_INFO_NUMBER("Target mask is:", target_data.target_mask);

    /* Logging an event is just iterating through the targets and calling a callback */
    error = col_traverse_collection(dispatcher->target_list,
                                    COL_TRAVERSE_ONELEVEL,
                                    elapi_tgt_cb,
                                    (void *)(&target_data));

    elapi_destroy_event(resolved_event);

    TRACE_FLOW_NUMBER("elapi_dsp_log Exit. Returning", error);
    return error;
}

/* Initializes default internal template */
int elapi_set_default_tplt(unsigned base, ...)
{
    int error = EOK;
    struct collection_item *tpl = NULL;
    va_list args;

    TRACE_FLOW_STRING("elapi_set_default_tplt", "Entry");

    if (global_dispatcher == NULL) {
        error = elapi_init(NULL, NULL);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to init ELAPI", error);
            return error;
        }
    }

    /* Clean previous instance of the default template */
    elapi_destroy_event_tplt(global_dispatcher->default_tpl);
    global_dispatcher->default_tpl = NULL;

    /* Process varible arguments */
    va_start(args, base);

    /* Create template out of base and args */
    error = elapi_create_event_tplt_with_vargs(&tpl,
                                               base,
                                               args);
    va_end(args);

    if (error) {
        TRACE_ERROR_NUMBER("Failed to create template. Error", error);
        return error;
    }

    global_dispatcher->default_tpl = tpl;

    TRACE_FLOW_STRING("elapi_set_default_tplt", "Exit");
    return error;
}

/* There is one default template associated with the dispatcher */
int elapi_get_default_tplt(struct collection_item **tpl)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_get_default_tplt", "Entry");

    if ((global_dispatcher == NULL) ||
        (global_dispatcher->default_tpl == NULL)) {
        TRACE_INFO_STRING("Default template does not exit", "");

        error = elapi_set_default_tplt(E_BASE_DEFV1, E_EOARG);
        if (error) {
            TRACE_ERROR_NUMBER("Set default template returned error", error);
            return error;
        }
    }

    *tpl = global_dispatcher->default_tpl;
    TRACE_FLOW_NUMBER("elapi_get_default_tplt. Exit returning", error);
    return error;
}



/* Function to log raw key value pairs without creating an event */
int elapi_dsp_msg(uint32_t target,
                  struct elapi_dispatcher *dispatcher,
                  struct collection_item *tpl,
                  ...)
{
    int error = EOK;
    va_list args;

    TRACE_FLOW_STRING("elapi_dsp_msg", "Entry");

    va_start(args, tpl);

    error = elapi_dsp_msg_with_vargs(target, dispatcher, tpl, args);

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
    struct collection_item *tpl = NULL;

    TRACE_FLOW_STRING("elapi_create_simple_event", "Entry");

    /* Check storage */
    if (event == NULL ) {
        TRACE_ERROR_STRING("Event storage must be provided", "");
        return EINVAL;
    }

    *event = NULL;

    /* Get default template */
    error = elapi_get_default_tplt(&tpl);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to get default template. Error", error);
        return error;
    }

    va_start(args, event);

    /* Create event */
    error = elapi_create_event_with_vargs(&evt,
                                          tpl,
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
int elapi_msg(uint32_t target, struct collection_item *tpl, ...)
{
    int error = EOK;
    va_list args;
    struct collection_item *use_tpl;

    TRACE_FLOW_STRING("elapi_msg", "Entry");

    if (!tpl) {
        /* Get default template */
        error = elapi_get_default_tplt(&use_tpl);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to get default template. Error", error);
            return error;
        }
    }
    else use_tpl = tpl;

    va_start(args, tpl);

    error = elapi_dsp_msg_with_vargs(target,
                                     global_dispatcher,
                                     use_tpl,
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
