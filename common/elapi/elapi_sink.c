/*
    ELAPI

    Module that contains functions that manipulate ELAPI sinks.

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
#include <errno.h>      /* for errors */
#include <string.h>     /* for memset() and other */
#include <stdlib.h>     /* for free() */
#include <stdarg.h>     /* for va_arg */
#include <dlfcn.h>      /* for dlopen() */

#include "elapi_priv.h"
#include "ini_config.h"
#include "file_provider.h"
#include "trace.h"
#include "config.h"

/* NOTE: Add new provider here */
struct elapi_prvdr_lookup providers[] =
    {{ ELAPI_EMB_PRVDR_FILE, file_ability },
/*   { ELAPI_EMB_PRVDR_SYSLOG, syslog_ability } */
     { NULL, NULL }};


/* This is a traverse callback for sink list */
int elapi_sink_cb(const char *sink,
                  int sink_len,
                  int type,
                  void *data,
                  int length,
                  void *passed_data,
                  int *stop)
{
    TRACE_FLOW_STRING("elapi_sink_cb", "Entry.");

    /* FIXME THIS IS A PLACEHOLDER FUNCTION FOR NOW */

    /* Skip header */
    if (type == COL_TYPE_COLLECTION) {
        TRACE_FLOW_STRING("elapi_sink_cb - skip header", "Exit.");
        return EOK;
    }

    printf("Sink: %s\n", sink);

    TRACE_FLOW_STRING("elapi_sink_cb", "Exit.");
    return EOK;
}

/* Destroy sink */
void elapi_sink_destroy(struct elapi_sink_ctx *context)
{
    TRACE_FLOW_STRING("elapi_sink_destroy", "Entry.");

#ifdef ELAPI_VERBOSE
    /* FIXME: Can be removeed when the interface is stable */
    /* For testing purposes print the context we are trying to free */
    elapi_print_sink_ctx(context);
#endif

    if (context) {
        TRACE_INFO_STRING("Context is not null.", "Destroying sink.");
        /* FIXME: Do something about pending data if any */
        /* Assume for now that we do not care about pending data */

        /* If the private data has been allocated and close callback is there
         * call a callback to clean the data and free it.
         */
        if (context->sink_cfg.priv_ctx) {
            TRACE_INFO_STRING("Calling provider's close function.", "");
            /* Call close function of the provider */
            context->sink_cfg.cpb_cb.close_cb(&(context->sink_cfg.priv_ctx));
        }

        /* Now if the handle of the provider is set, offload the library instance */
        if (context->sink_cfg.libhandle) {
            TRACE_INFO_STRING("Offloading shared library.", "");
            dlclose(context->sink_cfg.libhandle);
            context->sink_cfg.libhandle = NULL;
        }

        if (context->sink_cfg.provider) {
            TRACE_INFO_STRING("Cleaning provider.", "");
            free(context->sink_cfg.provider);
            context->sink_cfg.provider = NULL;
        }

        TRACE_INFO_STRING("Freeing context", "");
        free(context);
    }

    TRACE_FLOW_STRING("elapi_sink_destroy", "Exit.");
}

/* Internal sink cleanup function */
int elapi_sink_free_cb(const char *sink,
                       int sink_len,
                       int type,
                       void *data,
                       int length,
                       void *passed_data,
                       int *stop)
{
    TRACE_FLOW_STRING("elapi_sink_free_cb", "Entry.");

    /* Skip header */
    if (type == COL_TYPE_COLLECTION) {
        TRACE_FLOW_STRING("elapi_sink_free_cb - skip header", "Exit.");
        return EOK;
    }

    TRACE_INFO_STRING("Cleaning Sink:", sink);

    elapi_sink_destroy(*((struct elapi_sink_ctx **)(data)));

    TRACE_FLOW_STRING("elapi_sink_free_cb", "Exit.");
    return EOK;
}

/* Function to read sink common configuration */
static int elapi_read_sink_cfg(struct elapi_sink_cfg *sink_cfg,
                               const char *name,
                               struct collection_item *ini_config)
{
    int error = EOK;
    struct collection_item *cfg_item = NULL;
    const char *provider;

    TRACE_FLOW_STRING("elapi_read_sink_cfg", "Entry point");

    /*********** Provider *************/

    /* First check if this sink is properly configured and get its provider */
    error = get_config_item(name,
                            ELAPI_SINK_PROVIDER,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read \"provider\" attribute returned error", error);
        return error;
    }

    /* Do we have provider? */
    if (cfg_item == NULL) {
        /* There is no provider - return error */
        TRACE_ERROR_STRING("Required key is missing in the configuration.", "Fatal Error!");
        return ENOENT;
    }

    /* Get provider value */
    provider = get_const_string_config_value(cfg_item, &error);
    if ((error) || (!provider) || (*provider == '\0')) {
        TRACE_ERROR_STRING("Invalid \"provider\" value", "Fatal Error!");
        return EINVAL;
    }

    /* Save provider inside configuration data */
    sink_cfg->provider = strdup(provider);
    if (sink_cfg->provider == NULL) {
        /* Failed to save the provider value */
        TRACE_ERROR_STRING("Failed to save \"provider\" value.", "Fatal Error!");
        return ENOMEM;
    }

    /*********** Required *************/
    /* Next is "required" field */
    cfg_item = NULL;
    error = get_config_item(name,
                            ELAPI_SINK_REQUIRED,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read \"required\" attribute returned error", error);
        return error;
    }

    /* Do we have "required"? */
    if (cfg_item == NULL) {
        /* There is no attribute - assume default */
        TRACE_INFO_STRING("No \"required\" attribute.", "Assume optional");
        sink_cfg->required = 0;
    }
    else {
        sink_cfg->required = (uint32_t) get_bool_config_value(cfg_item, '\0', &error);
        if (error) {
            TRACE_ERROR_STRING("Invalid \"required\" value", "Fatal Error!");
            return EINVAL;
        }
    }

    /*********** Onerror *************/
    /* Next is "onerror" field */
    cfg_item = NULL;
    error = get_config_item(name,
                            ELAPI_SINK_ONERROR,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read \"onerror\" attribute returned error", error);
        return error;
    }

    /* Do we have "required"? */
    if (cfg_item == NULL) {
        /* There is no attribute - assume default */
        TRACE_INFO_STRING("No \"onerror\" attribute.", "Assume retry (0)");
        sink_cfg->onerror = 0;
    }
    else {
        sink_cfg->onerror = (uint32_t) get_unsigned_config_value(cfg_item, 1, 0, &error);
        if (error) {
            TRACE_ERROR_STRING("Invalid \"onerror\" value", "Fatal Error!");
            return EINVAL;
        }
    }

    /*********** Timeout *************/
    /* Next is "timeout" field */
    cfg_item = NULL;
    error = get_config_item(name,
                            ELAPI_SINK_TIMEOUT,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read \"timeout\" attribute returned error", error);
        return error;
    }

    /* Do we have "required"? */
    if (cfg_item == NULL) {
        /* There is no attribute - assume default */
        TRACE_INFO_STRING("No \"timeout\" attribute.", "Assume default timeout");
        sink_cfg->timeout = ELAPI_SINK_DEFAULT_TIMEOUT;
    }
    else {
        sink_cfg->timeout = (uint32_t) get_unsigned_config_value(cfg_item,
                                                                 1,
                                                                 ELAPI_SINK_DEFAULT_TIMEOUT,
                                                                 &error);
        if (error) {
            TRACE_ERROR_STRING("Invalid \"timeout\" value", "Fatal Error!");
            return EINVAL;
        }
    }

    /*********** Synch *************/
    /* Next is "synch" field */
    cfg_item = NULL;
    error = get_config_item(name,
                            ELAPI_SINK_SYNCH,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read \"synch\" attribute returned error", error);
        return error;
    }

    /* Do we have "required"? */
    if (cfg_item == NULL) {
        /* There is no attribute - assume default */
        TRACE_INFO_STRING("No \"synch\" attribute.", "Assume retry (0)");
        sink_cfg->synch = 0;
    }
    else {
        sink_cfg->synch = (uint32_t) get_bool_config_value(cfg_item, '\0', &error);
        if (error) {
            TRACE_ERROR_STRING("Invalid \"synch\" value", "Fatal Error!");
            return EINVAL;
        }
    }

    TRACE_FLOW_STRING("elapi_read_sink_cfg", "Exit");
    return error;
}

/* Function to load external sink library */
static int elapi_load_lib(void **libhandle, sink_cpb_fn *sink_fn, const char *name)
{
    char sink_lib_name[SINK_LIB_NAME_SIZE];
    sink_cpb_fn sink_symbol = NULL;
    void *handle = NULL;
    char *lib_error = NULL;

    TRACE_FLOW_STRING("elapi_load_lib", "Entry point");

    if ((strlen(name) + sizeof(SINK_NAME_TEMPLATE)) >= SINK_LIB_NAME_SIZE) {
        TRACE_ERROR_STRING("Provider string is too long:", name);
        return EINVAL;
    }

    /* I considered using snprintf here but prefer this way.
     * Main reason is that snprintf will truncate
     * the string and I would have to determine that after
     * while in this implementation the copying
     * would never even start if the buffer is not
     * big enough.
     */
    sprintf(sink_lib_name, SINK_NAME_TEMPLATE, name);
    TRACE_INFO_STRING("Name of the library to try to load:", sink_lib_name);

    /* Load library */
    handle = dlopen(sink_lib_name, RTLD_LAZY);
    if (!handle) {
        TRACE_ERROR_STRING("Dlopen returned error", dlerror());
        return ELIBACC;
    }

    /* Clear any existing error */
    dlerror();
    /* Get addres to the main entry point */
    sink_symbol = (sink_cpb_fn)(dlsym(handle, SINK_ENTRY_POINT));
    if ((lib_error = dlerror()) != NULL)  {
        TRACE_ERROR_STRING("Dlsym returned error", lib_error);
        dlclose(handle);
        return ELIBACC;
    }

    *libhandle = handle;
    *sink_fn = sink_symbol;

    TRACE_FLOW_STRING("elapi_load_lib", "Exit");
    return EOK;
}

/* Function to load sink provider */
int elapi_sink_loader(struct elapi_sink_cfg *sink_cfg)
{
    int error = EOK;
    int num = 0;

    TRACE_FLOW_STRING("elapi_sink_loader", "Entry point");

    while (providers[num].name) {
        TRACE_INFO_STRING("Checking provider:", providers[num].name);
        if (strcasecmp(providers[num].name, sink_cfg->provider) == 0) {
            TRACE_INFO_STRING("Using provider:", providers[num].name);
            sink_cfg->ability = providers[num].ability;
            TRACE_FLOW_STRING("elapi_sink_loader", "Exit");
            return EOK;
        }
        num++;
    }

    TRACE_INFO_NUMBER("Provider not found.", "Assume external.");

    /* It is an external provider */
    error = elapi_load_lib(&(sink_cfg->libhandle), &(sink_cfg->ability), sink_cfg->provider);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to load library", error);
        return error;
    }

    TRACE_FLOW_STRING("elapi_sink_loader", "Exit");
    return error;
}


/* Function to load sink provider */
int elapi_load_sink(struct elapi_sink_cfg *sink_cfg,
                    const char *name,
                    struct collection_item *ini_config,
                    const char *appname)
{
    int error = EOK;
    TRACE_FLOW_STRING("elapi_load_sink", "Entry point");

    /* Use sink loading wrapper */
    error = elapi_sink_loader(sink_cfg);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to load sink", error);
        return error;
    }

    /* Call ability function to fill in the pointers */
    sink_cfg->ability(&(sink_cfg->cpb_cb));

    /* Make sure the callbacks are initialized */
    if ((sink_cfg->cpb_cb.init_cb == NULL) ||
        (sink_cfg->cpb_cb.submit_cb == NULL) ||
        (sink_cfg->cpb_cb.close_cb == NULL)) {
        TRACE_ERROR_NUMBER("One of the callbacks is missing",
                           "Bad provider!");
        return EINVAL;
    }


    /* Call init entry point */
    /* NOTE: it is the responsibility of the provider
     * to enforce singleton in case provider can't
     * be loaded more than once like syslog for example.
     */
    error = sink_cfg->cpb_cb.init_cb(&(sink_cfg->priv_ctx),
                                       name,
                                       ini_config,
                                       appname);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to initalize sink", error);
        return error;
    }

    TRACE_FLOW_STRING("elapi_load_sink", "Exit");
    return error;

}

/* Function to create a sink */
int elapi_sink_create(struct elapi_sink_ctx **sink_ctx,
                      const char *name,
                      struct collection_item *ini_config,
                      const char *appname)
{
    int error = EOK;
    uint32_t required;
    struct elapi_sink_ctx *sink_context = NULL;

    TRACE_FLOW_STRING("elapi_sink_create", "Entry point");

    /* Allocate context */
    sink_context = (struct elapi_sink_ctx *)malloc(sizeof(struct elapi_sink_ctx));
    if (sink_context == NULL) {
        TRACE_ERROR_NUMBER("Memory allocation failed. Error", ENOMEM);
        return ENOMEM;
    }

    /* Initialize the allocatable items so that we can call destroy function
     * in case of error.
     * FIXME - add initialization here for other elements as they are added.
     */

    sink_context->async_mode = 0;
    sink_context->in_queue = NULL;
    sink_context->pending = NULL;
    sink_context->sink_cfg.provider = NULL;
    sink_context->sink_cfg.priv_ctx = NULL;
    sink_context->sink_cfg.libhandle = NULL;
    sink_context->sink_cfg.ability = NULL;
    sink_context->sink_cfg.cpb_cb.init_cb = NULL;
    sink_context->sink_cfg.cpb_cb.submit_cb = NULL;
    sink_context->sink_cfg.cpb_cb.close_cb = NULL;

    /* Read common fields */
    error = elapi_read_sink_cfg(&(sink_context->sink_cfg),
                                name, ini_config);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to read sink configuration", error);
        elapi_sink_destroy(sink_context);
        return error;
    }

    TRACE_INFO_NUMBER("Address of init function",
                      sink_context->sink_cfg.cpb_cb.init_cb);
    TRACE_INFO_NUMBER("Address of submit function",
                      sink_context->sink_cfg.cpb_cb.submit_cb);
    TRACE_INFO_NUMBER("Address of close function",
                      sink_context->sink_cfg.cpb_cb.close_cb);

    /* Load sink */
    error = elapi_load_sink(&(sink_context->sink_cfg),
                            name,
                            ini_config,
                            appname);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to load sink", error);
        required = sink_context->sink_cfg.required;
        elapi_sink_destroy(sink_context);
        if (required) {
            TRACE_ERROR_NUMBER("Sink is required so returning error", error);
            return error;
        }
        else {
            *sink_ctx = NULL;
            TRACE_FLOW_STRING("Sink is not required so OK", "Exit");
            return EOK;
        }
    }

    /* We are done so return the context to the caller */
    *sink_ctx = sink_context;

    TRACE_FLOW_STRING("elapi_sink_create", "Exit");
    return error;
}

/* Send event into the sink */
int elapi_sink_submit(struct elapi_sink_ctx *sink_ctx,
                      struct collection_item *event)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_sink_submit", "Entry");

    /* FIXME: Manage the queue of the requests here.
     * For now just call provider's submit function.
     */
    error = sink_ctx->sink_cfg.cpb_cb.submit_cb(sink_ctx->sink_cfg.priv_ctx,
                                                event);

    TRACE_FLOW_STRING("elapi_sink_submit", "Exit");
    return error;
}
