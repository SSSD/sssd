/*
    ELAPI

    Header file for the ELAPI logging interface.

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

#ifndef ELAPI_LOG_H
#define ELAPI_LOG_H

#include <stdint.h>

#include "elapi_async.h"

/* Default values for targets -
 * these constants match values in the default configuration.
 */
#define E_TARGET_DEBUG      0x00000001
#define E_TARGET_AUDIT      0x00000002
#define E_TARGET_LOG        0x00000004


/* Opaque dispatcher structure */
struct elapi_dispatcher;


/******************** Low level thread safe interface ************************************/
/* This interface should be used if application plans to control the dispatcher,
 * implement its own sinks that can be added dynamically or implements it own routing function.
 */

/********** Main functions of the interface **********/
/* Structure that contains the pointer to functions
 * that needed to be provided to enable async processing.
 */
struct elapi_async_ctx;

/* Interface to create the async context */
int elapi_create_asctx(struct elapi_async_ctx **ctx,
                       elapi_add_fd add_fd_cb,
                       elapi_rem_fd rem_fd_cb,
                       elapi_set_fd set_fd_cb,
                       void *ext_fd_data,
                       elapi_add_tm add_tm_cb,
                       elapi_rem_tm rem_tm_cb,
                       void *ext_tm_data);

/* Function to free the async context */
void elapi_destroy_asctx(struct elapi_async_ctx *ctx);

/* Function to create a dispatcher */
int elapi_create_dispatcher(struct elapi_dispatcher **dispatcher,  /* Handle of the dispatcher will be stored in this variable */
                            const char *appname,                   /* Application name. Passed to the sinks to do initialization */
                            const char *config_path);              /* See notes below in the elapi_init() function. */

/* A more advanced function to create a dispatcher */
int elapi_create_dispatcher_adv(struct elapi_dispatcher **dispatcher,  /* Handle of the dispatcher will be stored in this variable */
                                const char *appname,                   /* Application name. Passed to the sinks to do initialization */
                                const char *config_path,               /* See notes below in the elapi_init() function. */
                                struct elapi_async_ctx *ctx);          /* Async context. */

/* Function to clean memory associated with the dispatcher */
void elapi_destroy_dispatcher(struct elapi_dispatcher *dispatcher);

/* Function to log an event */
int elapi_dsp_log(uint32_t target,
                  struct elapi_dispatcher *dispatcher,
                  struct collection_item *event);

/* Function to log raw key value pairs without creating an event */
int elapi_dsp_msg(uint32_t target,
                  struct elapi_dispatcher *dispatcher,
                  struct collection_item *template,
                  ...);

/********** Advanced dispatcher management functions **********/

/* Managing the sink collection */
int elapi_alter_dispatcher(struct elapi_dispatcher *dispatcher,  /* Dispatcher */
                           const char *target,                   /* Target to look for */
                           const char *sink,                     /* Sink to change */
                           int action);                          /* Action to perform for sink */

/* Get target list */
char **elapi_get_target_list(struct elapi_dispatcher *dispatcher);

/* Free target list */
void elapi_free_target_list(char **target_list);

/* Get sink list */
char **elapi_get_sink_list(struct elapi_dispatcher *dispatcher, char *target);

/* Free sink list */
void elapi_free_sink_list(char **sink_list);


/******************** High level interface ************************************/
/* This interface is not thread safe but convenient. It hides the dispatcher. */

/* Function to initialize ELAPI library in the single threaded applications */
/* If config_path = NULL the configuration will be read from the standard locations:
 *  - First from the global configuration file "elapi.conf" located in the directory
 *    defined at the compile time by the ELAPI_DEFAULT_CONFIG_DIR constant.
 *    This file is assumed to contain common ELAPI configuration for this host;
 *  - Second from the file with name constructed from appname by appending to it
 *    suffix ".conf". The file will be looked in the directory pointed by
 *    ELAPI_DEFAULT_CONFIG_APP_DIR constant that is defined at compile time.
 *  The data from second file overwrites and complements the data from the first
 *  one.
 *  It is expected that applications will take advantage of the common
 *  central convention so config_path should be NULL in most cases.
 *
 * If config_path points to a file the function will try to read the file
 * as if it is a configuration file. The appname is ignored in this case.
 * If config_path points to a directory, the function will try to read
 * configuration from the file with name constructed by appending suffix ".conf"
 * to appname. The file will be looked up in that directory.
 * If the config_path is neither file or directory the default values will be used
 * to initialize dispatcher.
 *
 * In case appname is NULL a default value defined by build time constant
 * ELAPI_DEFAULT_APP_NAME will be used.
 */
int elapi_init(const char *appname, const char *config_path);

/* Log key value pairs  */
int elapi_msg(uint32_t target,
              struct collection_item *template, ...);

/* Log event  */
int elapi_log(uint32_t target,
              struct collection_item *event);

/* Corresponding wrapping macroses */
#define ELAPI_EVT_DEBUG(event) elapi_log(E_TARGET_DEBUG, event)
#define ELAPI_EVT_LOG(event)   elapi_log(E_TARGET_LOG, event)
#define ELAPI_EVT_AUDIT(event) elapi_log(E_TARGET_AUDIT, event)

/* Get dispatcher if you want to do some advanced operations */
struct elapi_dispatcher *elapi_get_dispatcher(void);

/* Close audit */
void elapi_close(void);

#endif
