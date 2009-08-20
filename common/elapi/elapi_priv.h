/*
    ELAPI

    Private header file continaing internal data for the ELAPI interface.

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

#ifndef ELAPI_PRIV_H
#define ELAPI_PRIV_H

#include <stdint.h>

#include "collection.h"
#include "elapi_async.h"
/* Classes of the collections used by ELAPI internally */
#define COL_CLASS_ELAPI_BASE        21000
#define COL_CLASS_ELAPI_EVENT       COL_CLASS_ELAPI_BASE + 0
#define COL_CLASS_ELAPI_TEMPLATE    COL_CLASS_ELAPI_BASE + 1
#define COL_CLASS_ELAPI_SINK        COL_CLASS_ELAPI_BASE + 2
#define COL_CLASS_ELAPI_TARGET      COL_CLASS_ELAPI_BASE + 3
#define COL_CLASS_ELAPI_SINK_REF    COL_CLASS_ELAPI_BASE + 4

/* Names for the collections */
#define E_TEMPLATE_NAME "template"
#define E_EVENT_NAME "event"

/* Constants used in INI file and in
 * the internal collection objects.
 */
#define ELAPI_DISPATCHER    "dispatcher"
#define ELAPI_SINKS         "sinks"
#define ELAPI_TARGETS       "targets"
#define ELAPI_SINK_REFS     "srefs"
#define ELAPI_TARGET_VALUE  "value"
#define ELAPI_SINK_PROVIDER "provider"

#define ELAPI_TARGET_ALL    0xFFFF  /* 65k targets should be enough */

struct elapi_dispatcher {
    /* Application name */
    char *appname;
    /* List of target names and chars */
    char **targets;
    /* Collection of targets */
    struct collection_item *target_list;
    /* Counter of the targets */
    int target_counter;
    /* Collection of sinks */
    struct collection_item *sink_list;
    /* Configuration */
    struct collection_item *ini_config;
    /* Default event template */
    struct collection_item *default_template;
    /* Async processing related data */
    elapi_add_fd add_fd_add_fn;
    elapi_rem_fd add_fd_rem_fn;
    elapi_add_timer add_timer_fn;
    void *callers_data;
    uint32_t async_mode;
};

/* Structure to pass data from logging function to targets */
struct elapi_tgt_data {
    struct collection_item *event;
    struct elapi_dispatcher *handle;
    uint32_t target_mask;
};

/* This is a structure that holds the information
 *  about the target.
 */
struct elapi_tgt_ctx {
    /* Value associted with the
     * target in the config file.
     */
    uint32_t target_value;
    /* Collection of pointers to sink objects */
    struct collection_item *sink_ref_list;
    /* FIXME - other things that belong here are:
     * state of the chain
     * reference to the current sink
     * reference to the preferred sink
     * etc.
     */
};

/* The structure that describes the sink in the dispatcher */
struct elapi_sink_ctx {
    /* Inpit queue of a sink */
    struct collection_item *in_queue;
    /* Pending list */
    struct collection_item *pending;
    /* FIXME: add:
     * sink's error status
     * sink's common config data (common between all sinks)
     * sink personal specific config data (config data specific to this sink)
     */
    /* Is this a sink or async sink */
    uint32_t async_mode;
};

/* The structure to hold a command and a result of the command execution */
struct elapi_get_sink {
    int action;
    int found;
};

/* Function to create event using arg list */
int elapi_create_event_with_vargs(struct collection_item **event,
                                  struct collection_item *template,
                                  struct collection_item *collection,
                                  int mode, va_list args);

/* Function to create event template using arg list */
int elapi_create_event_template_with_vargs(struct collection_item **template,
                                           unsigned base,
                                           va_list args);

/* Sink handler function */
int elapi_sink_cb(const char *sink,
                  int sink_len,
                  int type,
                  void *data,
                  int length,
                  void *passed_data,
                  int *stop);

/* Internal sink cleanup function */
int elapi_sink_free_cb(const char *sink,
                       int sink_len,
                       int type,
                       void *data,
                       int length,
                       void *passed_data,
                       int *stop);



/* Function to add a sink based on configuration  */
int elapi_sink_add(struct collection_item **sink_ref,
                   char *sink,
                   struct elapi_dispatcher *handle);

/* Create target object */
int elapi_tgt_create(struct elapi_tgt_ctx **context,
                     char *target,
                     struct elapi_dispatcher *handle);

/* Destroy target object */
void elapi_tgt_destroy(struct elapi_tgt_ctx *context);

/* Internal target cleanup function */
int elapi_tgt_free_cb(const char *sink,
                      int sink_len,
                      int type,
                      void *data,
                      int length,
                      void *passed_data,
                      int *stop);

/* Handler for logging through the targets */
int elapi_tgt_cb(const char *target,
                 int target_len,
                 int type,
                 void *data,
                 int length,
                 void *passed_data,
                 int *stop);

/* Create list of targets for a dispatcher */
int elapi_tgt_mklist(struct elapi_dispatcher *handle);

/* Send ELAPI config errors into a file */
void elapi_dump_ini_err(struct collection_item *error_list);

/* Print dispatcher internals for testing and debugin purposes */
void elapi_print_dispatcher(struct elapi_dispatcher *handle);


#endif
