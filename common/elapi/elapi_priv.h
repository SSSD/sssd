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
#include <stdarg.h>

#include "collection.h"
#include "elapi_basic.h"
#include "elapi_async.h"
#include "elapi_sink.h"

/* Classes of the collections used by ELAPI internally */
#define COL_CLASS_ELAPI_BASE        21000
#define COL_CLASS_ELAPI_EVENT       COL_CLASS_ELAPI_BASE + 0
#define COL_CLASS_ELAPI_TEMPLATE    COL_CLASS_ELAPI_BASE + 1
#define COL_CLASS_ELAPI_SINK        COL_CLASS_ELAPI_BASE + 2
#define COL_CLASS_ELAPI_TARGET      COL_CLASS_ELAPI_BASE + 3
#define COL_CLASS_ELAPI_SINK_REF    COL_CLASS_ELAPI_BASE + 4
#define COL_CLASS_ELAPI_RES_ITEM    COL_CLASS_ELAPI_BASE + 5

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
#define ELAPI_SINK_REQUIRED "required"
#define ELAPI_SINK_ONERROR  "onerror"
#define ELAPI_SINK_TIMEOUT  "timeout"
#define ELAPI_SINK_SYNCH    "synch"
#define ELAPI_RESOLVE_ITEM  "res_item"

/* Default timout before dispatcher tries to revive sink.
 * The actual value is configurable on per sink basis
 * so I do not see a value in making this a compile time
 * option (at least at the moment).
 */
#define ELAPI_SINK_DEFAULT_TIMEOUT  60

/* Names of embedded providers */
#define ELAPI_EMB_PRVDR_FILE    "file"
#define ELAPI_EMB_PRVDR_SYSLOG  "syslog"

/* Numbers for embedded providers */
#define ELAPI_EMB_PRVDR_FILENUM     0
#define ELAPI_EMB_PRVDR_SYSLOGNUM   1

#define ELAPI_TARGET_ALL    0xFFFF  /* 65k targets should be enough */

/* Possible values for onerror config parameter */
#define ELAPI_ONERROR_REVIVE        0
#define ELAPI_ONERROR_DISABLE       1

/* Structure that contains the pointer to functions
 * that needed to be provided to enable async processing.
 */
struct elapi_async_ctx {
    /* Callbacks related to file descriptor. */
    elapi_add_fd add_fd_cb;
    elapi_rem_fd rem_fd_cb;
    elapi_set_fd set_fd_cb;
    /* File descriptor callback external data. */
    void *ext_fd_data;
    /* Callbacks for timer */
    elapi_add_tm add_tm_cb;
    elapi_rem_tm rem_tm_cb;
    /* Timer's external data */
    void *ext_tm_data;
};

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
    /* Items to resolve */
    struct collection_iterator *resolve_list;
    /* Default event template */
    struct collection_item *default_template;
    /* Async processing related data */
    struct elapi_async_ctx *async_ctx;
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

/* Structure that hols sink's error status */
struct sink_status {
    int suspended;
    time_t lasttry;
};

/* Common configuration items for all sinks */
struct elapi_sink_cfg {
    char *provider;
    uint32_t required;
    uint32_t onerror;
    uint32_t timeout;
    uint32_t synch;
    void *priv_ctx;
    void *libhandle;
    sink_cpb_fn ability;
    struct sink_cpb cpb_cb;
};

/* The structure that describes the sink in the dispatcher */
struct elapi_sink_ctx {
    /* Input queue of a sink */
    struct collection_item *in_queue;
    /* Pending list */
    struct collection_item *pending;
    /* Sink's error status */
    struct sink_status status;
    /* Synch/asynch mode */
    uint32_t async_mode;
    /* Sink configuration data */
    struct elapi_sink_cfg sink_cfg;
    /* Back pointer to the target context.
     * This is needed for the cases
     * when we detect that sink
     * is failed and we need
     * to fail over for the next one.
     */
     struct elapi_tgt_ctx *tgt_ctx;

};

/* A helper structure that holds data
 * needed to resolve the event.
 */
struct elapi_resolve_data {
    /* Reference to the message item inside event */
    struct collection_item *message;
    /* Reference back to dispatcher */
    struct elapi_dispatcher *handle;
    /* Time related data */
    time_t tm;
    /* Structured UTC time */
    struct tm utc_time;
    /* Structured local time */
    struct tm local_time;
    /* Time offset */
    int offset;
};

/* Structure to pass data from logging function to targets */
struct elapi_tgt_data {
    struct collection_item *event;
    struct elapi_dispatcher *handle;
    uint32_t target_mask;
};


/* Lookup structure for searching for providers */
struct elapi_prvdr_lookup {
    const char *name;
    sink_cpb_fn ability;
};


/* The structure to hold a command and a result of the command execution */
struct elapi_get_sink {
    int action;
    int found;
};

/* Signature of the item resolution function */
typedef int (*elapi_rslv_cb)(struct elapi_resolve_data *resolver,
                             struct collection_item *item,
                             int *skip);

/* Structure to hold type-callback tuples */
struct elapi_rslv_item_data {
    int type;
    elapi_rslv_cb resolve_cb;
};

/* Structure to hold name-data tuples */
struct elapi_resolve_list {
    const char *name;
    struct elapi_rslv_item_data resolve_item;
};

/* Function to initialize resolution list */
int elapi_init_resolve_list(struct collection_iterator **list);

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
                   const char *sink,
                   struct elapi_dispatcher *handle);

/* Function to create a sink */
int elapi_sink_create(struct elapi_sink_ctx **sink_ctx,
                      const char *name,
                      struct collection_item *ini_config,
                      const char *appname);

/* Destroy sink */
void elapi_sink_destroy(struct elapi_sink_ctx *context);

/* Send event into the sink */
int elapi_sink_submit(struct elapi_sink_ctx *sink_ctx,
                      struct collection_item *event);

/* Create target object */
int elapi_tgt_create(struct elapi_tgt_ctx **context,
                     const char *target,
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

/* Submit event into the target */
int elapi_tgt_submit(struct elapi_dispatcher *handle,
                     struct elapi_tgt_ctx *context,
                     struct collection_item *event);

/* Create list of targets for a dispatcher */
int elapi_tgt_mklist(struct elapi_dispatcher *handle);

/* Create event context */
int elapi_resolve_event(struct collection_item **final_event,
                        struct collection_item *event,
                        struct elapi_dispatcher *handle);

/* Function to place the event items into a formatted string */
int elapi_sprintf(struct elapi_data_out *out_data,
                  const char *format_str,
                  struct collection_item *event);


/* Send ELAPI config errors into a file */
void elapi_dump_ini_err(struct collection_item *error_list);

#ifdef ELAPI_VERBOSE
/* Print dispatcher internals for testing and debugging purposes */
void elapi_print_dispatcher(struct elapi_dispatcher *handle);

/* Print sink context details */
void elapi_print_sink_ctx(struct elapi_sink_ctx *sink_context);
#else
#define elapi_print_dispatcher(arg)

#endif

#endif
