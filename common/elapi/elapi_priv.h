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

#include "collection.h"
#include "elapi_async.h"
/* Classes of the collections used by ELAPI internally */
#define COL_CLASS_ELAPI_BASE        21000
#define COL_CLASS_ELAPI_EVENT       COL_CLASS_ELAPI_BASE + 0
#define COL_CLASS_ELAPI_TEMPLATE    COL_CLASS_ELAPI_BASE + 1
#define COL_CLASS_ELAPI_SINK        COL_CLASS_ELAPI_BASE + 2

/* Names for the collections */
#define E_TEMPLATE_NAME "template"
#define E_EVENT_NAME "event"


#define ELAPI_DISPATCHER    "dispatcher"
#define ELAPI_SINKS         "sinks"

struct elapi_dispatcher {
    char **sinks;
    int need_to_free;
    char *appname;
    /*event_router_fn router; - FIXME - not defined yet */
    struct collection_item *sink_list;
    int sink_counter;
    struct collection_item *ini_config;
    /* Default event template */
    struct collection_item *default_template;
    /* Async processing related data */
    elapi_add_fd add_fd_add_fn;
    elapi_rem_fd add_fd_rem_fn;
    elapi_add_timer add_timer_fn;
    void *callers_data;
    int async_mode;
};

/* Structure to pass data from logging function to sinks */
struct elapi_sink_context {
    struct collection_item *event;
    struct elapi_dispatcher *handle;
    char *format;
    char *previous;
    int previous_status;
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
int elapi_internal_sink_handler(const char *sink,
                                int sink_len,
                                int type,
                                void *data,
                                int length,
                                void *passed_data,
                                int *stop);

/* Internal sink cleanup function */
int elapi_internal_sink_cleanup_handler(const char *sink,
                                        int sink_len,
                                        int type,
                                        void *data,
                                        int length,
                                        void *passed_data,
                                        int *stop);


/* Create list of the sinks */
int elapi_internal_construct_sink_list(struct elapi_dispatcher *handle);

/* Function to add a sink to the collection */
int elapi_internal_add_sink_to_collection(struct collection_item *sink_list,
                                          char *sink,
                                          char *appname);

/* Send ELAPI config errors into a file */
void elapi_internal_dump_errors_to_file(struct collection_item *error_list);


#endif
