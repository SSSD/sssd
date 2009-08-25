/*
    ELAPI

    Common sink interface header.

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

#ifndef ELAPI_SINK_H
#define ELAPI_SINK_H

#include <time.h>
#include "collection.h"

#define ELAPI_SINK_OK           0 /* Sink can be used for logging */
#define ELAPI_SINK_SUSPENDED    1 /* Sink is temporary disabled due to recoverable error */
#define ELAPI_SINK_DISABLED     2 /* Sink is explicitely disabled by the application */
#define ELAPI_SINK_PULSE        3 /* Sink is disabled for this one event */

#define SINK_LIB_NAME_SIZE  100
#define SINK_ENTRY_POINT    "get_sink_info"
#define SINK_NAME_TEMPLATE  "libelapi_sink_%s.so"

/* Flags related to loading sinks */
#define SINK_FLAG_NO_LIMIT          0x00000000 /* NO limits to loading and manipulating this sink - default */
#define SINK_FLAG_LOAD_SINGLE       0x00000001 /* Only allow one instance of the provider per process */


/* Log facility callbacks */
/* FIXME - the signatures need to take into the account async processing */
typedef int (*init_fn)(void **priv_ctx, char *name, struct collection_item *ini_config);
typedef int (*submit_fn)(void *priv_ctx, struct collection_item *event);
typedef void (*close_fn)(void **priv_ctx);

struct sink_cpb {
    init_fn init_cb;
    submit_fn submit_cb;
    close_fn close_cb;
};

/* The only open function the sink can expose */
typedef void (*sink_cpb_fn)(struct sink_cpb *sink_cpb_block);


/* Standard capability function */
void get_sink_info(struct sink_cpb *cpb_block);

#endif
