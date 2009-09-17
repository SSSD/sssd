/*
    ELAPI

    Implementation for the ELAPI async processing interface.

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
#include <errno.h>  /* for errors */

#include "elapi_async.h"
/* Private headers that deal with fd and tm structure definitions */
#include "elapi_fd.h"
#include "elapi_tm.h"
#include "trace.h"
#include "config.h"

/* Functions to set and get data from file descriptor data. */
/* Functions return EINVAL if passed in argument is invalid. */
int elapi_set_fd_priv(struct elapi_fd_data *fd_data,
                      void *priv_data_to_set)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_set_fd_priv", "Entry");

    /* Check arguments */
    if (fd_data == NULL) {
        TRACE_ERROR_NUMBER("Invalid argument. Error", EINVAL);
        return EINVAL;
    }

    fd_data->ext_data = priv_data_to_set;

    TRACE_FLOW_STRING("elapi_set_fd_priv", "Exit");
    return error;
}

int elapi_get_fd_priv(struct elapi_fd_data *fd_data,
                      void **priv_data_to_get)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_get_fd_priv", "Entry");

    /* Check arguments */
    if ((fd_data == NULL) || (priv_data_to_get == NULL))  {
        TRACE_ERROR_NUMBER("Invalid argument. Error", EINVAL);
        return EINVAL;
    }

    *priv_data_to_get = fd_data->ext_data;

    TRACE_FLOW_STRING("elapi_get_fd_priv", "Exit");
    return error;
}

/* Cleanup function */
void elapi_destroy_fd_data(struct elapi_fd_data *fd_data)
{
    TRACE_FLOW_STRING("elapi_destroy_fd_data", "Entry");


    TRACE_FLOW_STRING("elapi_destroy_fd_data", "Exit");
}


/* Functions to set and get custom data from timer data. */
/* Functions return EINVAL if passed in argument is invalid. */
int elapi_set_tm_priv(struct elapi_tm_data *tm_data,
                      void *priv_data_to_set)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_set_tm_priv", "Entry");

    /* Check arguments */
    if (tm_data == NULL) {
        TRACE_ERROR_NUMBER("Invalid argument. Error", EINVAL);
        return EINVAL;
    }

    tm_data->ext_data = priv_data_to_set;

    TRACE_FLOW_STRING("elapi_set_tm_priv", "Exit");
    return error;
}

int elapi_get_tm_priv(struct elapi_tm_data *tm_data,
                      void **priv_data_to_get)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_get_tm_priv", "Entry");

    /* Check arguments */
    if ((tm_data == NULL) || (priv_data_to_get == NULL))  {
        TRACE_ERROR_NUMBER("Invalid argument. Error", EINVAL);
        return EINVAL;
    }

    *priv_data_to_get = tm_data->ext_data;

    TRACE_FLOW_STRING("elapi_get_tm_priv", "Exit");
    return error;
}

/* Cleanup function */
void elapi_destroy_tm_data(struct elapi_tm_data *tm_data)
{
    TRACE_FLOW_STRING("elapi_destroy_tm_data", "Entry");


    TRACE_FLOW_STRING("elapi_destroy_tm_data", "Exit");
}


/* Public interfaces ELAPI exposes to handle fd or timer
 * events (do not confuse with log events).
 */
int elapi_process_fd(struct elapi_fd_data *fd_data)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_process_fd", "Entry");


    TRACE_FLOW_STRING("elapi_process_fd", "Exit");
    return error;
}

int elapi_process_tm(struct elapi_tm_data *tm_data)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_process_tm", "Entry");


    TRACE_FLOW_STRING("elapi_process_tm", "Exit");
    return error;
}
