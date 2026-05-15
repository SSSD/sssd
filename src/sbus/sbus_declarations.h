/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2017 Red Hat

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

#ifndef _SBUS_DECLARATIONS_H_
#define _SBUS_DECLARATIONS_H_

#include <sys/types.h>
#include <tevent.h>
#include <talloc.h>

#include "util/util.h"

/*****************************************************************************
 *
 * This file contains declarations of symbols that must be generally available
 * to the user but that must not be used on their own so they should not be
 * present in sbus.h or other header files.
 *
 * Do not include this file directly.
 *
 *****************************************************************************/

struct sbus_request;
struct sbus_connection;
struct sbus_server;
enum sbus_reconnect_status;

/* Connection custom destructor function. */
typedef void * sbus_connection_destructor_data;
typedef void
(*sbus_connection_destructor_fn)(sbus_connection_destructor_data);

/* Reconnection callback. */
typedef void * sbus_reconnect_data;
typedef void
(*sbus_reconnect_cb)(struct sbus_connection *,
                     enum sbus_reconnect_status,
                     sbus_reconnect_data);

/* Access check function. */
typedef void * sbus_connection_access_check_data;
typedef errno_t
(*sbus_connection_access_check_fn)(struct sbus_request *,
                                   sbus_connection_access_check_data);

/* On new server connection function. */
typedef void * sbus_server_on_connection_data;
typedef errno_t
(*sbus_server_on_connection_cb)(struct sbus_connection *,
                                sbus_server_on_connection_data);

/**
 * This function is wrapped with sbus_connection_set_destructor macro.
 * Please, use this macro instead.
 *
 * @see sbus_connection_set_destructor
 */
void _sbus_connection_set_destructor(struct sbus_connection *conn,
                                     const char *name,
                                     sbus_connection_destructor_fn fn,
                                     sbus_connection_destructor_data data);

/**
 * @see sbus_connection_set_access_check
 */
void
_sbus_connection_set_access_check(struct sbus_connection *conn,
                                  const char *name,
                                  sbus_connection_access_check_fn check_fn,
                                  sbus_connection_access_check_data data);

/**
 * @see sbus_connection_get_data
 */
void *_sbus_connection_get_data(struct sbus_connection *conn);

/**
 * @see sbus_reconnect_enable
 */
void
_sbus_reconnect_enable(struct sbus_connection *conn,
                       unsigned int max_retries,
                       sbus_reconnect_cb callback,
                       sbus_reconnect_data callback_data);

/**
 * @see sbus_server_set_on_connection
 */
void
_sbus_server_set_on_connection(struct sbus_server *server,
                               const char *name,
                               sbus_server_on_connection_cb on_connection_cb,
                               sbus_server_on_connection_data data);

#endif /* _SBUS_DECLARATIONS_H_ */
