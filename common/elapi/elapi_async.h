/*
    ELAPI

    Header file for the ELAPI async processing interface.

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

#ifndef ELAPI_ASYNC_H
#define ELAPI_ASYNC_H

#include <sys/time.h>

#define ELAPI_FD_READ       0x00000001 /* request to read */
#define ELAPI_FD_WRITE      0x00000002 /* request to write */

/* Structure that holds ELAPI file descriptor's watch data */
struct elapi_fd_data;

/* Structure that holds ELAPI timer data */
struct elapi_tm_data;

/* Functions to set and get data from file descriptor data. */
/* Functions return EINVAL if passed in argument is invalid. */
int elapi_set_fd_priv(struct elapi_fd_data *fd_data,
                      void *priv_data_to_set);
int elapi_get_fd_priv(struct elapi_fd_data *fd_data,
                      void **priv_data_to_get);
/* Cleanup function */
void elapi_destroy_fd_data(struct elapi_fd_data *fd_data);

/* Functions to set and get custom data from timer data. */
/* Functions return EINVAL if passed in argument is invalid. */
int elapi_set_tm_priv(struct elapi_tm_data *tm_data,
                      void *priv_data_to_set);
int elapi_get_tm_priv(struct elapi_tm_data *tm_data,
                      void **priv_data_to_get);
/* Cleanup function */
void elapi_destroy_tm_data(struct elapi_tm_data *tm_data);

/* Public interfaces ELAPI exposes to handle fd or timer
 * events (do not confuse with log events).
 */
int elapi_process_fd(struct elapi_fd_data *fd_data);
int elapi_process_tm(struct elapi_tm_data *tm_data);

/* Signature of the function to add
 * file descriptor into the event loop.
 * Provided by caller of the ELAPI interface.
 */
typedef int (*elapi_add_fd)(int fd,
                            unsigned flags,
                            struct elapi_fd_data *fd_data,
                            void *ext_fd_data);

/* Signature of the function to remove
 * file descriptor from the event loop.
 * Provided by caller of the ELAPI interface.
 */
typedef int (*elapi_rem_fd)(int fd,
                            struct elapi_fd_data *fd_data,
                            void *ext_fd_data);

/* Signature of the function to set
 * file descriptor for read/write operation.
 * Provided by caller of the ELAPI interface.
 */
typedef int (*elapi_set_fd)(int fd,
                            unsigned flags,
                            struct elapi_fd_data *fd_data,
                            void *ext_fd_data);


/* Signature of the function to add timer.
 * Provided by caller of the ELAPI interface.
 */
typedef int (*elapi_add_tm)(struct timeval tv,
                            struct elapi_tm_data *tm_data,
                            void *ext_tm_data);

/* Signature of the function to add timer.
 * Provided by caller of the ELAPI interface.
 * Caller must be aware that the timeval strcuture
 * is allocated on stack.
 */
typedef int (*elapi_rem_tm)(struct elapi_tm_data *tm_data,
                            void *ext_tm_data);




#endif
