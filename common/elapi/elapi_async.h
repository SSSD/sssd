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

/* Signature ELAPI callback function that
 * should be called when the event loop got an event on the
 * socket or file descriptor.
 * ELAPI will always try to write to sockets in async way
 * if the sink has this capability.
 * So this is the callback that will always be
 * invoked when we get ACK from the process receiving events.
 */
typedef int (*elapi_fd_callback)(int fd,                /* File descriptor     */
                                 void *elapi_data);     /* ELAPI supplied data */

/* Signature ELAPI callback function that
 * should be called when the event loop got a timer driven event.
 */
typedef int (*elapi_timer_callback)(void *elapi_data);  /* ELAPI supplied data */

/* Signature of the supplied by caller function that ELAPI
 * will call to add the fd into the application event processing loop.
 */
typedef int (*elapi_add_fd)(int fd,                     /* File descriptor to add */
                            void *callers_data,         /* Data that the function
                                                         * would need to do its work */
                            elapi_fd_callback handle,   /* Callback to call when event happens */
                            void *elapi_data);          /* Data to pass to the callback */

/* Signature of the supplied by caller function that ELAPI
 * will call to remove the fd from the application event processing loop.
 * The implementation of the function should assume that
 * ELAPI will close file/socket descriptor after colling this function.
 */
typedef int (*elapi_rem_fd)(int fd,                     /* File descriptor to add */
                            void *callers_data);        /* Data that the function
                                                         * would need to do its work */

/* Signature of the supplied by caller function that ELAPI
 * will call to add a new timer event to the application event processing loop.
 */
typedef int (*elapi_add_timer)(struct timeval timer,        /* Timer */
                               void *callers_data,          /* Data that the function
                                                             * would need to do its work */
                               elapi_timer_callback handle, /* Callback to call when event happens */
                               void *elapi_data);           /* Data to pass to the callback */





#endif
