/*
    ELAPI

    Private header to define internal structure of the ELAPI fd data.

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

#ifndef ELAPI_FD_H
#define ELAPI_FD_H

#include "elapi_priv.h"

/* Structure that holds ELAPI file descriptor's watch data */
struct elapi_fd_data {
    int fd;
    void *ext_data;
    struct elapi_dispatcher *handle;
    struct elapi_sink_ctx *sink_ctx;
    struct collection_item *event;
};

/* Create the fd data structure for the event */
int elapi_create_fd_data(struct elapi_fd_data **fd_data,
                         int fd,
                         void *ext_data,
                         struct elapi_sink_ctx *sink_ctx,
                         struct collection_item *event);


#endif
