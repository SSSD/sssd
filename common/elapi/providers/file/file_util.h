/*
    ELAPI

    Header for file provider utility functions.

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

#ifndef FILE_UTIL_H
#define FILE_UTIL_H

#include "file_provider.h"
#include "elapi_basic.h"
#include "collection.h"

/* Sepcific format related includes */
#include "file_fmt_csv.h"

/* Leftovers' class and name */
#define FILE_LO_NAME    "lo"
#define FILE_LO_CLASS   20300

/* Allocate a new one or add to existing */
#define FILE_SER_NEW      0
#define FILE_SER_APPEND   1

/* Denotes how data is referenced */
#define FILE_ITEM_DIRECT 0  /* Data is in the collection */
#define FILE_ITEM_REF    1  /* Collection contains references */


/* Function to prepare data for logging */
int file_prep_data(struct elapi_data_out **out_data,
                   struct file_prvdr_ctx *ctx,
                   struct collection_item *event);

#endif
