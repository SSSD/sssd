/*
    INI LIBRARY

    Header file for the meta data related functions.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

    INI Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    INI Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with INI Library.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef INI_METADATA_H
#define INI_METADATA_H

#include <stdint.h>
#include <stdio.h>
#include "collection.h"


/* Prepare metadata */
int prepare_metadata(uint32_t metaflags,
                     struct collection_item **metadata,
                     int *save_error);

/* Collect metadata for the file */
int collect_metadata(uint32_t metaflags,
                     struct collection_item **metadata,
                     FILE *config_file,
                     const char *config_filename);



#endif
