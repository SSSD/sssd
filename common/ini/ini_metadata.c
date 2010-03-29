/*
    INI LIBRARY

    Functions to process metadata.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2010

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

#define _GNU_SOURCE
#include "config.h"
#include "collection.h"
#include "collection_tools.h"
#include "trace.h"
#include "ini_config.h"
#include "ini_metadata.h"

#define INI_METADATA    "meta"

/* Prepare metadata */
int prepare_metadata(uint32_t metaflags,
                     struct collection_item **metadata,
                     int *save_error)
{
    int error = EOK;
    struct collection_item *metasec = NULL;

    TRACE_FLOW_STRING("prepare_metadata", "Entry");

    /* Are we supposed to collect or process meta data ? */
    if (!metadata) {
        TRACE_FLOW_STRING("No meta data", "Exit");
        return EOK;
    }

    /* Allocate metadata */
    error = col_create_collection(metadata,
                                  INI_METADATA,
                                  COL_CLASS_INI_META);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to create meta data", error);
        return error;
    }

    /* Check and create section for file error if needed */
    if (metaflags & INI_META_SEC_ERROR_FLAG) {
        /* Create ERROR collection */
        if ((error = col_create_collection(&metasec,
                                           INI_META_SEC_ERROR,
                                           COL_CLASS_INI_SECTION)) ||
            (error = col_add_collection_to_collection(
                                           *metadata,
                                           NULL,
                                           NULL,
                                           metasec,
                                           COL_ADD_MODE_REFERENCE))) {
            TRACE_ERROR_NUMBER("Failed to create error section", error);
            col_destroy_collection(metasec);
            col_destroy_collection(*metadata);
            return error;
        }
        /* If we are here we would have to save file open error */
        *save_error = 1;
        col_destroy_collection(metasec);
    }

    TRACE_FLOW_STRING("prepare_metadata", "Exit");
    return error;
}



/* Collect metadata for the file */
int collect_metadata(uint32_t metaflags,
                     struct collection_item **metadata,
                     FILE *config_file)
{
    int error = EOK;

    TRACE_FLOW_STRING("collect_metadata", "Entry");

    TRACE_FLOW_STRING("collect_metadata", "Exit");
    return error;
}

/* Function to free metadata */
void free_ini_config_metadata(struct collection_item *metadata)
{
    TRACE_FLOW_STRING("free_ini_config_metadata", "Entry");
    col_destroy_collection(metadata);
    TRACE_FLOW_STRING("free_ini_config_metadata", "Exit");
}
