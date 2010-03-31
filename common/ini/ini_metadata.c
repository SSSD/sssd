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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
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
                     FILE *config_file,
                     const char *config_filename)
{
    int error = EOK;
    struct collection_item *metasec = NULL;
    int filedes;
    struct stat file_stats;

    TRACE_FLOW_STRING("collect_metadata", "Entry");
    /* Check and create section for file error if needed */
    if (metaflags & INI_META_SEC_ACCESS_FLAG) {
        /* Create ACCESS collection */
        error = col_create_collection(&metasec,
                                      INI_META_SEC_ACCESS,
                                      COL_CLASS_INI_SECTION);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to create access section.", error);
            col_destroy_collection(metasec);
            return error;
        }

        filedes = fileno(config_file);

        /* Collect statistics */
        errno = 0;
        if (fstat(filedes, &file_stats) < 0) {
            error = errno;
            TRACE_ERROR_NUMBER("Failed to get statistics.", error);
            col_destroy_collection(metasec);
            return error;
        }

        /* Record statistics */
        /* UID */
        error = col_add_int_property(metasec,
                                     NULL,
                                     INI_META_KEY_UID,
                                     file_stats.st_uid);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to save uid", error);
            col_destroy_collection(metasec);
            return error;
        }

        /* GID */
        error = col_add_int_property(metasec,
                                     NULL,
                                     INI_META_KEY_GID,
                                     file_stats.st_gid);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to save gid", error);
            col_destroy_collection(metasec);
            return error;
        }

        /* PERMISSIONS */
        error = col_add_unsigned_property(metasec,
                                          NULL,
                                          INI_META_KEY_PERM,
                                          file_stats.st_mode);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to save permissions", error);
            col_destroy_collection(metasec);
            return error;
        }

        /* Modification time stamp */
        error = col_add_int_property(metasec,
                                     NULL,
                                     INI_META_KEY_MODIFIED,
                                     file_stats.st_mtime);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to save modification time", error);
            col_destroy_collection(metasec);
            return error;
        }

        /* Name */
        error = col_add_str_property(metasec,
                                     NULL,
                                     INI_META_KEY_NAME,
                                     config_filename,
                                     0);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to save file name", error);
            col_destroy_collection(metasec);
            return error;
        }

        /* Device  ID */
        error = col_add_int_property(metasec,
                                     NULL,
                                     INI_META_KEY_DEV,
                                     file_stats.st_dev);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to save inode", error);
            col_destroy_collection(metasec);
            return error;
        }

        /* i-node */
        error = col_add_int_property(metasec,
                                     NULL,
                                     INI_META_KEY_INODE,
                                     file_stats.st_ino);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to save inode", error);
            col_destroy_collection(metasec);
            return error;
        }

        /* Add section to metadata */
        error = col_add_collection_to_collection(
                                    *metadata,
                                    NULL,
                                    NULL,
                                    metasec,
                                    COL_ADD_MODE_REFERENCE);

        col_destroy_collection(metasec);

        if (error) {
            TRACE_ERROR_NUMBER("Failed to save file name", error);
            return error;
        }
    }

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
