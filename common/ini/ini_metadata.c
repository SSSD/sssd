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

/* Beffer length used for int to string conversions */
#define CONVERSION_BUFFER 80

/* Invalid file mode */
#define WRONG_FMODE 0x80000000

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
            *metadata = NULL;
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
    char buff[CONVERSION_BUFFER];

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
        snprintf(buff, CONVERSION_BUFFER, "%lu",
                 (unsigned long)file_stats.st_uid);
        error = col_add_str_property(metasec,
                                     NULL,
                                     INI_META_KEY_UID,
                                     buff,
                                     0);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to save uid", error);
            col_destroy_collection(metasec);
            return error;
        }

        /* GID */
        snprintf(buff, CONVERSION_BUFFER, "%lu",
                 (unsigned long)file_stats.st_gid);
        error = col_add_str_property(metasec,
                                     NULL,
                                     INI_META_KEY_GID,
                                     buff,
                                     0);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to save gid", error);
            col_destroy_collection(metasec);
            return error;
        }

        /* PERMISSIONS */
        snprintf(buff, CONVERSION_BUFFER, "%lu",
                 (unsigned long)file_stats.st_mode);
        error = col_add_str_property(metasec,
                                     NULL,
                                     INI_META_KEY_PERM,
                                     buff,
                                     0);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to save permissions", error);
            col_destroy_collection(metasec);
            return error;
        }

        /* Modification time stamp */
        snprintf(buff, CONVERSION_BUFFER, "%ld",
                 (long int)file_stats.st_mtime);
        error = col_add_str_property(metasec,
                                     NULL,
                                     INI_META_KEY_MODIFIED,
                                     buff,
                                     0);
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

        /* The device ID can actualy be bigger than
         * 32-bits according to the type sizes.
         * However it is probaly not going to happen
         * on a real system.
         * Add a check for this case.
         */
        if (file_stats.st_dev > ULONG_MAX) {
            TRACE_ERROR_NUMBER("Device is out of range", ERANGE);
            col_destroy_collection(metasec);
            return ERANGE;
        }

        /* Device  ID */
        snprintf(buff, CONVERSION_BUFFER, "%lu",
                 (unsigned long)file_stats.st_dev);
        error = col_add_str_property(metasec,
                                     NULL,
                                     INI_META_KEY_DEV,
                                     buff,
                                     0);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to save inode", error);
            col_destroy_collection(metasec);
            return error;
        }

        /* i-node */
        snprintf(buff, CONVERSION_BUFFER, "%lu",
                (unsigned long)file_stats.st_ino);
        error = col_add_str_property(metasec,
                                     NULL,
                                     INI_META_KEY_INODE,
                                     buff,
                                     0);
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

/* Function to check uid or gid */
static int check_id(struct collection_item *metadata,
                    unsigned long id,
                    const char *key)
{
    int error = EOK;
    struct collection_item *item = NULL;
    unsigned long fid;

    TRACE_FLOW_STRING("check_id", "Entry");
    TRACE_INFO_STRING("Key", key);

    error = get_config_item(INI_META_SEC_ACCESS,
                            key,
                            metadata,
                            &item);
    if (error) {
        TRACE_ERROR_NUMBER("Internal collection error.", error);
        return error;
    }

    /* Entry is supposed to be there so it is an error
        * is the item is not found.
        */
    if (item == NULL) {
        TRACE_ERROR_NUMBER("Expected item is not found.", ENOENT);
        return ENOENT;
    }

    fid = get_ulong_config_value(item, 1, -1, &error);
    if ((error) || (fid == -1)) {
        TRACE_ERROR_NUMBER("Conversion failed", EINVAL);
        return EINVAL;
    }

    if (id != fid) {
        TRACE_ERROR_NUMBER("File ID:", fid);
        TRACE_ERROR_NUMBER("ID passed in.", id);
        TRACE_ERROR_NUMBER("Access denied.", EACCES);
        return EACCES;
    }

    TRACE_FLOW_STRING("check_id", "Exit");
    return EOK;
}

/* Function to check access */
int config_access_check(struct collection_item *metadata,
                        uint32_t flags,
                        uid_t uid,
                        gid_t gid,
                        mode_t mode,
                        mode_t mask)
{
    int error = EOK;
    struct collection_item *item = NULL;
    mode_t f_mode;

    TRACE_FLOW_STRING("config_access_check", "Entry");

    flags &= INI_ACCESS_CHECK_MODE |
             INI_ACCESS_CHECK_GID |
             INI_ACCESS_CHECK_UID;

    if ((metadata == NULL) || (flags == 0)) {
        TRACE_ERROR_NUMBER("Invalid parameter.", EINVAL);
        return EINVAL;

    }

    /* Check that metadata is actually metadata */
    if(!col_is_of_class(metadata, COL_CLASS_INI_META)) {
        TRACE_ERROR_NUMBER("Invalid collection.", EINVAL);
        return EINVAL;
    }

    /* Check mode */
    if (flags & INI_ACCESS_CHECK_MODE) {

        error = get_config_item(INI_META_SEC_ACCESS,
                                INI_META_KEY_PERM,
                                metadata,
                                &item);
        if (error) {
            TRACE_ERROR_NUMBER("Internal collection error.", error);
            return error;
        }

        /* Entry is supposed to be there so it is an error
            * is the item is not found.
            */
        if (item == NULL) {
            TRACE_ERROR_NUMBER("Expected item is not found.", ENOENT);
            return ENOENT;
        }

        f_mode = (mode_t)get_ulong_config_value(item, 1, WRONG_FMODE, &error);
        if ((error) || (f_mode == WRONG_FMODE)) {
            TRACE_ERROR_NUMBER("Conversion failed", error);
            return ENOENT;
        }

        TRACE_INFO_NUMBER("File mode as saved.", f_mode);
        f_mode &= S_IRWXU | S_IRWXG | S_IRWXO;
        TRACE_INFO_NUMBER("File mode adjusted.", f_mode);

        TRACE_INFO_NUMBER("Mode as provided.", mode);
        mode &= S_IRWXU | S_IRWXG | S_IRWXO;
        TRACE_INFO_NUMBER("Mode adjusted.", mode);

        /* Adjust mask */
        if (mask == 0) mask = S_IRWXU | S_IRWXG | S_IRWXO;
        else mask &= S_IRWXU | S_IRWXG | S_IRWXO;

        if ((mode & mask) != (f_mode & mask)) {
            TRACE_INFO_NUMBER("File mode:", (mode & mask));
            TRACE_INFO_NUMBER("Mode adjusted.", (f_mode & mask));
            TRACE_ERROR_NUMBER("Access denied.", EACCES);
            return EACCES;
        }
    }

    /* Check uid */
    if (flags & INI_ACCESS_CHECK_UID) {

        error = check_id(metadata, (unsigned long)uid, INI_META_KEY_UID);
        if (error) {
            TRACE_ERROR_NUMBER("Check for UID failed.", error);
            return error;
        }
    }

    /* Check gid */
    if (flags & INI_ACCESS_CHECK_GID) {

        error = check_id(metadata, (unsigned long)gid, INI_META_KEY_GID);
        if (error) {
            TRACE_ERROR_NUMBER("Check for UID failed.", error);
            return error;
        }
    }

    TRACE_FLOW_STRING("config_access_check", "Exit");
    return error;

}

static unsigned long get_checked_value(struct collection_item *metadata,
                                       const char *key,
                                       int *err)
{

    int error = EOK;
    struct collection_item *item = NULL;
    unsigned long value;

    TRACE_FLOW_STRING("get_checked_value", "Entry");
    TRACE_INFO_STRING("Key", key);

    error = get_config_item(INI_META_SEC_ACCESS,
                            key,
                            metadata,
                            &item);
    if (error) {
        TRACE_ERROR_NUMBER("Internal collection error.", error);
        *err = error;
        return 0;
    }

    /* Entry is supposed to be there so it is an error
     * is the item is not found.
     */
    if (item == NULL) {
        TRACE_ERROR_NUMBER("Expected item is not found.", ENOENT);
        *err = ENOENT;
        return 0;
    }

    value = get_ulong_config_value(item, 1, -1, &error);
    if ((error) || (value == -1)) {
        TRACE_ERROR_NUMBER("Conversion failed", EINVAL);
        *err = EINVAL;
        return 0;
    }

    *err = 0;

    TRACE_FLOW_NUMBER("get_checked_value Returning", value);
    return value;

}


/* Function to check whether the configuration is different */
int config_changed(struct collection_item *metadata,
                   struct collection_item *saved_metadata,
                   int *changed)
{
    int error = EOK;
    struct collection_item *md[2];
    unsigned long value[3][2];
    const char *key[] = { INI_META_KEY_MODIFIED,
                          INI_META_KEY_DEV,
                          INI_META_KEY_INODE };
    int i, j;


    TRACE_FLOW_STRING("config_changed", "Entry");

    if ((!metadata) ||
        (!saved_metadata) ||
        (!changed) ||
        (!col_is_of_class(metadata, COL_CLASS_INI_META)) ||
        (!col_is_of_class(saved_metadata, COL_CLASS_INI_META))) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        return EINVAL;
    }

    md[0] = metadata;
    md[1] = saved_metadata;

    /* Get three values from each collection and compare them */
    for (i = 0; i < 3; i++) {
        for (j = 0; j < 2; j++) {
            value[i][j] = get_checked_value(md[j], key[i] , &error);
            if (error) {
                TRACE_ERROR_NUMBER("Failed to get section.", error);
                return error;
            }
        }
        if (value[i][0] != value[i][1]) {
            *changed = 1;
            break;
        }
    }

    TRACE_FLOW_STRING("config_changed", "Exit");
    return error;

}
