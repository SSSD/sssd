/*
    INI LIBRARY

    Reading configuration from INI file
    and storing as a collection.

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

#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"
#include "trace.h"
#include "collection.h"
#include "collection_tools.h"
#include "path_utils.h"
#include "ini_defines.h"
#include "ini_parse.h"
#include "ini_metadata.h"
#include "ini_config.h"


/***************************************************************************/
/* Function to read single ini file and pupulate
 * the provided collection with subcollcetions from the file */
static int ini_to_collection(FILE *file,
                             const char *config_filename,
                             struct collection_item *ini_config,
                             int error_level,
                             struct collection_item **error_list,
                             struct collection_item *lines)
{
    int error;
    int status;
    int section_count = 0;
    char *key = NULL;
    char *value = NULL;
    struct collection_item *current_section = NULL;
    int length;
    int ext_err = -1;
    struct parse_error pe;
    int line = 0;
    int created = 0;
    char buf[BUFFER_SIZE+1];


    TRACE_FLOW_STRING("ini_to_collection", "Entry");

    /* Open the collection of errors */
    if (error_list != NULL) {
        *error_list = NULL;
        error = col_create_collection(error_list, INI_ERROR, COL_CLASS_INI_PERROR);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to create error collection", error);
            return error;
        }
        /* Add file name as the first item */
        error = col_add_str_property(*error_list, NULL, INI_ERROR_NAME, config_filename, 0);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to and name to collection", error);
            col_destroy_collection(*error_list);
            return error;
        }
        created = 1;
    }

    /* Read file lines */
    while (1) {
        /* Always read one less than the buffer */
        status = read_line(file, buf, BUFFER_SIZE+1, &key, &value, &length, &ext_err);
        if (status == RET_EOF) break;

        line++;

        switch (status) {
        case RET_PAIR:

#ifdef HAVE_VALIDATION

            /* Add line to the collection of lines.
             * It is pretty safe in this case to just type cast the value to
             * int32_t since it is unrealistic that ini file will ever have
             * so many lines.
             */
            if (lines) {
                error = col_add_int_property(lines, NULL, key, (int32_t)line);
                if (error) {
                    TRACE_ERROR_NUMBER("Failed to add line to line collection", error);
                    col_destroy_collection(current_section);
                    if (created) {
                        col_destroy_collection(*error_list);
                        *error_list = NULL;
                    }
                    return error;
                }
            }

#endif /* HAVE_VALIDATION */

            /* Do we have a section at the top of the file ? */
            if (section_count == 0) {
                /* Check if collection already exists */
                error = col_get_collection_reference(ini_config, &current_section,
                                                     INI_DEFAULT_SECTION);
                if (error != EOK) {
                    /* Create default collection */
                    if ((error = col_create_collection(&current_section,
                                                       INI_DEFAULT_SECTION,
                                                       COL_CLASS_INI_SECTION)) ||
                        (error = col_add_collection_to_collection(ini_config,
                                                                  NULL,NULL,
                                                                  current_section,
                                                                  COL_ADD_MODE_REFERENCE))) {
                        TRACE_ERROR_NUMBER("Failed to create collection", error);
                        col_destroy_collection(current_section);
                        if (created) {
                            col_destroy_collection(*error_list);
                            *error_list = NULL;
                        }
                        return error;
                    }
                }
                section_count++;
            }

            /* Put value into the collection */
            error = col_insert_str_property(current_section,
                                            NULL,
                                            COL_DSP_END,
                                            NULL,
                                            0,
                                            COL_INSERT_DUPOVER,
                                            key,
                                            value,
                                            length);
            if (error != EOK) {
                TRACE_ERROR_NUMBER("Failed to add pair to collection", error);
                col_destroy_collection(current_section);
                if (created) {
                    col_destroy_collection(*error_list);
                    *error_list = NULL;
                }
                return error;
            }
            break;

        case RET_SECTION:

#ifdef HAVE_VALIDATION

            /* Add line to the collection of lines */
            if (lines) {
                /* For easier search make line numbers for the sections negative.
                 * This would allow differentiating sections and attributes.
                 * It is pretty safe in this case to just type cast the value to
                 * int32_t since it is unrealistic that ini file will ever have
                 * so many lines.
                 */
                error = col_add_int_property(lines, NULL, key, (int32_t)(-1 * line));
                if (error) {
                    TRACE_ERROR_NUMBER("Failed to add line to line collection", error);
                    col_destroy_collection(current_section);
                    if (created) {
                        col_destroy_collection(*error_list);
                        *error_list = NULL;
                    }
                    return error;
                }
            }

#endif /* HAVE_VALIDATION */

            /* Read a new section */
            col_destroy_collection(current_section);
            current_section = NULL;

            error = col_get_collection_reference(ini_config, &current_section, key);
            if (error != EOK) {
                /* Create default collection */
                if ((error = col_create_collection(&current_section, key,
                                                   COL_CLASS_INI_SECTION)) ||
                    (error = col_add_collection_to_collection(ini_config,
                                                              NULL, NULL,
                                                              current_section,
                                                              COL_ADD_MODE_REFERENCE))) {
                    TRACE_ERROR_NUMBER("Failed to add collection", error);
                    col_destroy_collection(current_section);
                    if (created) {
                        col_destroy_collection(*error_list);
                        *error_list = NULL;
                    }
                    return error;
                }
            }
            section_count++;
            break;

        case RET_EMPTY:
            TRACE_INFO_STRING("Empty string", "");
            break;

        case RET_COMMENT:
            TRACE_INFO_STRING("Comment", "");
            break;

        case RET_ERROR:
            pe.line = line;
            pe.error = ext_err;
            error = col_add_binary_property(*error_list, NULL,
                                            ERROR_TXT, &pe, sizeof(pe));
            if (error) {
                TRACE_ERROR_NUMBER("Failed to add error to collection", error);
                col_destroy_collection(current_section);
                if (created) {
                    col_destroy_collection(*error_list);
                    *error_list = NULL;
                }
                return error;
            }
            /* Exit if there was an error parsing file */
            if (error_level != INI_STOP_ON_NONE) {
                TRACE_ERROR_STRING("Invalid format of the file", "");
                col_destroy_collection(current_section);
                return EIO;
            }
            break;

        case RET_INVALID:
        default:
            pe.line = line;
            pe.error = ext_err;
            error = col_add_binary_property(*error_list, NULL,
                                            WARNING_TXT, &pe, sizeof(pe));
            if (error) {
                TRACE_ERROR_NUMBER("Failed to add warning to collection", error);
                col_destroy_collection(current_section);
                if (created) {
                    col_destroy_collection(*error_list);
                    *error_list = NULL;
                }
                return error;
            }
            /* Exit if we are told to exit on warnings */
            if (error_level == INI_STOP_ON_ANY) {
                TRACE_ERROR_STRING("Invalid format of the file", "");
                if (created) col_destroy_collection(current_section);
                return EIO;
            }
            TRACE_ERROR_STRING("Invalid string", "");
            break;
        }
        ext_err = -1;
    }

    /* Note: File is not closed on this level any more.
     * It opened on the level above, checked and closed there.
     * It is not the responsibility of this function to close
     * file any more.
     */

    COL_DEBUG_COLLECTION(ini_config);

    col_destroy_collection(current_section);

    COL_DEBUG_COLLECTION(ini_config);

    TRACE_FLOW_STRING("ini_to_collection", "Success Exit");

    return EOK;
}

/*********************************************************************/
/* Function to free configuration */
void free_ini_config(struct collection_item *ini_config)
{
    TRACE_FLOW_STRING("free_ini_config", "Entry");
    col_destroy_collection(ini_config);
    TRACE_FLOW_STRING("free_ini_config", "Exit");
}

/* Function to free configuration error list */
void free_ini_config_errors(struct collection_item *error_set)
{
    TRACE_FLOW_STRING("free_ini_config_errors", "Entry");
    col_destroy_collection(error_set);
    TRACE_FLOW_STRING("free_ini_config_errors", "Exit");
}

#ifdef HAVE_VALIDATION

/* Function to free configuration lines list.
 *
 * The following doxygen description is moved here.
 * When the function gets exposed move it into
 * the header file.
 */
/**
 * @brief Function to free lines object.
 *
 * EXPERIMENTAL. Reserved for future use.
 *
 * @param[in] lines       Lines object.
 *
 */

void free_ini_config_lines(struct collection_item *lines)
{
    TRACE_FLOW_STRING("free_ini_config_lines", "Entry");
    col_destroy_collection(lines);
    TRACE_FLOW_STRING("free_ini_config_lines", "Exit");
}

#endif /* HAVE_VALIDATION */


/* Read configuration information from a file */
int config_from_file(const char *application,
                     const char *config_filename,
                     struct collection_item **ini_config,
                     int error_level,
                     struct collection_item **error_list)
{
    int error;

    TRACE_FLOW_STRING("config_from_file", "Entry");
    error = config_from_file_with_metadata(application,
                                           config_filename,
                                           ini_config,
                                           error_level,
                                           error_list,
                                           0,
                                           NULL);
    TRACE_FLOW_NUMBER("config_from_file. Returns", error);
    return error;
}

/* Read configuration information from a file descriptor */
int config_from_fd(const char *application,
                   int fd,
                   const char *config_source,
                   struct collection_item **ini_config,
                   int error_level,
                   struct collection_item **error_list)
{
    int error;

    TRACE_FLOW_STRING("config_from_fd", "Entry");
    error = config_from_fd_with_metadata(application,
                                         fd,
                                         config_source,
                                         ini_config,
                                         error_level,
                                         error_list,
                                         0,
                                         NULL);
    TRACE_FLOW_NUMBER("config_from_fd. Returns", error);
    return error;
}



/* Low level function that prepares the collection
 * and calls parser.
 */
static int config_with_metadata(const char *application,
                                FILE *config_file,
                                const char *config_source,
                                struct collection_item **ini_config,
                                int error_level,
                                struct collection_item **error_list,
                                uint32_t metaflags,
                                struct collection_item **metadata)
{
    int error;
    int created = 0;
    struct collection_item *lines = NULL;

#ifdef HAVE_VALIDATION
    int created_lines = 0;
#endif

    TRACE_FLOW_STRING("config_from_file", "Entry");

    /* Now we check arguments in the calling functions. */

    /* Create collection if needed */
    if (*ini_config == NULL) {
        error = col_create_collection(ini_config,
                                      application,
                                      COL_CLASS_INI_CONFIG);
        if (error != EOK) {
            TRACE_ERROR_NUMBER("Failed to create collection", error);
            return error;
        }
        created = 1;
    }
    /* Is the collection of the right class? */
    else if (((col_is_of_class(*ini_config, COL_CLASS_INI_CONFIG))== 0) &&
             ((col_is_of_class(*ini_config, COL_CLASS_INI_META))== 0)) {
        TRACE_ERROR_NUMBER("Wrong collection type", EINVAL);
        return EINVAL;
    }

#ifdef HAVE_VALIDATION
    /* This code is preserved for future use */
    error = col_create_collection(lines,
                                    application,
                                    COL_CLASS_INI_LINES);
    if (error != EOK) {
        TRACE_ERROR_NUMBER("Failed to create collection", error);
        if (created) {
            col_destroy_collection(*ini_config);
            *ini_config = NULL;
        }
        return error;
    }
    created_lines = 1;
#else
    /* Until we implement validation do not read the lines. */
    lines = NULL;
#endif /* HAVE_VALIDATION */

    /* Do the actual work - for now do not read lines.*/
    error = ini_to_collection(config_file, config_source,
                              *ini_config, error_level,
                              error_list, lines);
    /* In case of error when we created collection - delete it */
    if (error && created) {
        col_destroy_collection(*ini_config);
        *ini_config = NULL;
    }

    /* FIXME - put lines collection into the metadata */

    TRACE_FLOW_NUMBER("config_from_file. Returns", error);
    return error;
}

/* Function to read the ini file from fd
 * with meta data.
 */
int config_from_fd_with_metadata(const char *application,
                                 int ext_fd,
                                 const char *config_filename,
                                 struct collection_item **ini_config,
                                 int error_level,
                                 struct collection_item **error_list,
                                 uint32_t metaflags,
                                 struct collection_item **metadata)
{
    int error = EOK;
    int file_error = EOK;
    int save_error = 0;
    int fd = -1;
    FILE *config_file = NULL;
    char abs_name[PATH_MAX + 1];
    char buff[CONVERSION_BUFFER];

    TRACE_FLOW_STRING("config_from_fd_with_metadata", "Entry");

    /* We need to check arguments before we can move on,
     * and start allocating memory.
     */
    if ((ini_config == NULL) ||
        (application == NULL)) {
        TRACE_ERROR_NUMBER("Invalid argument", EINVAL);
        return EINVAL;
    }

    /* Prepare meta data */
    error = prepare_metadata(metaflags, metadata, &save_error);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to prepare metadata", error);
        return error;
    }

    errno = 0;

    if (ext_fd == -1) {
        /* No file descriptor so use name */
        config_file = fopen(config_filename, "r");
    }
    else {
        /* Create a copy of the descriptor so that we can close it if needed */
        fd = dup(ext_fd);
        if (fd != -1) config_file = fdopen(fd, "r");
    }
    file_error = errno;

    if (save_error) {
        /* Record the result of the open file operation in metadata */
        snprintf(buff, CONVERSION_BUFFER, "%d", file_error);
        error = col_add_str_property(*metadata,
                                     INI_META_SEC_ERROR,
                                     INI_META_KEY_READ_ERROR,
                                     buff,
                                     0);
        if (error) {
            /* Something is really wrong if we failed here */
            TRACE_ERROR_NUMBER("Failed to save file open error", error);
            if (config_file) fclose(config_file);
            return error;
        }
    }

    if(!config_file) {
        TRACE_ERROR_NUMBER("Failed to open file", file_error);
        return file_error;
    }

    /* Normalize path for reporting purposes */
    error = make_normalized_absolute_path(abs_name,
                                          PATH_MAX,
                                          config_filename);
    if(error) {
        TRACE_ERROR_NUMBER("Failed to resolve path", error);
        fclose(config_file);
        return error;
    }


    if (metadata) {
        /* Collect meta data before actually parsing the file */
        error = collect_metadata(metaflags,
                                 metadata,
                                 config_file,
                                 abs_name);
        if(error) {
            TRACE_ERROR_NUMBER("Failed to collect metadata", error);
            fclose(config_file);
            return error;
        }
    }

    if (!(metaflags & INI_META_ACTION_NOPARSE)) {
        /* Parse data if needed */
        error = config_with_metadata(application,
                                     config_file,
                                     abs_name,
                                     ini_config,
                                     error_level,
                                     error_list,
                                     metaflags,
                                     metadata);
    }

    /* We opened the file we close it */
    fclose(config_file);

    TRACE_FLOW_NUMBER("config_from_fd_with_metadata. Returns", error);
    return error;
}

/* Function to read the ini file with metadata
 * using file name.
 */
int config_from_file_with_metadata(const char *application,
                                   const char *config_filename,
                                   struct collection_item **ini_config,
                                   int error_level,
                                   struct collection_item **error_list,
                                   uint32_t metaflags,
                                   struct collection_item **metadata)
{
    int error = EOK;
    TRACE_FLOW_STRING("config_from_file_with_metadata", "Entry");

    error = config_from_fd_with_metadata(application,
                                         -1,
                                         config_filename,
                                         ini_config,
                                         error_level,
                                         error_list,
                                         metaflags,
                                         metadata);

    TRACE_FLOW_STRING("config_from_file_with_metadata", "Exit");
    return error;
}


/* Read default config file and then overwrite it with a specific one
 * from the directory */
int config_for_app_with_metadata(const char *application,
                                 const char *config_file,
                                 const char *config_dir,
                                 struct collection_item **ini_config,
                                 int error_level,
                                 struct collection_item **error_set,
                                 uint32_t metaflags,
                                 struct collection_item **meta_default,
                                 struct collection_item **meta_appini)
{
    int error = EOK;
    char *file_name;
    struct collection_item *error_list_common = NULL;
    struct collection_item *error_list_specific = NULL;
    struct collection_item **pass_common = NULL;
    struct collection_item **pass_specific = NULL;
    int created = 0;
    int tried = 0;
    int noents = 0;

    TRACE_FLOW_STRING("config_for_app", "Entry");

    if (ini_config == NULL) {
        TRACE_ERROR_NUMBER("Invalid parameter", EINVAL);
        return EINVAL;
    }

    if ((config_file == NULL) && (config_dir == NULL)) {
        TRACE_ERROR_NUMBER("Noop call of the function is invalid", EINVAL);
        return EINVAL;
    }

    /* Prepare error collection pointers */
    if (error_set != NULL) {
        TRACE_INFO_STRING("Error set is not NULL", "preparing error set");
        pass_common = &error_list_common;
        pass_specific = &error_list_specific;
        *error_set = NULL;
        /* Construct the overarching error collection */
        error = col_create_collection(error_set,
                                      FILE_ERROR_SET,
                                      COL_CLASS_INI_PESET);
        if (error != EOK) {
            TRACE_ERROR_NUMBER("Failed to create collection", error);
            return error;
        }
    }
    else {
        TRACE_INFO_STRING("No error set. Errors will not be captured", "");
        pass_common = NULL;
        pass_specific = NULL;
    }

    /* Create collection if needed */
    if (*ini_config == NULL) {
        TRACE_INFO_STRING("New config collection. Allocate.", "");
        error = col_create_collection(ini_config,
                                      application,
                                      COL_CLASS_INI_CONFIG);
        if (error != EOK) {
            TRACE_ERROR_NUMBER("Failed to create collection", error);
            if (error_set) {
                col_destroy_collection(*error_set);
                *error_set = NULL;
            }
            return error;
        }
        created = 1;
    }
    /* Is the collection of the right class? */
    else if ((col_is_of_class(*ini_config, COL_CLASS_INI_CONFIG) == 0) &&
             (col_is_of_class(*ini_config, COL_CLASS_INI_META) == 0)) {
        TRACE_ERROR_NUMBER("Wrong collection type", EINVAL);
        return EINVAL;
    }

    /* Read master file */
    if (config_file != NULL) {
        TRACE_INFO_STRING("Reading master file:", config_file);
        /* Get configuration information from the file */
        error = config_from_file_with_metadata(application,
                                               config_file,
                                               ini_config,
                                               error_level,
                                               pass_common,
                                               metaflags,
                                               meta_default);
        tried++;
        /* ENOENT and EOK are Ok */
        if (error) {
            if (error != ENOENT) {
                TRACE_ERROR_NUMBER("Failed to read master file", error);
                /* In case of error when we created collection - delete it */
                if(error && created) {
                    col_destroy_collection(*ini_config);
                    *ini_config = NULL;
                }
                /* We do not clear the error_set here */
                return error;
            }
            else noents++;
        }
        /* Add error results if any to the overarching error collection */
        if ((pass_common != NULL) && (*pass_common != NULL)) {
            TRACE_INFO_STRING("Process errors resulting from file:", config_file);
            error = col_add_collection_to_collection(*error_set, NULL, NULL,
                                                     *pass_common,
                                                     COL_ADD_MODE_EMBED);
            if (error) {
                if (created) {
                    col_destroy_collection(*ini_config);
                    *ini_config = NULL;
                }
                if (error_set) {
                    col_destroy_collection(*error_set);
                    *error_set = NULL;
                }
                TRACE_ERROR_NUMBER("Failed to add error collection to another error collection", error);
                return error;
            }
        }
    }

    if (config_dir != NULL) {
        /* Get specific application file */
        file_name = malloc(strlen(config_dir) + strlen(application) + NAME_OVERHEAD);
        if (file_name == NULL) {
            error = ENOMEM;
            TRACE_ERROR_NUMBER("Failed to allocate memory for file name", error);
            /* In case of error when we created collection - delete it */
            if(created) {
                col_destroy_collection(*ini_config);
                *ini_config = NULL;
            }
            if (error_set) {
                col_destroy_collection(*error_set);
                *error_set = NULL;
            }
            return error;
        }

        sprintf(file_name, "%s%s%s.conf", config_dir, SLASH, application);
        TRACE_INFO_STRING("Opening file:", file_name);
        /* Read specific file */
        error = config_from_file_with_metadata(application,
                                               file_name,
                                               ini_config,
                                               error_level,
                                               pass_specific,
                                               metaflags,
                                               meta_appini);
        tried++;
        free(file_name);
        /* ENOENT and EOK are Ok */
        if (error) {
            if (error != ENOENT) {
                TRACE_ERROR_NUMBER("Failed to read specific application file", error);
                /* In case of error when we created collection - delete it */
                if (error && created) {
                    col_destroy_collection(*ini_config);
                    *ini_config = NULL;
                }
                /* We do not clear the error_set here */
                return error;
            }
            else noents++;
        }
        /* Add error results if any to the overarching error collection */
        if ((pass_specific != NULL) && (*pass_specific != NULL)) {
            error = col_add_collection_to_collection(*error_set, NULL, NULL,
                                                     *pass_specific,
                                                     COL_ADD_MODE_EMBED);
            if (error) {
                if (created) {
                    col_destroy_collection(*ini_config);
                    *ini_config = NULL;
                }
                if (error_set) {
                    col_destroy_collection(*error_set);
                    *error_set = NULL;
                }
                TRACE_ERROR_NUMBER("Failed to add error collection to another error collection", error);
                return error;
            }
        }
    }

    /* If we failed to read or access file as many
     * times as we tried and we told to stop on any errors
     * we should report an error.
     */
    TRACE_INFO_NUMBER("Tried:", tried);
    TRACE_INFO_NUMBER("Noents:", noents);

    if ((tried == noents) && (error_level == INI_STOP_ON_ANY)) {
        TRACE_ERROR_NUMBER("Fail to read or access all the files tried", ENOENT);
        if (created) {
            col_destroy_collection(*ini_config);
            *ini_config = NULL;
        }
        if (error_set) {
            col_destroy_collection(*error_set);
            *error_set = NULL;
        }
        return ENOENT;
    }

    TRACE_FLOW_STRING("config_to_collection", "Exit");
    return EOK;
}


/* Function to return configuration data
 * for the application without meta data.
 */
int config_for_app(const char *application,
                   const char *config_file,
                   const char *config_dir,
                   struct collection_item **ini_config,
                   int error_level,
                   struct collection_item **error_set)
{
    int error = EOK;
    TRACE_FLOW_STRING("config_for_app", "Entry");

    error = config_for_app_with_metadata(application,
                                         config_file,
                                         config_dir,
                                         ini_config,
                                         error_level,
                                         error_set,
                                         0,
                                         NULL,
                                         NULL);

    TRACE_FLOW_NUMBER("config_for_app. Returning", error);
    return error;
}
