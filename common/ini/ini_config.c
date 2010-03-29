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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <locale.h>
#include <fcntl.h>
#include <unistd.h>
#include "config.h"
/* For error text */
#include <libintl.h>
#define _(String) gettext (String)
/* INI file is used as a collection */
#include "collection.h"
#include "collection_tools.h"
#include "trace.h"
#include "ini_config.h"
#include "ini_metadata.h"

#define NAME_OVERHEAD   10

#define SLASH           "/"

#define EXCLUDE_EMPTY   0
#define INCLUDE_EMPTY   1

/* Name of the special collection used to store parsing errors */
#define FILE_ERROR_SET  "ini_file_error_set"

/* Text error strings used when errors are printed out */
#define WARNING_TXT         _("Warning")
#define ERROR_TXT           _("Error")
/* For parse errors */
#define WRONG_COLLECTION    _("Passed in list is not a list of parse errors.\n")
#define FAILED_TO_PROCCESS  _("Internal Error. Failed to process error list.\n")
#define ERROR_HEADER        _("Parsing errors and warnings in file: %s\n")
/* For grammar errors */
#define WRONG_GRAMMAR       _("Passed in list is not a list of grammar errors.\n")
#define FAILED_TO_PROC_G    _("Internal Error. Failed to process list of grammar errors.\n")
#define ERROR_HEADER_G      _("Logical errors and warnings in file: %s\n")
/* For validation errors */
#define WRONG_VALIDATION    _("Passed in list is not a list of validation errors.\n")
#define FAILED_TO_PROC_V    _("Internal Error. Failed to process list of validation errors.\n")
#define ERROR_HEADER_V      _("Validation errors and warnings in file: %s\n")

#define LINE_FORMAT         _("%s (%d) on line %d: %s\n")


/* Codes that parsing function can return */
#define RET_PAIR        0
#define RET_COMMENT     1
#define RET_SECTION     2
#define RET_INVALID     3
#define RET_EMPTY       4
#define RET_EOF         5
#define RET_ERROR       6

#define INI_ERROR       "errors"
#define INI_ERROR_NAME  "errname"

/* Internal sizes. MAX_KEY is defined in config.h */
#define MAX_VALUE       PATH_MAX
#define BUFFER_SIZE     MAX_KEY + MAX_VALUE + 3


/*============================================================*/
/* The following classes moved here from the public header
 * They are reserved for future use.
 *
 * NOTE: before exposing these constants again in the common header
 * check that the class IDs did not get reused over time by
 * other classes.
 */
/** @brief Collection of grammar errors.
 *
 * Reserved for future use.
 */
#define COL_CLASS_INI_GERROR      COL_CLASS_INI_BASE + 5
/** @brief Collection of validation errors.
 *
 * Reserved for future use.
 */
#define COL_CLASS_INI_VERROR      COL_CLASS_INI_BASE + 6

#ifdef HAVE_VALIDATION

/** @brief Collection of lines from the INI file.
 *
 * Reserved for future use
 */
#define COL_CLASS_INI_LINES       COL_CLASS_INI_BASE + 7

#endif /* HAVE_VALIDATION */
/*============================================================*/


/* Different error string functions can be passed as callbacks */
typedef const char * (*error_fn)(int error);

/* Function to return parsing error */
const char *parsing_error_str(int parsing_error)
{
    const char *placeholder= _("Unknown pasing error.");
    const char *str_error[] = { _("Data is too long."),
                                _("No closing bracket."),
                                _("Section name is missing."),
                                _("Section name is too long."),
                                _("Equal sign is missing."),
                                _("Property name is missing."),
                                _("Property name is too long.")
    };

    /* Check the range */
    if ((parsing_error < 1) || (parsing_error > ERR_MAXPARSE))
            return placeholder;
    else
            return str_error[parsing_error-1];
}

/* Function to return grammar error.
 * This function is currently not used.
 * It is planned to be used by the INI
 * file grammar parser.
 *
 * The following doxygen description is moved here.
 * When the function gets exposed move it into
 * the header file.
 */
/** @brief Function to return a grammar error in template.
 *
 * EXPERIMENTAL. Reserved for future use.
 *
 * This error is returned when the template
 * is translated into the grammar object.
 *
 * @param[in] parsing_error    Error code for the grammar error.
 *
 * @return Error string.
 */

const char *grammar_error_str(int grammar_error)
{
    const char *placeholder= _("Unknown grammar error.");
    /* THIS IS A TEMPORARY PLACEHOLDER !!!! */
    const char *str_error[] = { _(""),
                                _(""),
                                _(""),
                                _(""),
                                _(""),
                                _(""),
                                _("")
    };

    /* Check the range */
    if ((grammar_error < 1) || (grammar_error > ERR_MAXGRAMMAR))
            return placeholder;
    else
            return str_error[grammar_error-1];
}

/* Function to return validation error.
 * This function is currently not used.
 * It is planned to be used by the INI
 * file grammar validator.
 *
 * The following doxygen description is moved here.
 * When the function gets exposed move it into
 * the header file.
 */
/** @brief Function to return a validation error.
 *
 * EXPERIMENTAL. Reserved for future use.
 *
 * This is the error that it is returned when
 * the INI file is validated against the
 * grammar object.
 *
 * @param[in] parsing_error    Error code for the validation error.
 *
 * @return Error string.
 */
const char *validation_error_str(int validation_error)
{
    const char *placeholder= _("Unknown validation error.");
    /* THIS IS A TEMPORARY PLACEHOLDER !!!! */
    const char *str_error[] = { _(""),
                                _(""),
                                _(""),
                                _(""),
                                _(""),
                                _(""),
                                _("")
    };

    /* Check the range */
    if ((validation_error < 1) || (validation_error > ERR_MAXVALID))
            return placeholder;
    else
            return str_error[validation_error-1];
}


/* Internal function to read line from INI file */
int read_line(FILE *file,
              char *buf,
              int read_size,
              char **key,
              char **value,
              int *length,
              int *ext_error);

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
                                struct collection_item *metadata)
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
        error = col_add_int_property(*metadata,
                                     INI_META_SEC_ERROR,
                                     INI_META_KEY_READ_ERROR,
                                     file_error);
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

    /* Collect meta data before actually parsing the file */
    error = collect_metadata(metaflags, metadata, config_file);
    if(error) {
        TRACE_ERROR_NUMBER("Failed to collect metadata", error);
        return error;
    }

    if (!(metaflags & INI_META_ACTION_NOPARSE)) {
        /* Parse data if needed */
        error = config_with_metadata(application,
                                     config_file,
                                     config_filename,
                                     ini_config,
                                     error_level,
                                     error_list,
                                     metaflags,
                                     *metadata);
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



/* Reads a line from the file */
int read_line(FILE *file,
              char *buf,
              int read_size,
              char **key, char **value,
              int *length,
              int *ext_error)
{

    char *res;
    int len;
    char *buffer;
    int i;
    char *eq;

    TRACE_FLOW_STRING("read_line", "Entry");

    *ext_error = 0;

    buffer = buf;

    /* Get data from file */
    res = fgets(buffer, read_size - 1, file);
    if (res == NULL) {
        TRACE_ERROR_STRING("Read nothing", "");
        return RET_EOF;
    }

    /* Make sure the buffer is NULL terminated */
    buffer[read_size - 1] = '\0';

    len = strlen(buffer);
    if (len == 0) {
        TRACE_ERROR_STRING("Nothing was read.", "");
        return RET_EMPTY;
    }

    /* Added \r just in case we deal with Windows in future */
    if ((buffer[len - 1] != '\n') && (buffer[len - 1] != '\r')) {
        TRACE_ERROR_STRING("String it too big!", "");
        *ext_error = ERR_LONGDATA;
        return RET_ERROR;
    }

    /* Ingnore comments */
    if ((*buffer == ';') || (*buffer == '#')) {
        TRACE_FLOW_STRING("Comment", buf);
        return RET_COMMENT;
    }

    TRACE_INFO_STRING("BUFFER before trimming:", buffer);

    /* Trucate trailing spaces and CRs */
    /* Make sure not to step before the beginning */
    while (len && isspace(buffer[len - 1])) {
        buffer[len - 1] = '\0';
        len--;
    }

    TRACE_INFO_STRING("BUFFER after trimming trailing spaces:", buffer);

    /* Trucate leading spaces  */
    while (isspace(*buffer)) {
        buffer++;
        len--;
    }

    TRACE_INFO_STRING("BUFFER after trimming leading spaces:", buffer);
    TRACE_INFO_NUMBER("BUFFER length:", len);

    /* Empty line */
    if (len == 0) {
        TRACE_FLOW_STRING("Empty line", buf);
        return RET_EMPTY;
    }

    /* Section */
    if (*buffer == '[') {
        if (buffer[len-1] != ']') {
            TRACE_ERROR_STRING("Invalid format for section", buf);
            *ext_error = ERR_NOCLOSESEC;
            return RET_ERROR;
        }
        buffer++;
        len--;
        while (isspace(*buffer)) {
            buffer++;
            len--;
        }
        if (len == 0) {
            TRACE_ERROR_STRING("Invalid format for section", buf);
            *ext_error = ERR_NOSECTION;
            return RET_ERROR;
        }

        buffer[len - 1] = '\0';
        len--;
        while (isspace(buffer[len - 1])) {
            buffer[len - 1] = '\0';
            len--;
        }
        if (len >= MAX_KEY) {
            TRACE_ERROR_STRING("Section name is too long", buf);
            *ext_error = ERR_SECTIONLONG;
            return RET_ERROR;
        }

        *key = buffer;
        return RET_SECTION;
    }

    /* Assume we are dealing with the K-V here */
    /* Find "=" */
    eq = strchr(buffer, '=');
    if (eq == NULL) {
        TRACE_ERROR_STRING("No equal sign", buf);
        *ext_error = ERR_NOEQUAL;
        return RET_INVALID;
    }

    len -= eq-buffer;

    /* Strip spaces around "=" */
    i = eq - buffer - 1;
    while ((i >= 0) && isspace(buffer[i])) i--;
    if (i < 0) {
        TRACE_ERROR_STRING("No key", buf);
        *ext_error = ERR_NOKEY;
        return RET_INVALID;
    }

    /* Copy key into provided buffer */
    if(i >= MAX_KEY) {
        TRACE_ERROR_STRING("Section name is too long", buf);
        *ext_error = ERR_LONGKEY;
        return RET_INVALID;
    }
    *key = buffer;
    buffer[i + 1] = '\0';
    TRACE_INFO_STRING("KEY:", *key);

    eq++;
    len--;
    while (isspace(*eq)) {
        eq++;
        len--;
    }

    *value = eq;
    /* Make sure we include trailing 0 into data */
    *length = len + 1;

    TRACE_INFO_STRING("VALUE:", *value);
    TRACE_INFO_NUMBER("LENGTH:", *length);

    TRACE_FLOW_STRING("read_line", "Exit");
    return RET_PAIR;
}



/* Internal function that prints errors */
static void print_error_list(FILE *file,
                             struct collection_item *error_list,
                             int cclass,
                             char *wrong_col_error,
                             char *failed_to_process,
                             char *error_header,
                             char *line_format,
                             error_fn error_function)
{
    struct collection_iterator *iterator;
    int error;
    struct collection_item *item = NULL;
    struct parse_error *pe;
    unsigned int count;

    TRACE_FLOW_STRING("print_error_list", "Entry");

    /* If we have something to print print it */
    if (error_list == NULL) {
        TRACE_ERROR_STRING("No error list","");
        return;
    }

    /* Make sure we go the right collection */
    if (!col_is_of_class(error_list, cclass)) {
        TRACE_ERROR_STRING("Wrong collection class:", wrong_col_error);
        fprintf(file,"%s\n", wrong_col_error);
        return;
    }

    /* Bind iterator */
    error =  col_bind_iterator(&iterator, error_list, COL_TRAVERSE_DEFAULT);
    if (error) {
        TRACE_ERROR_STRING("Error (bind):", failed_to_process);
        fprintf(file, "%s\n", failed_to_process);
        return;
    }

    while(1) {
        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            TRACE_ERROR_STRING("Error (iterate):", failed_to_process);
            fprintf(file, "%s\n", failed_to_process);
            col_unbind_iterator(iterator);
            return;
        }

        /* Are we done ? */
        if (item == NULL) break;

        /* Process collection header */
        if (col_get_item_type(item) == COL_TYPE_COLLECTION) {
            col_get_collection_count(item, &count);
            if (count <= 2) break;
        } else if (col_get_item_type(item) == COL_TYPE_STRING) {
            fprintf(file, error_header, (char *)col_get_item_data(item));
        }
        else {
            /* Put error into provided format */
            pe = (struct parse_error *)(col_get_item_data(item));
            fprintf(file, line_format,
                    col_get_item_property(item, NULL),      /* Error or warning */
                    pe->error,                          /* Error */
                    pe->line,                           /* Line */
                    error_function(pe->error));         /* Error str */
        }

    }

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    col_unbind_iterator(iterator);

    TRACE_FLOW_STRING("print_error_list", "Exit");
}

/* Print errors and warnings that were detected while parsing one file */
void print_file_parsing_errors(FILE *file,
                               struct collection_item *error_list)
{
    print_error_list(file,
                     error_list,
                     COL_CLASS_INI_PERROR,
                     WRONG_COLLECTION,
                     FAILED_TO_PROCCESS,
                     ERROR_HEADER,
                     LINE_FORMAT,
                     parsing_error_str);
}


/* Print errors and warnings that were detected while processing grammar.
 *
 * The following doxygen description is moved here.
 * When the function gets exposed move it into
 * the header file.
 */
/**
 * @brief Print errors and warnings that were detected while
 * checking grammar of the template.
 *
 * EXPERIMENTAL. Reserved for future use.
 *
 * @param[in] file           File descriptor.
 * @param[in] error_list     List of the parsing errors.
 *
 */
void print_grammar_errors(FILE *file,
                          struct collection_item *error_list)
{
    print_error_list(file,
                     error_list,
                     COL_CLASS_INI_GERROR,
                     WRONG_GRAMMAR,
                     FAILED_TO_PROC_G,
                     ERROR_HEADER_G,
                     LINE_FORMAT,
                     grammar_error_str);
}

/* Print errors and warnings that were detected while validating INI file.
 *
 * The following doxygen description is moved here.
 * When the function gets exposed move it into
 * the header file.
 */
/**
 * @brief Print errors and warnings that were detected while
 * checking INI file against the grammar object.
 *
 * EXPERIMENTAL. Reserved for future use.
 *
 * @param[in] file           File descriptor.
 * @param[in] error_list     List of the parsing errors.
 *
 */
void print_validation_errors(FILE *file,
                             struct collection_item *error_list)
{
    print_error_list(file,
                     error_list,
                     COL_CLASS_INI_VERROR,
                     WRONG_VALIDATION,
                     FAILED_TO_PROC_V,
                     ERROR_HEADER_V,
                     LINE_FORMAT,
                     validation_error_str);
}

/* Print errors and warnings that were detected while parsing
 * the whole configuration */
void print_config_parsing_errors(FILE *file,
                                 struct collection_item *error_list)
{
    struct collection_iterator *iterator;
    int error;
    struct collection_item *item = NULL;
    struct collection_item *file_errors = NULL;

    TRACE_FLOW_STRING("print_config_parsing_errors", "Entry");

    /* If we have something to print print it */
    if (error_list == NULL) {
        TRACE_ERROR_STRING("No error list", "");
        return;
    }

    /* Make sure we go the right collection */
    if (!col_is_of_class(error_list, COL_CLASS_INI_PESET)) {
        TRACE_ERROR_STRING("Wrong collection class:", WRONG_COLLECTION);
        fprintf(file, "%s\n", WRONG_COLLECTION);
        return;
    }

    /* Bind iterator */
    error =  col_bind_iterator(&iterator, error_list, COL_TRAVERSE_DEFAULT);
    if (error) {
        TRACE_ERROR_STRING("Error (bind):", FAILED_TO_PROCCESS);
        fprintf(file,"%s\n", FAILED_TO_PROCCESS);
        return;
    }

    while(1) {
        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            TRACE_ERROR_STRING("Error (iterate):", FAILED_TO_PROCCESS);
            fprintf(file, "%s\n", FAILED_TO_PROCCESS);
            col_unbind_iterator(iterator);
            return;
        }

        /* Are we done ? */
        if (item == NULL) break;

        /* Print per file sets of errors */
        if (col_get_item_type(item) == COL_TYPE_COLLECTIONREF) {
            /* Extract a sub collection */
            error = col_get_reference_from_item(item, &file_errors);
            if (error) {
                TRACE_ERROR_STRING("Error (extract):", FAILED_TO_PROCCESS);
                fprintf(file, "%s\n", FAILED_TO_PROCCESS);
                col_unbind_iterator(iterator);
                return;
            }
            print_file_parsing_errors(file, file_errors);
            col_destroy_collection(file_errors);
        }
    }

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    col_unbind_iterator(iterator);

    TRACE_FLOW_STRING("print_config_parsing_errors", "Exit");
}


/* Function to get value from the configration handle */
int get_config_item(const char *section,
                    const char *name,
                    struct collection_item *ini_config,
                    struct collection_item **item)
{
    int error = EOK;
    struct collection_item *section_handle = NULL;
    const char *to_find;
    char default_section[] = INI_DEFAULT_SECTION;

    TRACE_FLOW_STRING("get_config_item", "Entry");

    /* Do we have the accepting memory ? */
    if (item == NULL) {
        TRACE_ERROR_NUMBER("No buffer - invalid argument.", EINVAL);
        return EINVAL;
    }

    /* Is the collection of a right type */
    if ((col_is_of_class(ini_config, COL_CLASS_INI_CONFIG) == 0) &&
        (col_is_of_class(ini_config, COL_CLASS_INI_META) == 0)) {
        TRACE_ERROR_NUMBER("Wrong collection type", EINVAL);
        return EINVAL;
    }

    *item = NULL;

    if (section == NULL) to_find = default_section;
    else to_find = section;

    TRACE_INFO_STRING("Getting Name:", name);
    TRACE_INFO_STRING("In Section:", section);

    /* Get Subcollection */
    error = col_get_collection_reference(ini_config, &section_handle, to_find);
    /* Check error */
    if (error && (error != ENOENT)) {
        TRACE_ERROR_NUMBER("Failed to get section", error);
        return error;
    }

    /* Did we find a section */
    if ((error == ENOENT) || (section_handle == NULL)) {
        /* We have not found section - return success */
        TRACE_FLOW_STRING("get_value_from_config", "No such section");
        return EOK;
    }

    /* Get item */
    error = col_get_item(section_handle, name,
                         COL_TYPE_STRING, COL_TRAVERSE_ONELEVEL, item);

    /* Make sure we free the section we found */
    col_destroy_collection(section_handle);

    TRACE_FLOW_NUMBER("get_config_item returning", error);
    return error;
}

/* Get long long value from config item */
static long long get_llong_config_value(struct collection_item *item,
                                        int strict,
                                        long long def,
                                        int *error)
{
    int err;
    const char *str;
    char *endptr;
    long long val = 0;

    TRACE_FLOW_STRING("get_long_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
       (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return def;
    }

    if (error) *error = EOK;

    /* Try to parse the value */
    str = (const char *)col_get_item_data(item);
    errno = 0;
    val = strtoll(str, &endptr, 10);
    err = errno;

    /* Check for various possible errors */
    if (err != 0) {
        TRACE_ERROR_NUMBER("Conversion failed", err);
        if (error) *error = err;
        return def;
    }

    /* Other error cases */
    if ((endptr == str) || (strict && (*endptr != '\0'))) {
        TRACE_ERROR_NUMBER("More characters or nothing processed", EIO);
        if (error) *error = EIO;
        return def;
    }

    TRACE_FLOW_NUMBER("get_long_config_value returning", (long)val);
    return val;
}

/* Get unsigned long long value from config item */
static unsigned long long get_ullong_config_value(struct collection_item *item,
                                                  int strict,
                                                  unsigned long long def,
                                                  int *error)
{
    int err;
    const char *str;
    char *endptr;
    unsigned long long val = 0;

    TRACE_FLOW_STRING("get_long_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
       (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return def;
    }

    if (error) *error = EOK;

    /* Try to parse the value */
    str = (const char *)col_get_item_data(item);
    errno = 0;
    val = strtoull(str, &endptr, 10);
    err = errno;

    /* Check for various possible errors */
    if (err != 0) {
        TRACE_ERROR_NUMBER("Conversion failed", err);
        if (error) *error = err;
        return def;
    }

    /* Other error cases */
    if ((endptr == str) || (strict && (*endptr != '\0'))) {
        TRACE_ERROR_NUMBER("More characters or nothing processed", EIO);
        if (error) *error = EIO;
        return def;
    }

    TRACE_FLOW_NUMBER("get_long_config_value returning", (long)val);
    return val;
}


/* Get integer value from config item */
int get_int_config_value(struct collection_item *item,
                         int strict,
                         int def,
                         int *error)
{
    long long val = 0;
    int err = 0;

    TRACE_FLOW_STRING("get_int_config_value", "Entry");

    val = get_llong_config_value(item, strict, def, &err);
    if (err == 0) {
        if ((val > INT_MAX) || (val < INT_MIN)) {
            val = def;
            err = ERANGE;
        }
    }

    if (error) *error = err;

    TRACE_FLOW_NUMBER("get_int_config_value returning", (int)val);
    return (int)val;
}

/* Get unsigned integer value from config item */
unsigned get_unsigned_config_value(struct collection_item *item,
                                   int strict,
                                   unsigned def,
                                   int *error)
{
    unsigned long long val = 0;
    int err = 0;

    TRACE_FLOW_STRING("get_unsigned_config_value", "Entry");

    val = get_ullong_config_value(item, strict, def, &err);
    if (err == 0) {
        if (val > UINT_MAX) {
            val = def;
            err = ERANGE;
        }
    }

    if (error) *error = err;

    TRACE_FLOW_NUMBER("get_unsigned_config_value returning",
                      (unsigned)val);
    return (unsigned)val;
}

/* Get long value from config item */
long get_long_config_value(struct collection_item *item,
                           int strict,
                           long def,
                           int *error)
{
    long long val = 0;
    int err = 0;

    TRACE_FLOW_STRING("get_long_config_value", "Entry");

    val = get_llong_config_value(item, strict, def, &err);
    if (err == 0) {
        if ((val > LONG_MAX) || (val < LONG_MIN)) {
            val = def;
            err = ERANGE;
        }
    }

    if (error) *error = err;

    TRACE_FLOW_NUMBER("get_long_config_value returning",
                      (long)val);
    return (long)val;
}

/* Get unsigned long value from config item */
unsigned long get_ulong_config_value(struct collection_item *item,
                                     int strict,
                                     unsigned long def,
                                     int *error)
{
    unsigned long long val = 0;
    int err = 0;

    TRACE_FLOW_STRING("get_ulong_config_value", "Entry");

    val = get_ullong_config_value(item, strict, def, &err);
    if (err == 0) {
        if (val > ULONG_MAX) {
            val = def;
            err = ERANGE;
        }
    }

    if (error) *error = err;

    TRACE_FLOW_NUMBER("get_ulong_config_value returning",
                      (unsigned long)val);
    return (unsigned long)val;
}


/* Get double value */
double get_double_config_value(struct collection_item *item,
                               int strict, double def, int *error)
{
    const char *str;
    char *endptr;
    double val = 0;

    TRACE_FLOW_STRING("get_double_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return def;
    }

    if (error) *error = EOK;

    /* Try to parse the value */
    str = (const char *)col_get_item_data(item);
    errno = 0;
    val = strtod(str, &endptr);

    /* Check for various possible errors */
    if ((errno == ERANGE) ||
        ((errno != 0) && (val == 0)) ||
        (endptr == str)) {
        TRACE_ERROR_NUMBER("Conversion failed", EIO);
        if (error) *error = EIO;
        return def;
    }

    if (strict && (*endptr != '\0')) {
        TRACE_ERROR_NUMBER("More characters than expected", EIO);
        if (error) *error = EIO;
        val = def;
    }

    TRACE_FLOW_NUMBER("get_double_config_value returning", val);
    return val;
}

/* Get boolean value */
unsigned char get_bool_config_value(struct collection_item *item,
                                    unsigned char def, int *error)
{
    const char *str;
    int len;

    TRACE_FLOW_STRING("get_bool_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return def;
    }

    if (error) *error = EOK;

    str = (const char *)col_get_item_data(item);
    len = col_get_item_length(item);

    /* Try to parse the value */
    if ((strncasecmp(str, "true", len) == 0) ||
        (strncasecmp(str, "yes", len) == 0)) {
        TRACE_FLOW_STRING("Returning", "true");
        return '\1';
    }
    else if ((strncasecmp(str, "false", len) == 0) ||
             (strncasecmp(str, "no", len) == 0)) {
        TRACE_FLOW_STRING("Returning", "false");
        return '\0';
    }

    TRACE_ERROR_STRING("Returning", "error");
    if (error) *error = EIO;
    return def;
}

/* Return a string out of the value */
char *get_string_config_value(struct collection_item *item,
                              int *error)
{
    char *str = NULL;

    TRACE_FLOW_STRING("get_string_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    str = strdup((const char *)col_get_item_data(item));
    if (str == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate memory.", ENOMEM);
        if (error) *error = ENOMEM;
        return NULL;
    }

    if (error) *error = EOK;

    TRACE_FLOW_STRING("get_string_config_value returning", str);
    return str;
}

/* Get string from item */
const char *get_const_string_config_value(struct collection_item *item, int *error)
{
    const char *str;

    TRACE_FLOW_STRING("get_const_string_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    str = (const char *)col_get_item_data(item);

    if (error) *error = EOK;

    TRACE_FLOW_STRING("get_const_string_config_value returning", str);
    return str;
}

/* A special hex format is assumed.
 * The string should be taken in single quotes
 * and consist of hex encoded value two hex digits per byte.
 * Example: '0A2BFECC'
 * Case does not matter.
 */
char *get_bin_config_value(struct collection_item *item,
                           int *length, int *error)
{
    int i;
    char *value = NULL;
    const char *buff;
    int size = 0;
    unsigned char hex;
    int len;
    const char *str;

    TRACE_FLOW_STRING("get_bin_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    /* Check the length */
    len = col_get_item_length(item)-1;
    if ((len%2) != 0) {
        TRACE_ERROR_STRING("Invalid length for binary data", "");
        if (error) *error = EINVAL;
        return NULL;
    }

    str = (const char *)col_get_item_data(item);

    /* Is the format correct ? */
    if ((*str != '\'') ||
        (str[len -1] != '\'')) {
        TRACE_ERROR_STRING("String is not escaped","");
        if (error) *error = EIO;
        return NULL;
    }

    /* Check that all the symbols are ok */
    buff = str + 1;
    len -= 2;
    for (i = 0; i < len; i += 2) {
        if (!isxdigit(buff[i]) || !isxdigit(buff[i + 1])) {
            TRACE_ERROR_STRING("Invalid encoding for binary data", buff + i);
            if (error) *error = EIO;
            return NULL;
        }
    }

    /* The value is good so we can allocate memory for it */
    value = malloc(len / 2);
    if (value == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate memory.", ENOMEM);
        if (error) *error = ENOMEM;
        return NULL;
    }

    /* Convert the value */
    for (i = 0; i < len; i += 2) {
        if (isdigit(buff[i])) {
            if (isdigit(buff[i+1]))
                hex = 16 * (buff[i] - '0') + (buff[i+1] - '0');
            else
                hex = 16 * (buff[i] - '0') + (tolower(buff[i+1]) - 'a' + 10);
        }
        else {
            if (isdigit(buff[i+1]))
                hex = 16 * (tolower(buff[i]) - 'a') + (buff[i+1] - '0');
            else
                hex = 16 * (tolower(buff[i]) - 'a' + 10) + (tolower(buff[i+1]) - 'a' + 10);
        }

        value[size] = (char)(hex);
        size++;
    }

    if (error) *error = EOK;
    if (length) *length = size;
    TRACE_FLOW_STRING("get_bin_config_value", "Exit");
    return value;
}

/* Function to free binary configuration value */
void free_bin_config_value(char *value)
{
    if (value) free(value);
}

/* Arrays of stings */
static char **get_str_cfg_array(struct collection_item *item,
                                int include,
                                const char *sep,
                                int *size,
                                int *error)
{
    char *copy = NULL;
    char *dest = NULL;
    char locsep[4];
    int lensep;
    char *buff;
    int count = 0;
    int len = 0;
    int resume_len;
    char **array;
    char *start;
    int i, j;
    int dlen;

    TRACE_FLOW_STRING("get_str_cfg_array", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (col_get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    /* Handle the separators */
    if (sep == NULL) {
        locsep[0] = ',';
        locsep[1] = '\0';
        lensep = 2;
    }
    else {
        strncpy(locsep, sep, 3);
        locsep[3] = '\0';
        lensep = strlen(locsep) + 1;
    }

    /* Allocate memory for the copy of the string */
    copy = malloc(col_get_item_length(item));
    if (copy == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate memory.", ENOMEM);
        if (error) *error = ENOMEM;
        return NULL;
    }

    /* Loop through the string */
    dest = copy;
    buff = col_get_item_data(item);
    start = buff;
    dlen = col_get_item_length(item);
    for(i = 0; i < dlen; i++) {
        for(j = 0; j < lensep; j++) {
            if(buff[i] == locsep[j]) {
                /* If we found one of the separators trim spaces around */
                resume_len = len;
                while (len > 0) {
                    if (isspace(start[len - 1])) len--;
                    else break;
                }
                TRACE_INFO_STRING("Current:", start);
                TRACE_INFO_NUMBER("Length:", len);
                if (len > 0) {
                    /* Save block aside */
                    memcpy(dest, start, len);
                    count++;
                    dest += len;
                    *dest = '\0';
                    dest++;
                }
                else if(include) {
                    count++;
                    *dest = '\0';
                    dest++;
                }
                if (locsep[j] == '\0') break; /* We are done */

                /* Move forward and trim spaces if any */
                start += resume_len + 1;
                i++;
                TRACE_INFO_STRING("Other pointer :", buff + i);
                while ((i < dlen) && (isspace(*start))) {
                    i++;
                    start++;
                }
                len = -1; /* Len will be increased in the loop */
                i--; /* i will be increas so we need to step back */
                TRACE_INFO_STRING("Remaining buffer after triming spaces:", start);
                break;
            }
        }
        len++;
    }

    /* Now we know how many items are there in the list */
    array = malloc((count + 1) * sizeof(char *));
    if (array == NULL) {
        free(copy);
        TRACE_ERROR_NUMBER("Failed to allocate memory.", ENOMEM);
        if (error) *error = ENOMEM;
        return NULL;
    }

    /* Loop again to fill in the pointers */
    start = copy;
    for (i = 0; i < count; i++) {
        TRACE_INFO_STRING("Token :", start);
        TRACE_INFO_NUMBER("Item :", i);
        array[i] = start;
        /* Move to next item */
        while(*start) start++;
        start++;
    }
    array[count] = NULL;

    if (error) *error = EOK;
    if (size) *size = count;
    TRACE_FLOW_STRING("get_str_cfg_array", "Exit");
    return array;
}

/* Get array of strings from item eliminating empty tokens */
char **get_string_config_array(struct collection_item *item,
                               const char *sep, int *size, int *error)
{
    TRACE_FLOW_STRING("get_string_config_array", "Called.");
    return get_str_cfg_array(item, EXCLUDE_EMPTY, sep, size, error);
}
/* Get array of strings from item preserving empty tokens */
char **get_raw_string_config_array(struct collection_item *item,
                                   const char *sep, int *size, int *error)
{
    TRACE_FLOW_STRING("get_raw_string_config_array", "Called.");
    return get_str_cfg_array(item, INCLUDE_EMPTY, sep, size, error);
}

/* Special function to free string config array */
void free_string_config_array(char **str_config)
{
    TRACE_FLOW_STRING("free_string_config_array", "Entry");

    if (str_config != NULL) {
        if (*str_config != NULL) free(*str_config);
        free(str_config);
    }

    TRACE_FLOW_STRING("free_string_config_array", "Exit");
}

/* Get an array of long values.
 * NOTE: For now I leave just one function that returns numeric arrays.
 * In future if we need other numeric types we can change it to do strtoll
 * internally and wrap it for backward compatibility.
 */
long *get_long_config_array(struct collection_item *item, int *size, int *error)
{
    const char *str;
    char *endptr;
    long val = 0;
    long *array;
    int count = 0;
    int err;

    TRACE_FLOW_STRING("get_long_config_array", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (col_get_item_type(item) != COL_TYPE_STRING) ||
        (size == NULL)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    /* Assume that we have maximum number of different numbers */
    array = (long *)malloc(sizeof(long) * col_get_item_length(item)/2);
    if (array == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate memory.", ENOMEM);
        if (error) *error = ENOMEM;
        return NULL;
    }

    /* Now parse the string */
    str = (const char *)col_get_item_data(item);
    while (*str) {

        errno = 0;
        val = strtol(str, &endptr, 10);
        err = errno;

        if (err) {
            TRACE_ERROR_NUMBER("Conversion failed", err);
            free(array);
            if (error) *error = err;
            return NULL;
        }

        if (endptr == str) {
            TRACE_ERROR_NUMBER("Nothing processed", EIO);
            free(array);
            if (error) *error = EIO;
            return NULL;
        }

        /* Save value */
        array[count] = val;
        count++;
        /* Are we done? */
        if (*endptr == 0) break;
        /* Advance to the next valid number */
        for (str = endptr; *str; str++) {
            if (isdigit(*str) || (*str == '-') || (*str == '+')) break;
        }
    }

    *size = count;
    if (error) *error = EOK;

    TRACE_FLOW_NUMBER("get_long_config_value returning", val);
    return array;

}

/* Get an array of double values */
double *get_double_config_array(struct collection_item *item, int *size, int *error)
{
    const char *str;
    char *endptr;
    double val = 0;
    double *array;
    int count = 0;
    struct lconv *loc;

    TRACE_FLOW_STRING("get_double_config_array", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (col_get_item_type(item) != COL_TYPE_STRING) ||
        (size == NULL)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    /* Assume that we have maximum number of different numbers */
    array = (double *)malloc(sizeof(double) * col_get_item_length(item)/2);
    if (array == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate memory.", ENOMEM);
        if (error) *error = ENOMEM;
        return NULL;
    }

    /* Get locale information so that we can check for decimal point character.
     * Based on the man pages it is unclear if this is an allocated memory or not.
     * Seems like it is a static thread or process local structure so
     * I will not try to free it after use.
     */
    loc = localeconv();

    /* Now parse the string */
    str = (const char *)col_get_item_data(item);
    while (*str) {
        TRACE_INFO_STRING("String to convert",str);
        errno = 0;
        val = strtod(str, &endptr);
        if ((errno == ERANGE) ||
            ((errno != 0) && (val == 0)) ||
            (endptr == str)) {
            TRACE_ERROR_NUMBER("Conversion failed", EIO);
            free(array);
            if (error) *error = EIO;
            return NULL;
        }
        /* Save value */
        array[count] = val;
        count++;
        /* Are we done? */
        if (*endptr == 0) break;
        TRACE_INFO_STRING("End pointer after conversion",endptr);
        /* Advance to the next valid number */
        for (str = endptr; *str; str++) {
            if (isdigit(*str) || (*str == '-') || (*str == '+') ||
               /* It is ok to do this since the string is null terminated */
               ((*str == *(loc->decimal_point)) && isdigit(str[1]))) break;
        }
    }

    *size = count;
    if (error) *error = EOK;

    TRACE_FLOW_NUMBER("get_double_config_value returning", val);
    return array;

}


/* Special function to free long config array */
void free_long_config_array(long *array)
{
    if (array != NULL) free(array);
}

/* Special function to free double config array */
void free_double_config_array(double *array)
{
    if (array != NULL) free(array);
}

/* The section array should be freed using this function */
void free_section_list(char **section_list)
{
    TRACE_FLOW_STRING("free_section_list","Entry");

    col_free_property_list(section_list);

    TRACE_FLOW_STRING("free_section_list","Exit");
}

/* The section array should be freed using this function */
void free_attribute_list(char **section_list)
{
    TRACE_FLOW_STRING("free_section_list","Entry");

    col_free_property_list(section_list);

    TRACE_FLOW_STRING("free_section_list","Exit");
}


/* Get list of sections as an array of strings.
 * Function allocates memory for the array of the sections.
 */
char **get_section_list(struct collection_item *ini_config, int *size, int *error)
{
    char **list;

    TRACE_FLOW_STRING("get_section_list","Entry");
    /* Do we have the item ? */
    if ((ini_config == NULL) ||
        ((col_is_of_class(ini_config, COL_CLASS_INI_CONFIG) == 0) &&
         (col_is_of_class(ini_config, COL_CLASS_INI_META) == 0))) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    /* Pass it to the function from collection API */
    list = col_collection_to_list(ini_config, size, error);

    TRACE_FLOW_STRING("get_section_list returning", ((list == NULL) ? "NULL" : list[0]));
    return list;
}

/* Get list of attributes in a section as an array of strings.
 * Function allocates memory for the array of the strings.
 */
char **get_attribute_list(struct collection_item *ini_config, const char *section, int *size, int *error)
{
    struct collection_item *subcollection = NULL;
    char **list;
    int err;

    TRACE_FLOW_STRING("get_attribute_list","Entry");
    /* Do we have the item ? */
    if ((ini_config == NULL) ||
        ((col_is_of_class(ini_config, COL_CLASS_INI_CONFIG) == 0) &&
         (col_is_of_class(ini_config, COL_CLASS_INI_META) == 0)) ||
        (section == NULL)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    /* Fetch section */
    err = col_get_collection_reference(ini_config, &subcollection, section);
    /* Check error */
    if (err && (subcollection == NULL)) {
        TRACE_ERROR_NUMBER("Failed to get section", err);
        if (error) *error = EINVAL;
        return NULL;
    }

    /* Pass it to the function from collection API */
    list = col_collection_to_list(subcollection, size, error);

    col_destroy_collection(subcollection);

    TRACE_FLOW_STRING("get_attribute_list returning", ((list == NULL) ? "NULL" : list[0]));
    return list;
}
