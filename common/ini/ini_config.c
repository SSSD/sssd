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
#include "config.h"
/* For error text */
#include <libintl.h>
#define _(String) gettext (String)
/* INI file is used as a collection */
#include "collection_priv.h"
#include "collection.h"
#include "collection_tools.h"
#include "trace.h"
#include "ini_config.h"

#define NAME_OVERHEAD   10

#define SLASH           "/"

/* Name of the special collection used to store parsing errors */
#define FILE_ERROR_SET  "ini_file_error_set"

/* Text error strings used when errors are printed out */
#define WARNING_TXT        _("Warning")
#define ERROR_TXT          _("Error")
#define WRONG_COLLECTION   _("Passed in list is not a list of parse errors.\n")
#define FAILED_TO_PROCCESS _("Internal Error. Failed to process error list.\n")
#define ERROR_HEADER       _("Parsing errors and warnings in file: %s\n")
#define LINE_FORMAT        _("%s (%d) on line %d: %s\n")

/* Codes that parsing function can return */
#define RET_PAIR        0
#define RET_COMMENT     1
#define RET_SECTION     2
#define RET_INVALID     3
#define RET_EMPTY       4
#define RET_EOF         5
#define RET_ERROR       6

/* STATIC INTERNAL FUNCTIONS */
#ifdef HAVE_PARSE_ERROR


/* Function to return parsing error */
inline const char *parsing_error_str(int parsing_error)
{
    const char *placeholder= _("Unknown error.");
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

#else


inline const char *parsing_error_str(int parsing_error)
{
    const char *placeholder= _("Parsing errors are not compiled.");
    return placeholder;
}

#endif

int read_line(FILE *file,char **key,char **value, int *length, int *ext_error);

/* Add to collection or update - CONSIDER moving to the collection.c */
static int add_or_update(struct collection_item *current_section,
                         char *key,
                         void *value,
                         int length,
                         int type)
{
    int found = COL_NOMATCH;
	int error;

    TRACE_FLOW_STRING("add_or_update", "Entry");

    error = is_item_in_collection(current_section, key,
                                  COL_TYPE_ANY, COL_TRAVERSE_IGNORE, &found);

    if (found == COL_MATCH) {
        TRACE_INFO_STRING("Updating...", "");
        error = update_property(current_section,
                                key, type, value, length,
                                COL_TRAVERSE_IGNORE);
    }
    else {
        TRACE_INFO_STRING("Adding...", "");
        error = add_any_property(current_section, NULL,
                                 key, type, value, length);
    }

    TRACE_FLOW_NUMBER("add_or_update returning", error);
    return error;
}

/***************************************************************************/
/* Function to read single ini file and pupulate
 * the provided collection with subcollcetions from the file */
static int ini_to_collection(const char *filename,
                             struct collection_item *ini_config,
                             int error_level,
                             struct collection_item **error_list)
{
    FILE *file;
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

    TRACE_FLOW_STRING("ini_to_collection", "Entry");

    /* Open file for reading */
    file = fopen(filename,"r");
    if (file == NULL) {
        error = errno;
        TRACE_ERROR_NUMBER("Failed to open file - but this is OK", error);
        return EOK;
    }

    /* Open the collection of errors */
    if (error_list != NULL) {
        *error_list = NULL;
        error = create_collection(error_list, filename, COL_CLASS_INI_PERROR);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to create error collection", error);
            fclose(file);
            return EOK;
        }
        created = 1;
    }

    /* Read file lines */
    while (1) {
        status = read_line(file, &key, &value, &length, &ext_err);
        if (status == RET_EOF) break;

        line++;

        switch (status) {
        case RET_PAIR:
            /* Do we have a section at the top of the file ? */
            if (section_count == 0) {
                /* Check if collection already exists */
                error = get_collection_reference(ini_config, &current_section,
                                                 INI_DEFAULT_SECTION);
                if (error != EOK) {
                    /* Create default collection */
                    if ((error = create_collection(&current_section,
                                                   INI_DEFAULT_SECTION,
                                                   COL_CLASS_INI_SECTION)) ||
                        (error = add_collection_to_collection(ini_config,
                                                   NULL,NULL,
                                                   current_section,
                                                   COL_ADD_MODE_REFERENCE))) {
                        TRACE_ERROR_NUMBER("Failed to create collection", error);
                        fclose(file);
                        destroy_collection(current_section);
                        if (created) destroy_collection(*error_list);
                        return error;
                    }
                }
                section_count++;
            }

            /* Put value into the collection */
            error = add_or_update(current_section,
                                  key, value, length, COL_TYPE_STRING);
            if (error != EOK) {
                TRACE_ERROR_NUMBER("Failed to add pair to collection", error);
                fclose(file);
                destroy_collection(current_section);
                if (created) destroy_collection(*error_list);
                return error;
            }
            break;

        case RET_SECTION:
            /* Read a new section */
            destroy_collection(current_section);
            current_section = NULL;

            error = get_collection_reference(ini_config, &current_section, key);
            if (error != EOK) {
                /* Create default collection */
                if ((error = create_collection(&current_section, key,
                                               COL_CLASS_INI_SECTION)) ||
                    (error = add_collection_to_collection(ini_config,
                                               NULL, NULL,
                                               current_section,
                                               COL_ADD_MODE_REFERENCE))) {
                    TRACE_ERROR_NUMBER("Failed to add collection", error);
                    fclose(file);
                    destroy_collection(current_section);
                    if (created) destroy_collection(*error_list);
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
            error = add_binary_property(*error_list, NULL,
                                        ERROR_TXT, &pe, sizeof(pe));
            if (error) {
                TRACE_ERROR_NUMBER("Failed to add error to collection", error);
                fclose(file);
                destroy_collection(current_section);
                if (created) destroy_collection(*error_list);
                return error;
            }
            /* Exit if there was an error parsing file */
            if (error_level != INI_STOP_ON_NONE) {
                TRACE_ERROR_STRING("Invalid format of the file", "");
                destroy_collection(current_section);
                fclose(file);
                return EIO;
            }
            break;

        case RET_INVALID:
        default:
            pe.line = line;
            pe.error = ext_err;
            error = add_binary_property(*error_list, NULL,
                                        WARNING_TXT, &pe, sizeof(pe));
            if (error) {
                TRACE_ERROR_NUMBER("Failed to add warning to collection", error);
                fclose(file);
                destroy_collection(current_section);
                if (created) destroy_collection(*error_list);
                return error;
            }
            /* Exit if we are told to exit on warnings */
            if (error_level == INI_STOP_ON_ANY) {
                TRACE_ERROR_STRING("Invalid format of the file", "");
                if (created) destroy_collection(current_section);
                fclose(file);
                return EIO;
            }
            TRACE_ERROR_STRING("Invalid string", "");
            break;
        }
        ext_err = -1;
    }

    /* Close file */
    fclose(file);

    DEBUG_COLLECTION(ini_config);

    destroy_collection(current_section);

    DEBUG_COLLECTION(ini_config);

    TRACE_FLOW_STRING("ini_to_collection", "Success Exit");

    return EOK;
}

/*********************************************************************/
/* Read configuration information from a file */
int config_from_file(const char *application,
                     const char *config_file,
                     struct collection_item **ini_config,
                     int error_level,
                     struct collection_item **error_list)
{
    int error;
    int created = 0;

    TRACE_FLOW_STRING("config_from_file", "Entry");

    if ((ini_config == NULL) ||
        (application == NULL)) {
        TRACE_ERROR_NUMBER("Invalid argument", EINVAL);
        return EINVAL;
    }

    /* Create collection if needed */
    if (*ini_config == NULL) {
        error = create_collection(ini_config,
                                  application,
                                  COL_CLASS_INI_CONFIG);
        if (error != EOK) {
            TRACE_ERROR_NUMBER("Failed to create collection", error);
            return error;
        }
        created = 1;
    }
    /* Is the collection of the right class? */
    else if (is_of_class(*ini_config, COL_CLASS_INI_CONFIG)) {
        TRACE_ERROR_NUMBER("Wrong collection type", EINVAL);
        return EINVAL;
    }

    /* Do the actual work */
    error = ini_to_collection(config_file, *ini_config,
                              error_level, error_list);
    /* In case of error when we created collection - delete it */
    if (error && created) {
        destroy_collection(*ini_config);
        *ini_config = NULL;
    }

    TRACE_FLOW_NUMBER("config_from_file. Returns", error);
    return error;
}

/* Read default config file and then overwrite it with a specific one
 * from the directory */
int config_for_app(const char *application,
                   const char *config_file,
                   const char *config_dir,
                   struct collection_item **ini_config,
                   int error_level,
                   struct collection_item **error_set)
{
    int error = EOK;
    char *file_name;
    struct collection_item *error_list_common = NULL;
    struct collection_item *error_list_specific = NULL;
    struct collection_item **pass_common = NULL;
    struct collection_item **pass_specific = NULL;
    int created = 0;

    TRACE_FLOW_STRING("config_to_collection", "Entry");

    if (ini_config == NULL) {
        TRACE_ERROR_NUMBER("Failed to create collection", EINVAL);
        return EINVAL;
    }

    /* Prepare error collection pointers */
    if (error_set != NULL) {
        TRACE_INFO_STRING("Error set is not NULL", "preparing error set");
        pass_common = &error_list_common;
        pass_specific = &error_list_specific;
        *error_set = NULL;
        /* Construct the overarching error collection */
        error = create_collection(error_set,
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
        error = create_collection(ini_config,
                                  application,
                                  COL_CLASS_INI_CONFIG);
        if (error != EOK) {
            TRACE_ERROR_NUMBER("Failed to create collection", error);
            destroy_collection(*error_set);
            *error_set = NULL;
            return error;
        }
    }
    /* Is the collection of the right class? */
    else if (is_of_class(*ini_config, COL_CLASS_INI_CONFIG)) {
        TRACE_ERROR_NUMBER("Wrong collection type", EINVAL);
        return EINVAL;
    }

    /* Read master file */
    if (config_file != NULL) {
        TRACE_INFO_STRING("Reading master file:", config_file);
        error = ini_to_collection(config_file, *ini_config,
                                  error_level, pass_common);
        if (error != EOK) {
            TRACE_ERROR_NUMBER("Failed to read master file", error);
            /* In case of error when we created collection - delete it */
            if(error && created) {
                destroy_collection(*ini_config);
                *ini_config = NULL;
            }
            /* We do not clear the error_set here */
            return error;
        }
        /* Add error results if any to the overarching error collection */
        if ((pass_common != NULL) && (*pass_common != NULL)) {
            TRACE_INFO_STRING("Process erros resulting from file:", config_file);
            error = add_collection_to_collection(*error_set, NULL, NULL,
                                                 *pass_common,
                                                 COL_ADD_MODE_EMBED);
            if (error) {
                if (created) {
                    destroy_collection(*ini_config);
                    *ini_config = NULL;
                }
                destroy_collection(*error_set);
                *error_set = NULL;
                TRACE_ERROR_NUMBER("Failed to add error collection to another error collection", error);
                return error;
            }
        }
    }

    if (config_dir != NULL) {
        /* Get specific application file */
        file_name = malloc(strlen(config_dir) + strlen(application) + NAME_OVERHEAD);
        if (file_name == NULL) {
            error = errno;
            TRACE_ERROR_NUMBER("Failed to allocate memory for file name", error);
            /* In case of error when we created collection - delete it */
            if(error && created) {
                destroy_collection(*ini_config);
                *ini_config = NULL;
            }
            destroy_collection(*error_set);
            *error_set = NULL;
            return error;
        }

        sprintf(file_name, "%s%s%s.conf", config_dir, SLASH, application);
        TRACE_INFO_STRING("Opening file:", file_name);

        /* Read master file */
	    error = ini_to_collection(file_name, *ini_config,
                                  error_level, pass_specific);
        free(file_name);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to read specific application file", error);
            /* In case of error when we created collection - delete it */
            if (error && created) {
                destroy_collection(*ini_config);
                *ini_config = NULL;
            }
            /* We do not clear the error_set here */
            return error;
        }

        /* Add error results if any to the overarching error collection */
        if ((pass_specific != NULL) && (*pass_specific != NULL)) {
            TRACE_INFO_STRING("Process erros resulting from file:", file_name);
            error = add_collection_to_collection(*error_set, NULL, NULL,
                                                 *pass_specific,
                                                 COL_ADD_MODE_EMBED);
            if (error) {
                if (created) {
                    destroy_collection(*ini_config);
                    *ini_config = NULL;
                }
                destroy_collection(*error_set);
                *error_set = NULL;
                TRACE_ERROR_NUMBER("Failed to add error collection to another error collection", error);
                return error;
            }
        }
    }

    TRACE_FLOW_STRING("config_to_collection", "Exit");
    return EOK;
}

/* Reads a line from the file */
int read_line(FILE *file, char **key,char **value, int *length, int *ext_error)
{

    char *res;
    char buf[BUFFER_SIZE+1];
    int len;
    char *buffer;
    int i;
    char *eq;

    TRACE_FLOW_STRING("read_line", "Entry");

    *ext_error = 0;

    buffer = buf;

    /* Get data from file */
    res = fgets(buffer, BUFFER_SIZE, file);
    if (res == NULL) {
        TRACE_ERROR_STRING("Read nothing", "");
        return RET_EOF;
    }

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
    while (isspace(buffer[len - 1])) {
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
        return RET_BEST_EFFORT;
    }

    len -= eq-buffer;

    /* Strip spaces around "=" */
    i = eq - buffer - 1;
    while ((i >= 0) && isspace(buffer[i])) i--;
    if (i < 0) {
        TRACE_ERROR_STRING("No key", buf);
        *ext_error = ERR_NOKEY;
        return RET_BEST_EFFORT;
    }

    /* Copy key into provided buffer */
    if(i >= MAX_KEY) {
        TRACE_ERROR_STRING("Section name is too long", buf);
        *ext_error = ERR_LONGKEY;
        return RET_BEST_EFFORT;
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


/* Print errors and warnings that were detected while parsing one file */
void print_file_parsing_errors(FILE *file,
                               struct collection_item *error_list)
{
    struct collection_iterator *iterator;
    int error;
    struct collection_item *item = NULL;
    struct parse_error *pe;
    unsigned int count;

    TRACE_FLOW_STRING("print_file_parsing_errors", "Entry");

    /* If we have something to print print it */
    if (error_list == NULL) {
        TRACE_ERROR_STRING("No error list","");
        return;
    }

    /* Make sure we go the right collection */
    if (!is_of_class(error_list, COL_CLASS_INI_PERROR)) {
        TRACE_ERROR_STRING("Wrong collection class:", WRONG_COLLECTION);
        fprintf(file,"%s\n", WRONG_COLLECTION);
        return;
    }

    /* Bind iterator */
    error =  bind_iterator(&iterator, error_list, COL_TRAVERSE_DEFAULT);
    if (error) {
        TRACE_ERROR_STRING("Error (bind):", FAILED_TO_PROCCESS);
        fprintf(file, "%s\n", FAILED_TO_PROCCESS);
        return;
    }

    while(1) {
        /* Loop through a collection */
        error = iterate_collection(iterator, &item);
        if (error) {
            TRACE_ERROR_STRING("Error (iterate):", FAILED_TO_PROCCESS);
            fprintf(file, "%s\n", FAILED_TO_PROCCESS);
            unbind_iterator(iterator);
            return;
        }

        /* Are we done ? */
        if (item == NULL) break;

        /* Process collection header */
        if (get_item_type(item) == COL_TYPE_COLLECTION) {
            get_collection_count(item, &count);
            if (count > 1)
                fprintf(file, ERROR_HEADER, get_item_property(item, NULL));
            else break;
        }
        else {
            /* Put error into provided format */
            pe = (struct parse_error *)(get_item_data(item));
            fprintf(file, LINE_FORMAT,
                    get_item_property(item, NULL),      /* Error or warning */
                    pe->error,                          /* Error */
					pe->line,                           /* Line */
                    parsing_error_str(pe->error));      /* Error str */
        }

    }

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    unbind_iterator(iterator);

    TRACE_FLOW_STRING("print_file_parsing_errors", "Exit");
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
    if (!is_of_class(error_list, COL_CLASS_INI_PESET)) {
        TRACE_ERROR_STRING("Wrong collection class:", WRONG_COLLECTION);
        fprintf(file, "%s\n", WRONG_COLLECTION);
        return;
    }

    /* Bind iterator */
    error =  bind_iterator(&iterator, error_list, COL_TRAVERSE_DEFAULT);
    if (error) {
        TRACE_ERROR_STRING("Error (bind):", FAILED_TO_PROCCESS);
        fprintf(file,"%s\n", FAILED_TO_PROCCESS);
        return;
    }

    while(1) {
        /* Loop through a collection */
        error = iterate_collection(iterator, &item);
        if (error) {
            TRACE_ERROR_STRING("Error (iterate):", FAILED_TO_PROCCESS);
            fprintf(file, "%s\n", FAILED_TO_PROCCESS);
            unbind_iterator(iterator);
            return;
        }

        /* Are we done ? */
        if (item == NULL) break;

        /* Print per file sets of errors */
        if (get_item_type(item) == COL_TYPE_COLLECTIONREF) {
            /* Extract a sub collection */
            error = get_reference_from_item(item, &file_errors);
            if (error) {
                TRACE_ERROR_STRING("Error (extract):", FAILED_TO_PROCCESS);
                fprintf(file, "%s\n", FAILED_TO_PROCCESS);
                return;
            }
            print_file_parsing_errors(file, file_errors);
            destroy_collection(file_errors);
        }
    }

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    unbind_iterator(iterator);

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
    char *to_find;
    char default_section[] = INI_DEFAULT_SECTION;

    TRACE_FLOW_STRING("get_config_item", "Entry");

    /* Do we have the accepting memory ? */
    if (item == NULL) {
        TRACE_ERROR_NUMBER("No buffer - invalid argument.", EINVAL);
        return EINVAL;
    }

    /* Is the collection of a right type */
    if (!is_of_class(ini_config, COL_CLASS_INI_CONFIG)) {
        TRACE_ERROR_NUMBER("Wrong collection type", EINVAL);
        return EINVAL;
    }

    *item = NULL;

    if (section == NULL) to_find = default_section;
    else to_find = section;

    TRACE_INFO_STRING("Getting Name:", name);
    TRACE_INFO_STRING("In Section:", section);

    /* Get Subcollection */
    error = get_collection_reference(ini_config, &section_handle, to_find);
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
    error = get_item(section_handle, name,
                     COL_TYPE_STRING, COL_TRAVERSE_ONELEVEL, item);

    TRACE_FLOW_NUMBER("get_config_item returning", error);
    return error;
}

/* Get long value from config item */
long get_long_config_value(struct collection_item *item,
                           int strict, long def, int *error)
{
    char *endptr, *str;
    long val = 0;

    TRACE_FLOW_STRING("get_long_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
       (get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return def;
    }

    if (error) *error = EOK;

    /* Try to parse the value */
    str = (char *)get_item_data(item);
    errno = 0;
    val = strtol(str, &endptr, 10);

    /* Check for various possible errors */
    if (((errno == ERANGE) &&
        ((val == LONG_MAX) ||
         (val == LONG_MIN))) ||
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

    TRACE_FLOW_NUMBER("get_long_config_value returning", val);
    return val;
}

/* Get integer value from config item */
inline int get_int_config_value(struct collection_item *item,
                                int strict, int def, int *error)
{
    return get_long_config_value(item, strict, def, error);
}

/* Get unsigned integer value from config item */
unsigned get_unsigned_config_value(struct collection_item *item,
                                   int strict, unsigned def, int *error)
{
    return get_long_config_value(item, strict, def, error);
}

/* Get unsigned long value from config item */
unsigned long get_ulong_config_value(struct collection_item *item,
                                     int strict, unsigned long def, int *error)
{
    return get_long_config_value(item, strict, def, error);
}

/* Get double value */
double get_double_config_value(struct collection_item *item,
                               int strict, double def, int *error)
{
    char *endptr, *str;
    double val = 0;

    TRACE_FLOW_STRING("get_double_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return def;
    }

    if (error) *error = EOK;

    /* Try to parse the value */
    str = (char *)get_item_data(item);
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
    char *str;
    int len;

    TRACE_FLOW_STRING("get_bool_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return def;
    }

    if (error) *error = EOK;

    str = (char *)get_item_data(item);
    len = get_item_length(item);

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
                              int dup, int *error)
{
    char *str = NULL;

    TRACE_FLOW_STRING("get_string_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    /* If we are told to dup the value */
    if (dup) {
        errno = 0;
        str = strdup((char *)get_item_data(item));
        if (str == NULL) {
            TRACE_ERROR_NUMBER("Failed to allocate memory.", ENOMEM);
            if (error) *error = ENOMEM;
            return NULL;
        }
    }
    else str = (char *)get_item_data(item);

    if (error) *error = EOK;

    TRACE_FLOW_STRING("get_string_config_value", "Exit");
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
    char *buff;
    int size = 0;
    unsigned char hex;
    int len;
    char *str;

    TRACE_FLOW_STRING("get_bin_config_value", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    /* Check the length */
    len = get_item_length(item)-1;
    if ((len%2) != 0) {
        TRACE_ERROR_STRING("Invalid length for binary data", "");
        if (error) *error = EINVAL;
        return NULL;
    }

    str = (char *)get_item_data(item);

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
inline void free_bin_config_value(char *value)
{
    if (value) free(value);
}

/* Arrays of stings and integers */
char **get_string_config_array(struct collection_item *item,
                               char *sep, int *size, int *error)
{
    char defsep[] = ",";
    char *copy = NULL;
    char *dest = NULL;
    int lensep;
    char *buff;
    int count = 0;
    int len = 0;
    int resume_len;
    char **array;
    char *start;
    int i, j, k;
    int growlen = 0;

    TRACE_FLOW_STRING("get_string_config_array", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (get_item_type(item) != COL_TYPE_STRING)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    /* Handle the separators */
    if (sep == NULL) sep = defsep;
    lensep = strnlen(sep, 3);

    /* Allocate memory for the copy of the string */
    copy = malloc(get_item_length(item));
    if (copy == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate memory.", ENOMEM);
        if (error) *error = ENOMEM;
        return NULL;
    }

    /* Loop through the string */
    dest = copy;
    buff = item->data;
    start = buff;
    for(i = 0; i < item->length; i++) {
        growlen = 1;
        for(j = 0; j < lensep; j++) {
            if(buff[i] == sep[j]) {
                /* If we found one of the separators trim spaces around */
                resume_len = len;
                while (len > 0) {
                    if (isspace(start[len - 1])) len--;
                    else break;
                }
                if (len > 0) {
                    /* Save block aside */
                    memcpy(dest, start, len);
                    count++;
                    dest += len;
                    *dest = '\0';
                    dest++;
                    len = 0;
                    /* Move forward and trim spaces if any */
                    start += resume_len + 1;
                    i++;
                    TRACE_INFO_STRING("Remaining buffer :", start);
                    TRACE_INFO_STRING("Other pointer :", buff + i);
                    k = 0;
                    while (((i + k) < item->length) && (isspace(*start))) {
                        k++;
                        start++;
                    }
                    TRACE_INFO_STRING("Remaining buffer after triming spaces:", start);
                    if (k) i += k - 1;
                    /* Next iteration of the loop will add 1 */
                }
                /* Break out of the inner loop */
                growlen = 0;
                break;
            }
        }
        if (growlen) len++;
    }

    /* Copy the remaining piece */
    memcpy(dest, start, len);
    count++;
    dest += len;
    dest = '\0';
    dest++;

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
        array[i] = start;
        while (start) start++;
        start++;
    }
    array[count] = NULL;

    if (error) *error = EOK;
    if (size) *size = count;
    TRACE_FLOW_STRING("get_string_config_array", "Exit");
    return array;
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

/* Get an array of long values */
long *get_long_config_array(struct collection_item *item, int *size, int *error)
{
    char *endptr, *str;
    long val = 0;
    long *array;
    int count = 0;

    TRACE_FLOW_STRING("get_long_config_array", "Entry");

    /* Do we have the item ? */
    if ((item == NULL) ||
        (get_item_type(item) != COL_TYPE_STRING) ||
        (size == NULL)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        if (error) *error = EINVAL;
        return NULL;
    }

    /* Assume that we have maximum number of different numbers */
    array = (long *)malloc(sizeof(long) * get_item_length(item)/2);
    if (array == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate memory.", ENOMEM);
        if (error) *error = ENOMEM;
        return NULL;
    }

    /* Now parse the string */
    str = (char *)get_item_data(item);
    while (str) {
        errno = 0;
        val = strtol(str, &endptr, 10);
        if (((errno == ERANGE) &&
            ((val == LONG_MAX) ||
             (val == LONG_MIN))) ||
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
        /* Advance to the next valid number */
        for (str = endptr; *str; str++) {
            if (isdigit(*str) || (*str != '-') || (*str != '+')) break;
        }
    }

    *size = count;
    if (error) *error = EOK;

    TRACE_FLOW_NUMBER("get_long_config_value returning", val);
    return array;

}

/* Special function to free long config array */
inline void free_long_config_array(long *array)
{
    if (array != NULL) free(array);
}

