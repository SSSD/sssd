/*
    INI LIBRARY

    Header file for reading configuration from INI file
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

#ifndef INI_CONFIG_H
#define INI_CONFIG_H

#include <limits.h>
#include "collection.h"

/* Name of the default (missing section in the INI file */
#define INI_DEFAULT_SECTION "default"

/* Collection classes used in INI processing */
#define COL_CLASS_INI_BASE        20000
#define COL_CLASS_INI_CONFIG      COL_CLASS_INI_BASE + 0 /* Class for configuration collection. Implies a collection of sections */
#define COL_CLASS_INI_SECTION     COL_CLASS_INI_BASE + 1 /* A one level collection of key value pairs where values are always stings */
#define COL_CLASS_INI_PERROR      COL_CLASS_INI_BASE + 2 /* A one level collection of parse errors - store parse_error structs */
#define COL_CLASS_INI_PESET       COL_CLASS_INI_BASE + 3 /* A one level collection of parse error collections */
#define COL_CLASS_INI_GERROR      COL_CLASS_INI_BASE + 4 /* A one level collection of grammar errors - store parse_error structs */
#define COL_CLASS_INI_VERROR      COL_CLASS_INI_BASE + 5 /* A one level collection of validation errors - store parse_error structs */
#define COL_CLASS_INI_LINES       COL_CLASS_INI_BASE + 6 /* A one level collection of lines in INI file */


/* Error levels */
#define INI_STOP_ON_ANY     0   /* Fail if any problem is detected */
#define INI_STOP_ON_NONE    1   /* Best effort - do not fail */
#define INI_STOP_ON_ERROR   2   /* Fail on errors only */


/* Parsing errors and warnings */
#define ERR_LONGDATA        1   /* Error */
#define ERR_NOCLOSESEC      2   /* Error */
#define ERR_NOSECTION       3   /* Error */
#define ERR_SECTIONLONG     4   /* Error */
#define ERR_NOEQUAL         5   /* Warning */
#define ERR_NOKEY           6   /* Warning */
#define ERR_LONGKEY         7   /* Warning */

#define ERR_MAXPARSE        ERR_LONGKEY

/* Grammar errors and warnings */
/* Placeholder for now... */
#define ERR_MAXGRAMMAR      0

/* Validation errors and warnings */
/* Placeholder for now... */
#define ERR_MAXVALID        0



/* Internal sizes */
/* FIXME - make them configurable via config.h */
#define MAX_KEY         1024
#define MAX_VALUE       PATH_MAX
#define BUFFER_SIZE     MAX_KEY + MAX_VALUE + 3

struct parse_error {
    unsigned line;
    int error;
};

/* Function to return parsing error */
const char *parsing_error_str(int parsing_error);

/* Function to return grammar error in template.
 * This error is returned when the template
 * is translated into the grammar object.
 */
const char *grammar_error_str(int parsing_error);

/* Function to return validation error.
 * This is the error that it is returned when
 * the INI file is validated against the
 * grammar object.
 */
const char *validation_error_str(int parsing_error);

/* Read configuration information from a file */
int config_from_file(const char *application,               /* Name of the application - will be used as name of the collection */
                     const char *config_file,               /* Name of the config file - if NULL the collection will be empty */
                     struct collection_item **ini_config,   /* If *ini_config is NULL a new ini object will be allocated, */
                                                            /* otherwise the one that is pointed to will be updated. */
                     int error_level,                       /* Error level - break for errors, warnings or best effort (don't break) */
                     struct collection_item **error_list);  /* List of errors for a file */


/* Read configuration information from a file with extra collection of line numbers */
int config_from_file_with_lines(
                     const char *application,               /* Name of the application - will be used as name of the collection */
                     const char *config_file,               /* Name of the config file - if NULL the collection will be empty */
                     struct collection_item **ini_config,   /* If *ini_config is NULL a new ini object will be allocated, */
                                                            /* otherwise the one that is pointed to will be updated. */
                     int error_level,                       /* Error level - break for errors, warnings or best effort (don't break) */
                     struct collection_item **error_list,   /* List of errors for a file */
                     struct collection_item **lines);       /* Collection of pairs where key is the key and value is line number */


/* Read default config file and then overwrite it with a specific one from the directory */
int config_for_app(const char *application,               /* Name of the application that will be used to get config for */
                   const char *config_file,               /* Name of the configuration file with default settings for all apps */
                   const char *config_dir,                /* Name of the directory where the configuration files for different apps will be dropped */
                   struct collection_item **ini_config,   /* New config object */
                   int error_level,                       /* Level of error tolerance */
                   struct collection_item **error_set);   /* Collection of collections of parsing errors */

/* Function to free configuration */
void free_ini_config(struct collection_item *ini_config);

/* Function to free configuration error list */
void free_ini_config_errors(struct collection_item *error_set);

/* Function to free configuration line list */
void free_ini_config_lines(struct collection_item *lines);

/* Print errors and warnings that were detected while parsing one file */
/* Use this function to print results of the config_from_file() call */
void print_file_parsing_errors(FILE *file,                           /* File to send errors to */
                               struct collection_item *error_list);  /* List of parsing errors */


/* Print errors and warnings that were detected while
 * checking grammar of the template.
 */
void print_grammar_errors(FILE *file,                           /* File to send errors to */
                          struct collection_item *error_list);  /* List of grammar errors */

/* Print errors and warnings that were detected while
 * checking INI file against grammar object.
 */
void print_validation_errors(FILE *file,                           /* File to send errors to */
                             struct collection_item *error_list);  /* List of validation errors */

/* Print errors and warnings that were detected parsing configuration as a whole */
/* Use this function to print results of the config_for_app() call */
void print_config_parsing_errors(FILE *file,                           /* File to send errors to */
                                 struct collection_item *error_list);  /* Collection of collections of errors */

/* Get list of sections from the config collection as an array of strings.
 * Function allocates memory for the array of the sections.
 */
char **get_section_list(struct collection_item *ini_config, int *size, int *error);

/* The section array should be freed using this function */
void free_section_list(char **section_list);

/* Get list of attributes in a section as an array of strings.
 * Function allocates memory for the array of attributes.
 */
char **get_attribute_list(struct collection_item *ini_config, const char *section, int *size, int *error);

/* The attribute array should be freed using this function */
void free_attribute_list(char **attr_list);

/* Get a configuration item form the configuration */
int get_config_item(const char *section,                    /* Section. If NULL assumed default */
                    const char *name,                       /* Name of the property to look up */
                    struct collection_item *ini_config,     /* Collection to search */
                    struct collection_item **item);         /* Item returned. Will be NULL is not found. */

/* Conversion functions for the configuration item.
 * Sets error to EINVAL if the item is bad.
 * Sets error to EIO if the conversion failed.
 * These functions do not allocate memory.
 * They always return best effort conversion value.
 * In case of error they return provided default.
 * It is up to the caller to check an error and take an action.
 */
/* If "strict" parameter is non zero the function will fail if there are more
 * characters after last digit.
 */
int get_int_config_value(struct collection_item *item, int strict, int def, int *error);
long get_long_config_value(struct collection_item *item, int strict, long def, int *error);
unsigned get_unsigned_config_value(struct collection_item *item, int strict, unsigned def, int *error);
unsigned long get_ulong_config_value(struct collection_item *item, int strict, unsigned long def, int *error);
double get_double_config_value(struct collection_item *item, int strict, double def, int *error);
unsigned char get_bool_config_value(struct collection_item *item, unsigned char def, int *error);

/* Function get_string_config_value returns a newly allocated pointer to the string out of item.*/
char *get_string_config_value(struct collection_item *item, int *error);
/* Function returns the string stored in the item */
const char *get_const_string_config_value(struct collection_item *item, int *error);

/* A get_bin_value and get_xxx_array functions allocate memory.
 * It is the responsibility of the caller to free it after use.
 * free_xxx convenience wrappers are provided for this purpose.
 * Functions will return NULL if conversion failed.
 */
/* A special hex format is assumed.
 * The string should be taken in single quotes
 * and consist of hex encoded value two hex digits per byte.
 * Example: '0A2BFECC'
 * Case does not matter.
 */
char *get_bin_config_value(struct collection_item *item, int *length, int *error);
void free_bin_config_value(char *);

/* Array of stings */
/* Separator sting includes up to three different separators. If NULL comma is assumed. */
/* The spaces are trimmed automatically around separators in the string. */
char **get_string_config_array(struct collection_item *item, const char *sep, int *size, int *error);
/* Array of long values - separators are detected automatically. */
/* The length of the allocated array is returned in "size" */
long *get_long_config_array(struct collection_item *item, int *size, int *error);
/* Array of double values - separators are detected automatically. */
/* The length of the allocated array is returned in "size" */
double *get_double_config_array(struct collection_item *item, int *size, int *error);

/* Special function to free string config array */
void free_string_config_array(char **str_config);
/* Special function to free long config array */
void free_long_config_array(long *array);
/* Special function to free double config array */
void free_double_config_array(double *array);

#endif
