/*
    INI LIBRARY

    Parsing functions of the INI interface

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
#include "config.h"
/* For error text */
#include <libintl.h>
#define _(String) gettext (String)
/* INI file is used as a collection */
#include "trace.h"
#include "collection.h"
#include "collection_tools.h"
#include "ini_defines.h"
#include "ini_config.h"


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
