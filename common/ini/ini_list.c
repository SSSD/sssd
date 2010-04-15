/*
    INI LIBRARY

    Value interpretation functions for single values
    and corresponding memory cleanup functions.

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
#include <stdio.h>
#include <errno.h>
/*
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <locale.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
*/
#include "config.h"
#include "trace.h"
#include "collection.h"
#include "collection_tools.h"
#include "ini_config.h"


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
    TRACE_FLOW_STRING("free_attribute_list","Entry");

    col_free_property_list(section_list);

    TRACE_FLOW_STRING("free_attribute_list","Exit");
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
