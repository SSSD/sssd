/*
    ELAPI

    Module contains functions related to outputting events in CSV format.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE
#include <errno.h>      /* for errors */
#include <stdlib.h>     /* for free() */
#include <string.h>     /* for strcmp() */

#include "collection.h"
#include "file_fmt_csv.h"
#include "collection_tools.h"
#include "ini_config.h"
#include "trace.h"
#include "config.h"

/* Reasonable size for one event */
/* FIXME: may be it would make sense to make it configurable ? */
#define FILE_CSV_BLOCK      256

/* Calculate the potential size of the item */
static unsigned file_csv_data_len(struct file_csv_cfg *cfg,
                                  int type,
                                  int raw_len)
{
    int serialized_len = 0;

    TRACE_FLOW_STRING("col_get_data_len", "Entry point");

    switch (type) {
    case COL_TYPE_INTEGER:
    case COL_TYPE_UNSIGNED:
    case COL_TYPE_LONG:
    case COL_TYPE_ULONG:
        serialized_len = MAX_LONG_STRING_LEN;
        break;

    case COL_TYPE_STRING:
        if ((cfg->csvqualifier) &&
            (cfg->csvescchar)) serialized_len = raw_len * 2;
        else serialized_len = raw_len;
        break;

    case COL_TYPE_BINARY:
        serialized_len = raw_len * 2;
        break;

    case COL_TYPE_DOUBLE:
        serialized_len = MAX_DOUBLE_STRING_LEN;
        break;

    case COL_TYPE_BOOL:
        serialized_len = MAX_BOOL_STRING_LEN;
        break;

    default:
        serialized_len = 0;
        break;
    }

    if (cfg->csvqualifier) serialized_len += 2;

    TRACE_FLOW_STRING("col_get_data_len","Exit point");
    return (uint32_t)serialized_len;
}

/* Copy data escaping characters */
int file_copy_esc(char *dest,
                  const char *source,
                  unsigned char what_to_esc,
                  unsigned char what_to_use)
{
    int i = 0;
    int j = 0;

    while (source[i]) {
        if ((source[i] == what_to_use) ||
            (source[i] == what_to_esc)) {

            dest[j] = what_to_use;
            j++;

        }
        dest[j] = source[i];
        i++;
        j++;
    }

    return j;
}

/* Serialize item into the csv format */
int file_serialize_csv(struct elapi_data_out *out_data,
                       int type,
                       int length,
                       void *data,
                       void *mode_cfg)
{
    int error = EOK;
    struct file_csv_cfg *cfg;
    uint32_t projected_len;
    uint32_t used_len;
    int first = 1;
    int i;

    TRACE_FLOW_STRING("file_serialize_csv", "Entry");

    cfg = (struct file_csv_cfg *)mode_cfg;

    /* Get projected length of the item */
    projected_len = file_csv_data_len(cfg, type, length);

    TRACE_INFO_NUMBER("Expected data length: ", projected_len);

    /* Make sure we have enough space */
    if (out_data->buffer != NULL) {
        TRACE_INFO_STRING("Not a first time use.", "Adding length overhead");
        if (cfg->csvseparator) projected_len++;
        projected_len += cfg->csvnumsp;
        first = 0;
    }
    else {
        /* Add null terminating zero */
        projected_len++;
    }

    /* Grow buffer if needed */
    error = elapi_grow_data(out_data,
                            projected_len,
                            FILE_CSV_BLOCK);
    if (error) {
        TRACE_ERROR_NUMBER("Error. Failed to allocate memory.", error);
        return error;
    }

    /* Now everything should fit */
    if (!first) {
        /* Add separator if any */
        if (cfg->csvseparator) {
            out_data->buffer[out_data->length] = cfg->csvseparator;
            out_data->length++;
        }

        /* Add spaces if any */
        memset(&out_data->buffer[out_data->length],
               cfg->csvspace,
               cfg->csvnumsp);
    }

    /* Add qualifier */
    if (cfg->csvqualifier) {
        out_data->buffer[out_data->length] = cfg->csvqualifier;
        out_data->length++;
    }

    /* Add the value */
    switch (type) {
    case COL_TYPE_STRING:

        if ((cfg->csvqualifier) && (cfg->csvescchar)) {
            /* Qualify and escape */
            used_len = file_copy_esc((char *)&out_data->buffer[out_data->length],
                                     (const char *)(data),
                                     cfg->csvqualifier,
                                     cfg->csvescchar);
        }
        else {
            /* No escaping so just copy without trailing 0 */
            /* Item's length includes trailing 0 for data items */
            used_len = length - 1;
            memcpy(&out_data->buffer[out_data->length],
                   (const char *)(data),
                   used_len);
        }
        break;

    case COL_TYPE_BINARY:

        for (i = 0; i < length; i++)
            sprintf((char *)&out_data->buffer[out_data->length + i * 2],
                    "%02X", (unsigned int)(((const unsigned char *)(data))[i]));
        used_len = length * 2;
        break;

    case COL_TYPE_INTEGER:
        used_len = sprintf((char *)&out_data->buffer[out_data->length],
                           "%d", *((const int *)(data)));
        break;

    case COL_TYPE_UNSIGNED:
        used_len = sprintf((char *)&out_data->buffer[out_data->length],
                           "%u", *((const unsigned int *)(data)));
        break;

    case COL_TYPE_LONG:
        used_len = sprintf((char *)&out_data->buffer[out_data->length],
                           "%ld", *((const long *)(data)));
        break;

    case COL_TYPE_ULONG:
        used_len = sprintf((char *)&out_data->buffer[out_data->length],
                           "%lu", *((const unsigned long *)(data)));
        break;

    case COL_TYPE_DOUBLE:
        used_len = sprintf((char *)&out_data->buffer[out_data->length],
                           "%.4f", *((const double *)(data)));
        break;

    case COL_TYPE_BOOL:
        used_len = sprintf((char *)&out_data->buffer[out_data->length],
                           "%s",
                           (*((const unsigned char *)(data))) ? "true" : "false");
        break;

    default:
        out_data->buffer[out_data->length] = '\0';
        used_len = 0;
        break;
    }

    /* Adjust length */
    out_data->length += used_len;

    /* Add qualifier */
    if (cfg->csvqualifier) {
        out_data->buffer[out_data->length] = cfg->csvqualifier;
        out_data->length++;
    }

    /* The "length" member of the structure does not account
     * for the 0 symbol but we made sure that it fits
     * when we asked for the memory at the top.
     */
    out_data->buffer[out_data->length] = '\0';

    TRACE_INFO_STRING("Data: ", out_data->buffer);

    TRACE_FLOW_STRING("file_serialize_csv.", "Exit");
    return error;

}

/* Function that reads the specific configuration
 * information about the format of the output
 */
int file_get_csv_cfg(void **storage,
                     const char *name,
                     struct collection_item *ini_config,
                     const char *appname)
{
    int error = EOK;
    struct collection_item *cfg_item = NULL;
    struct file_csv_cfg *cfg= NULL;
    const char *qual;
    const char *sep;
    const char *esc;
    const char *space;

    TRACE_FLOW_STRING("file_get_csv_cfg", "Entry");

    /* Allocate memory for configuration */
    cfg = (struct file_csv_cfg *)malloc(sizeof(struct file_csv_cfg));
    if (cfg == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate storage for CSV configuration", ENOMEM);
        return ENOMEM;
    }

    /*********** Qualifier *************/

    /* Get qualifier */
    error = get_config_item(name,
                            FILE_CSV_QUAL,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read qualifier attribute returned error", error);
        free(cfg);
        return error;
    }

    /* Do we have qualifier? */
    if (cfg_item == NULL) {
        /* There is no qualifier - use default */
        cfg->csvqualifier = FILE_CSV_DEF_QUAL;
    }
    else {
        /* Get qualifier from configuration */
        error = EOK;
        qual = get_const_string_config_value(cfg_item, &error);
        if (error) {
            TRACE_ERROR_STRING("Failed to get value from configuration.", "Fatal Error!");
            free(cfg);
            return error;
        }

        if (qual[0] == '\0') cfg->csvqualifier = '\0';
        else if(qual[1] != '\0') {
            TRACE_ERROR_STRING("Qualifier has more than one symbol.", "Fatal Error!");
            free(cfg);
            return EINVAL;
        }
        else cfg->csvqualifier = qual[0];
    }

    /*********** Separator *************/

    /* Get separator */
    error = get_config_item(name,
                            FILE_CSV_SEP,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read separator attribute returned error", error);
        free(cfg);
        return error;
    }

    /* Do we have separator? */
    if (cfg_item == NULL) {
        /* There is no separator - use default */
        cfg->csvseparator = FILE_CSV_DEF_SEP;
    }
    else {
        /* Get separator from configuration */
        error = EOK;
        sep = get_const_string_config_value(cfg_item, &error);
        if (error) {
            TRACE_ERROR_STRING("Failed to get value from configuration.", "Fatal Error!");
            free(cfg);
            return error;
        }

        if (sep[0] == '\0') cfg->csvseparator = '\0';
        else if(sep[1] != '\0') {
            TRACE_ERROR_STRING("Separator has more than one symbol.", "Fatal Error!");
            free(cfg);
            return EINVAL;
        }
        else cfg->csvseparator = sep[0];
    }

    /*********** Escape symbol *************/

    /* Get escape symbol */
    error = get_config_item(name,
                            FILE_CSV_ESCSYM,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read esc symbol attribute returned error", error);
        free(cfg);
        return error;
    }

    /* Do we have esc symbol? */
    if (cfg_item == NULL) {
        /* There is no esc symbol - use default */
        cfg->csvescchar = FILE_CSV_DEF_ESC;
    }
    else {
        /* Get esc symbol from configuration */
        error = EOK;
        esc = get_const_string_config_value(cfg_item, &error);
        if (error) {
            TRACE_ERROR_STRING("Failed to get value from configuration.", "Fatal Error!");
            free(cfg);
            return error;
        }

        if (esc[0] == '\0') cfg->csvescchar = '\0';
        else if(esc[1] != '\0') {
            TRACE_ERROR_STRING("Esc symbol has more than one symbol.", "Fatal Error!");
            free(cfg);
            return EINVAL;
        }
        else cfg->csvescchar = esc[0];
    }

    /*********** Space *************/

    /* Get space */
    error = get_config_item(name,
                            FILE_CSV_SPACE,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read space attribute returned error", error);
        free(cfg);
        return error;
    }

    /* Do we have space? */
    if (cfg_item == NULL) {
        /* There is no esc symbol - use default */
        cfg->csvspace = FILE_CSV_DEF_SPC;
    }
    else {
        /* Get file name from configuration */
        error = EOK;
        space = get_const_string_config_value(cfg_item, &error);
        if (error) {
            TRACE_ERROR_STRING("Failed to get value from configuration.", "Fatal Error!");
            free(cfg);
            return error;
        }

        /* Determine what to use as a space symbol */
        if (space[0] == '\0') cfg->csvspace = ' ';
        else if(strcmp(space, FILE_CSV_SP) == 0) cfg->csvspace = ' ';
        else if(strcmp(space, FILE_CSV_TAB) == 0) cfg->csvspace = '\t';
        else if(strcmp(space, FILE_CSV_CR) == 0) cfg->csvspace = '\n';
        else {
            TRACE_ERROR_STRING("Esc symbol has more than one symbol.", "Fatal Error!");
            free(cfg);
            return EINVAL;
        }
    }

    /*********** Number of spaces *************/
    /* Get number of spaces */

    cfg_item = NULL;
    error = get_config_item(name,
                            FILE_CSV_NUMSP,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read number of spaces attribute returned error", error);
        free(cfg);
        return error;
    }

    /* Do we have number of spaces? */
    if (cfg_item == NULL) {
        /* There is no attribute - assume default */
        TRACE_INFO_STRING("No attribute.", "Assume no spaces");
        cfg->csvnumsp = 0;
    }
    else {
        cfg->csvnumsp = (uint32_t) get_unsigned_config_value(cfg_item, 1, 0, &error);
        if (error) {
            TRACE_ERROR_STRING("Invalid number of spaces value", "Fatal Error!");
            free(cfg);
            return EINVAL;
        }
        /* Check for right range */
        if (cfg->csvnumsp > FILE_MAXSPACE) {
            TRACE_ERROR_STRING("Too many spaces - not allowed", "Fatal Error!");
            free(cfg);
            return ERANGE;
        }
    }

    /*********** Header *************/
    /* Next is header field */

    cfg_item = NULL;
    error = get_config_item(name,
                            FILE_CSV_HEADER,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read header attribute returned error", error);
        free(cfg);
        return error;
    }

    /* Do we have header? */
    if (cfg_item == NULL) {
        /* There is no attribute - assume default */
        TRACE_INFO_STRING("No attribute.", "Assume no header");
        cfg->csvheader = 0;
    }
    else {
        cfg->csvheader = (uint32_t) get_bool_config_value(cfg_item, '\0', &error);
        if (error) {
            TRACE_ERROR_STRING("Invalid csv header value", "Fatal Error!");
            free(cfg);
            return EINVAL;
        }
    }

    *((struct file_csv_cfg **)storage) = cfg;

    TRACE_FLOW_STRING("file_get_csv_cfg", "Entry");
    return error;
}

#ifdef ELAPI_VERBOSE

void file_print_fmt_csv(void *data)
{
    struct file_csv_cfg *cfg;

    cfg = (struct file_csv_cfg *)(data);
    if (cfg == NULL) {
        printf("CSV Configuration is undefined!\n");
        return;
    }

    printf("CSV Configuration:\n");
    printf("  Qualifier: ");
    if (cfg->csvqualifier != '\0') printf("[%c]\n", cfg->csvqualifier);
    else printf("[undefined]\n");

    printf("  Separator: ");
    if (cfg->csvseparator != '\0') printf("[%c]\n", cfg->csvseparator);
    else printf("[undefined]\n");

    printf("  Escape: ");
    if (cfg->csvescchar != '\0') printf("[%c]\n", cfg->csvescchar);
    else printf("[undefined]\n");

    printf("  Space: [%c] [ASCII: %d]\n", cfg->csvspace, (int)(cfg->csvspace));
    printf("  Number of spaces: [%d]\n", cfg->csvnumsp);
    printf("  Header: [%s]\n", ((cfg->csvheader > 0) ? "yes" : "no"));
    printf("CSV Configuration END\n");

}
#endif
