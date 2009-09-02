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

#ifndef ELAPI_FILE_FMT_CSV_H
#define ELAPI_FILE_FMT_CSV_H

#include <stdint.h>
#include "collection.h"
#include "elapi_basic.h"

/* Format specific configuration parameters */
/* CSV:                                     */
#define FILE_CSV_QUAL       "csvqual"
#define FILE_CSV_SEP        "csvsep"
#define FILE_CSV_ESCSYM     "csvescsym"
#define FILE_CSV_SPACE      "csvspace"
#define FILE_CSV_NUMSP      "csvnumsp"
#define FILE_CSV_HEADER     "csvheader"

/* Strings from config that will be recognized */
#define FILE_CSV_SP         "space"
#define FILE_CSV_TAB        "tab"
#define FILE_CSV_CR         "cr"


/* Default values for configuration parameters */
#define FILE_CSV_DEF_QUAL   '"'
#define FILE_CSV_DEF_SEP    ','
#define FILE_CSV_DEF_ESC    '\\'
#define FILE_CSV_DEF_SPC    ' '

/* Try catch corrupted configuration 80 is more than enough */
#define FILE_MAXSPACE   80

/* Configuration for the CSV output */
struct file_csv_cfg {
    uint32_t csvheader;             /* Include csv header or not? */
    uint32_t csvnumsp;              /* How many spaces ? */
    unsigned char csvqualifier;     /* What is the qualifier? */
    unsigned char csvseparator;     /* What is the separator? */
    unsigned char csvescchar;       /* What is the escape character? */
    unsigned char csvspace;         /* What is the space character? */
};

/* Function that reads the specific configuration
 * information about the CSV format of the output
 */
int file_get_csv_cfg(void **storage,
                     const char *name,
                     struct collection_item *ini_config,
                     const char *appname);

/* Serialize an item into the csv format */
int file_serialize_csv(struct elapi_data_out *out_data,
                       int type,
                       int length,
                       void *data,
                       void *mode_cfg);


#ifdef ELAPI_VERBOSE
/* Function for debugging */
void file_print_fmt_csv(void *data);

#endif
#endif
