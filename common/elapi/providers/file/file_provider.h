/*
    ELAPI

    Header file used internally by the "file" provider.

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

#ifndef ELAPI_FILE_PROVIDER_H
#define ELAPI_FILE_PROVIDER_H

#include <stdint.h>

#include "elapi_sink.h"

/* Common configuration parameters */
#define FILE_OUTNAME        "filename"
#define FILE_KEEPOPEN       "keepopen"
#define FILE_OUTMODE        "outmode"
#define FILE_FIELDSET       "set"
#define FILE_FORMAT         "format"
#define FILE_FLUSH          "fsyncmode"


/* Max supported mode */
/* NOTE: Increase this value when you add a new mode.
 * If it ever gets to 10 the logic in the
 * function that builds the set needs to change.
 */
#define FILE_MAXMODE        5
/* Modes: */
#define FILE_MODE_CSV       0
#define FILE_MODE_FORMAT    1
#define FILE_MODE_HTML      2
#define FILE_MODE_XML       3
#define FILE_MODE_JSON      4
#define FILE_MODE_KVP       5


/* FIXME: Should it be a compile time switch? */
#define FILE_SUFFIX ".log"
#define FILE_SET_END '@'

/* Field set collection */
#define FILE_FIELDSET_COL   "set"
#define FILE_FIELDSET_CLASS  21000

/* Special file name - stderr is handled differently */
#define FILE_STDERR "stderr"

/* Structure that holds internal configuration of the file
 * provider.
 */
struct file_prvdr_cfg {
    char *filename;                 /* File name */
    uint32_t ownfile;               /* Do I own the file handle? */
    uint32_t keepopen;              /* Do we need to keep file open */
    int32_t fsyncmode;              /* How frequently data is fsynced */
    uint32_t outmode;               /* Output mode */
    struct collection_item *set;    /* Field set without leftovers symbol */
    uint32_t use_leftovers;         /* Was there a leftover symbol */
    uint32_t jam_leftovers;         /* leftovers should be serialized into one field */
    uint32_t mode_leftovers;        /* Format for the leftover fields */
    void *main_fmt_cfg;             /* Configuration data for the main format */
    void *lo_fmt_cfg;               /* Configuration data for leftovers format */
    /* FIXME add other config data strutures here */

    /* FIXME: Rotation rules ? */
};


/* File context */
struct file_prvdr_ctx {
    struct file_prvdr_cfg config; /* Configuration */
    int outfile;                  /* File handle */
    uint32_t smode;               /* Sink's synch mode */
    /* FIXME - other things go here */
};

/* File init function */
int file_init(void **priv_ctx,
              const char *name,
              struct collection_item *ini_config,
              const char *appname);

/* File close function */
void file_close(void **priv_ctx);

/* File submit function */
int file_submit(void *priv_ctx, struct collection_item *event);

/* This is the equivalent of the get info function */
void file_ability(struct sink_cpb *cpb_block);

#endif
