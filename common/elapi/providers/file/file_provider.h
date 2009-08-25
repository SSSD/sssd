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

/* Structure that holds internal configuration of the file
 * provider.
 */
struct file_prvdr_cfg {
    char *filename;                 /* File name */
    uint32_t keepopen;              /* Do we need to keep file open */
    uint32_t fsyncmode;             /* How frequently data is fsynced */
    uint32_t outmode;               /* Output mode */
    struct collection_item *set;    /* Field set without leftovers symbol */
    uint32_t use_leftovers;         /* Was there a leftover symbol */
    uint32_t jam_leftovers;         /* leftovers should be serialized into one field */
    uint32_t mode_leftovers;        /* Format for the leftover fields */
    uint32_t csvheader;             /* Include csv header or not? */
    char csvqualifier;              /* What is the qualifier? */
    char csvseparator;              /* What is the separator? */
    uint32_t csvescape;             /* Do we need to escape strings ? */
    char csvescchar;                /* What is the escape character? */
};

/* File context */
struct file_prvdr_ctx {
    struct file_prvdr_cfg config; /* Configuration */
    int outfile;                  /* File handle */
    /* FIXME - other things go here */
};



/* Function to read configuration */
int file_read_cfg(struct file_prvdr_cfg *file_cfg,
                  char *name,
                  struct collection_item *ini_config);

/* Function to create context */
int file_create_ctx(struct file_prvdr_ctx **file_ctx,
                    char *name,
                    struct collection_item *ini_config);

/* File init function */
int file_init(void **priv_ctx,
              char *name,
              struct collection_item *ini_config);

/* File close function */
void file_close(void **priv_ctx);

/* File submit function */
int file_submit(void *priv_ctx, struct collection_item *event);

/* This is the equivalent of the get info function */
void file_ability(struct sink_cpb *cpb_block);

#endif
