/*
    ELAPI

    Module implements a provider for sinks based on file.

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

#include "file_provider.h"
#include "ini_config.h"
#include "trace.h"
#include "config.h"
/* FIXME: temporary for debugging */
#include "collection_tools.h"


/* Function to read configuration */
int file_read_cfg(struct file_prvdr_cfg *file_cfg,
                  char *name,
                  struct collection_item *ini_config)
{
    int error = EOK;
    TRACE_FLOW_STRING("file_read_cfg", "Entry point");

    /* FIXME: read configuration items */

    TRACE_FLOW_STRING("file_read_cfg", "Exit");
    return error;
}


/* Function to create context */
int file_create_ctx(struct file_prvdr_ctx **file_ctx,
                    char *name,
                    struct collection_item *ini_config)
{
    int error = EOK;
    struct file_prvdr_ctx *ctx = NULL;

    TRACE_FLOW_STRING("file_create_ctx", "Entry point");

    ctx = (struct file_prvdr_ctx *)malloc(sizeof(struct file_prvdr_ctx));
    if (ctx == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate context", ENOMEM);
        return ENOMEM;
    }

    /* Init allocatable items */
    ctx->config.filename = NULL;

    /* Read configuration data */
    error = file_read_cfg(&(ctx->config), name, ini_config);
    if (error) {
        TRACE_ERROR_NUMBER("Error reading sink configuration", error);
        free(ctx);
        return error;
    }

    *file_ctx = ctx;

    TRACE_FLOW_STRING("file_create_ctx", "Exit");
    return error;
}


/* File init function */
int file_init(void **priv_ctx,
              char *name,
              struct collection_item *ini_config)
{
    int error = EOK;
    TRACE_FLOW_STRING("file_init", "Entry point");

    /* Start with creating context */
    error = file_create_ctx((struct file_prvdr_ctx **)priv_ctx,
                            name,
                            ini_config);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to create context", error);
        return error;
    }

	/* Open file */
    /* FIXME: ... */

    TRACE_FLOW_STRING("file_init", "Exit");
    return error;
}

/* File close function */
void file_close(void **priv_ctx)
{
    struct file_prvdr_ctx **ctx = NULL;

    TRACE_FLOW_STRING("file_close", "Entry point");

    ctx = (struct file_prvdr_ctx **)priv_ctx;

    /* Close file */
    /* FIXME: ... */

    /* If we allocated file name free it */
    if ((*ctx)->config.filename != NULL) {
        TRACE_INFO_STRING("Freeing file name", (*ctx)->config.filename);
        free((*ctx)->config.filename);
    }

    /* Free and indicate that the context is freed */
    free(*ctx);
    *ctx = NULL;

    TRACE_FLOW_STRING("file_close", "Exit");
}

/* File submit function */
int file_submit(void *priv_ctx, struct collection_item *event)
{
    int error = EOK;
    TRACE_FLOW_STRING("file_submit", "Entry point");


    /* FIXME: Placeholder for now */
    col_print_collection(event);

    TRACE_FLOW_STRING("file_sumbit", "Exit");
    return error;
}


/* This is the equivalent of the get info function */
void file_ability(struct sink_cpb *cpb_block)
{
    TRACE_FLOW_STRING("file_ability", "Entry point");

    cpb_block->init_cb = file_init;
    cpb_block->submit_cb = file_submit;
    cpb_block->close_cb = file_close;

    TRACE_FLOW_STRING("file_ability", "Exit");
}
