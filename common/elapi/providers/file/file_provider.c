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
#include <string.h>     /* for strlen() */
#include <unistd.h>     /* for close() */

#include "file_provider.h"
#include "file_util.h"
#include "file_fmt_csv.h"
#include "ini_config.h"
#include "trace.h"
#include "config.h"

/* NOTE: Each format module has its own header */
#include "file_fmt_csv.h"
/* Add headers for new formats here... */

/*******************************************************************/
/* SECTION FOR INTERNAL CONDITIONALLY COMPILED DEBUGGING FUNCTIONS */
/*******************************************************************/
#ifdef ELAPI_VERBOSE
#include "collection_tools.h"

/* Function to debug format configurations */
void file_print_fmt_cfg(uint32_t mode, void *fmt_cfg)
{
    switch(mode) {
    case FILE_MODE_CSV:
        file_print_fmt_csv(fmt_cfg);
        break;
    /* FIXME : add other formats later */
/*
    case FILE_MODE_FORMAT:
        error = file_print_fmt_format(fmt_cfg);
        break;
    case FILE_MODE_HTML:
        error = file_print_fmt_html(fmt_cfg);
        break;
    case FILE_MODE_XML:
        error = file_print_fmt_xml(fmt_cfg);
        break;
    case FILE_MODE_JSON:
        error = file_print_fmt_json(fmt_cfg);
        break;
    case FILE_MODE_KVP:
        error = file_print_fmt_kvp(fmt_cfg);
        break;
*/
    default:
        printf("Unsupported mode!\n");
    }
}


/* Function for debugging configuration */
void file_print_cfg(struct file_prvdr_cfg *cfg)
{
    printf("File provider configuration\n");

    printf("  File name: [%s]\n", ((cfg->filename != NULL) ? cfg->filename : "NULL"));
    printf("  Own file : [%s]\n", ((cfg->ownfile > 0) ? "yes" : "no"));
    printf("  Keep open: [%s]\n", ((cfg->keepopen > 0) ? "yes" : "no"));

    if (cfg->fsyncmode == 0) {
        printf("  Sync mode: [no flush]\n");
    }
    else if (cfg->fsyncmode > 0) {
        printf("  Sync mode: every [%d] event\n", cfg->fsyncmode);
    }
    else {
        printf("  Sync mode: every [%d] second\n", 0 - cfg->fsyncmode);
    }

    if (cfg->set) {
        printf("  There is a set of predefined fields\n");
        col_print_collection(cfg->set);
        printf("  Use leftovers: [%s]\n", ((cfg->use_leftovers > 0) ? "yes" : "no"));
        printf("  Jam leftovers: [%s]\n", ((cfg->jam_leftovers > 0) ? "yes" : "no"));
        if (cfg->use_leftovers > 0) {
            printf("Leftovers configuration:\n");
            file_print_fmt_cfg(cfg->mode_leftovers, cfg->lo_fmt_cfg);
            printf("Leftovers configuration END\n");
        }
    }
    else printf("All fields go into the output.\n");


    printf("Main configuration:\n");
    file_print_fmt_cfg(cfg->outmode, cfg->main_fmt_cfg);
    printf("Main configuration END:\n");

    printf("File provider configuration END\n");

}

/* Function to debug context */
void file_print_ctx(struct file_prvdr_ctx *ctx)
{
    if (ctx == NULL) {
        printf("No file provider context!\n");
        return;
    }

    printf("File Provider Context\n");

    /* Print configuration */
    file_print_cfg(&(ctx->config));

    /* Print other parts of the context */
    printf("File is currently: [%s]\n", ((ctx->outfile >= 0) ? "open" : "closed"));
    printf("File Provider Context END\n\n");

}
#endif

/*******************************************************************/
/*                     MAIN MODULE FUNCTIONS                       */
/*******************************************************************/

/* Function that reads the specific configuration
 * information about the format of the output
 */
static int file_read_fmt_cfg(void **storage,
                             uint32_t mode,
                             const char *name,
                             struct collection_item *ini_config,
                             const char *appname)
{
    int error = EOK;

    TRACE_FLOW_STRING("file_read_fmt_cfg", "Entry");

    switch(mode) {
    case FILE_MODE_CSV:
        error = file_get_csv_cfg(storage, name, ini_config, appname);
        break;
    /* FIXME : add other formats later */
/*
    case FILE_MODE_FORMAT:
        error = file_get_format_cfg(storage, name, ini_config, appname);
        break;
    case FILE_MODE_HTML:
        error = file_get_html_cfg(storage, name, ini_config, appname);
        break;
    case FILE_MODE_XML:
        error = file_get_xml_cfg(storage, name, ini_config, appname);
        break;
    case FILE_MODE_JSON:
        error = file_get_json_cfg(storage, name, ini_config, appname);
        break;
    case FILE_MODE_KVP:
        error = file_get_kvp_cfg(storage, name, ini_config, appname);
        break;
*/
    default:
        TRACE_ERROR_STRING("Unsupported mode", "Fatal error!");
        error = EINVAL;

    }
    TRACE_FLOW_NUMBER("file_read_fmt_cfg. Exit. Returning:", error);
    return error;
}

/* Function to build the set object from the configuration data */
static int file_build_set(struct file_prvdr_cfg *file_cfg,
                          struct collection_item *cfg_item)
{
    int error = EOK;
    char **fields;
    char *field;
    int size;
    int count;
    struct collection_item *dummy = NULL;
    struct collection_item *set = NULL;

    TRACE_FLOW_STRING("file_build_set", "Entry");

    /* Get fields array from config field */
    fields = get_string_config_array(cfg_item, NULL, &size, &error);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to get set items returned error", error);
        return error;
    }

    if (size > 0) {

        TRACE_INFO_STRING("We have the set of required fields", "");

        /* Create collection */
        error = col_create_collection(&set, FILE_FIELDSET_COL, FILE_FIELDSET_CLASS);
        if (error) {
            TRACE_ERROR_NUMBER("Attempt to create collection failed", error);
            return error;
        }

        for (count = 0; count < size; count++) {
            field = fields[count];
            TRACE_INFO_STRING("FIELD:", field);

            if (field[0] == FILE_SET_END) {
                TRACE_INFO_STRING("Leftovers field found.", "");
                if (count != (size - 1)) {
                    /* We found an end list field in the middle - error */
                    TRACE_ERROR_NUMBER("More fields after end list field.", EINVAL);
                    col_destroy_collection(set);
                    free_string_config_array(fields);
                    return EINVAL;
                }

                file_cfg->use_leftovers = 1;

                /* What format to use leftovers ? */
                /* NOTE: Is we ever support more than 10 formats
                 * this logic needs to change
                 */
                if ((field[1] >= '0') &&
                    (field[1] <= ('0' + FILE_MAXMODE)) &&
                    (field[2] == '\0')) {
                    /* We have a format specifier */
                    file_cfg->mode_leftovers = (uint32_t)(field[1] - '0');
                    file_cfg->jam_leftovers = 1;
                    TRACE_INFO_NUMBER("Use mode for leftovers:", file_cfg->mode_leftovers);
                }
                else {
                    /* Wrong format */
                    TRACE_ERROR_NUMBER("Leftover field has invalid format.", EINVAL);
                    col_destroy_collection(set);
                    free_string_config_array(fields);
                    return EINVAL;
                }

            }
            else {
                error = col_add_binary_property(set,
                                                NULL,
                                                field,
                                                &dummy,
                                                sizeof(struct collection_item *));
                if (error) {
                    TRACE_ERROR_NUMBER("Error adding item to the set.", error);
                    col_destroy_collection(set);
                    free_string_config_array(fields);
                    return error;
                }
            }
        }

        file_cfg->set = set;
    }

    /* Free the list */
    free_string_config_array(fields);

    TRACE_FLOW_STRING("file_build_set", "Exit");
    return error;
}


/* Function to read configuration */
static int file_read_cfg(struct file_prvdr_cfg *file_cfg,
                         const char *name,
                         struct collection_item *ini_config,
                         const char *appname)
{
    int error = EOK;
    struct collection_item *cfg_item = NULL;
    const char *filename;
    int use_default_name = 0;

    TRACE_FLOW_STRING("file_read_cfg", "Entry point");

    /*********** Filename *************/

    /* Get file name */
    error = get_config_item(name,
                            FILE_OUTNAME,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read \"filename\" attribute returned error", error);
        return error;
    }

    /* Do we have file name? */
    if (cfg_item == NULL) use_default_name = 1;
    else {
        /* Get file name from configuration */
        error = EOK;
        filename = get_const_string_config_value(cfg_item, &error);
        if (error) {
            TRACE_ERROR_STRING("Failed to get value from configuration.", "Fatal Error!");
            return error;
        }
        /* Check if file name is empty */
        if (filename[0] == '\0') use_default_name = 1;
        else {
            /* Now get a copy */
            file_cfg->filename = get_string_config_value(cfg_item, &error);
            if (error) {
                TRACE_ERROR_STRING("Failed to copy value from configuration.", "Fatal Error!");
                return error;
            }
        }
    }

    if (use_default_name) {
        /* There is no file name - use default */
        file_cfg->filename = malloc(strlen(appname) + sizeof(FILE_SUFFIX));
        if (file_cfg->filename == NULL) {
            TRACE_ERROR_STRING("Failed to allocate memory for file name.", "Fatal Error!");
            return ENOMEM;
        }
        /* Appname is validated in the elapi_log.c */
        /* This should be safe to do */
        strcpy(file_cfg->filename, appname);
        strcat(file_cfg->filename, FILE_SUFFIX);

        file_cfg->ownfile = 1;
    }
    else if (strcmp(filename, FILE_STDERR) != 0) file_cfg->ownfile = 1;
    else file_cfg->ownfile = 0;

    /*********** Keep open *************/
    /* Next is "keepopen" field */

    cfg_item = NULL;
    error = get_config_item(name,
                            FILE_KEEPOPEN,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read \"keepopen\" attribute returned error", error);
        return error;
    }

    /* Do we have "keepopen"? */
    if (cfg_item == NULL) {
        /* There is no attribute - assume default */
        TRACE_INFO_STRING("No \"keepopen\" attribute.", "Assume open on each entry");
        file_cfg->keepopen = 0;
    }
    else {
        file_cfg->keepopen = (uint32_t) get_bool_config_value(cfg_item, '\0', &error);
        if (error) {
            TRACE_ERROR_STRING("Invalid \"keepopen\" value", "Fatal Error!");
            return EINVAL;
        }
    }

    /*********** Outmode *************/
    /* Next is "outmode" field */

    cfg_item = NULL;
    error = get_config_item(name,
                            FILE_OUTMODE,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read \"outmode\" attribute returned error", error);
        return error;
    }

    /* Do we have "outmode"? */
    if (cfg_item == NULL) {
        /* There is no attribute - assume default */
        TRACE_INFO_STRING("No \"outmode\" attribute.", "Assume CSV kind");
        file_cfg->outmode = 0;
    }
    else {
        file_cfg->outmode = (uint32_t) get_unsigned_config_value(cfg_item, 1, 0, &error);
        if (error) {
            TRACE_ERROR_STRING("Invalid \"outmode\" value", "Fatal Error!");
            return EINVAL;
        }
        /* Check for right range */
        if (file_cfg->outmode > FILE_MAXMODE) {
            TRACE_ERROR_STRING("Invalid \"outmode\" value - out of range", "Fatal Error!");
            return ERANGE;
        }
    }

    /*********** Sync mode *************/
    /* Next is sync mode field */

    cfg_item = NULL;
    error = get_config_item(name,
                            FILE_FLUSH,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read \"fsyncmode\" attribute returned error", error);
        return error;
    }

    /* Do we have "fsyncmode"? */
    if (cfg_item == NULL) {
        /* There is no attribute - assume default */
        TRACE_INFO_STRING("No \"fsyncmode\" attribute.", "Assume CSV kind");
        file_cfg->fsyncmode = 0;
    }
    else {
        file_cfg->fsyncmode = (int32_t) get_int_config_value(cfg_item, 1, 0, &error);
        if (error) {
            TRACE_ERROR_STRING("Invalid \"fsyncmode\" value", "Fatal Error!");
            return EINVAL;
        }
    }

    /*********** Set *************/
    /* Next is the "set" field */
    cfg_item = NULL;
    error = get_config_item(name,
                            FILE_FIELDSET,
                            ini_config,
                            &cfg_item);
    if (error) {
        TRACE_ERROR_NUMBER("Attempt to read \"set\" attribute returned error", error);
        return error;
    }

    file_cfg->use_leftovers = 0;
    file_cfg->jam_leftovers = 0;
    file_cfg->mode_leftovers = file_cfg->outmode;

    /* Do we have "required"? */
    if (cfg_item == NULL) {
        /* There is no attribute - assume default */
        TRACE_INFO_STRING("No \"set\" attribute.", "Assume all fields as specified");
        file_cfg->set = NULL;
    }
    else {
        error = file_build_set(file_cfg, cfg_item);
        if (error) {
            TRACE_ERROR_STRING("Invalid \"set\" value", "Fatal Error!");
            return EINVAL;
        }
    }

    /*********** Format specific configurations *************/
    /* Read the main format configuration details */
    error = file_read_fmt_cfg((void **)(&(file_cfg->main_fmt_cfg)),
                              file_cfg->outmode,
                              name,
                              ini_config,
                              appname);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to read main format configuration", error);
        return error;
    }

    if (file_cfg->use_leftovers) {
        /* If we use same mode for leftovers and main do not read things again */
        if (file_cfg->mode_leftovers == file_cfg->outmode) {
            TRACE_INFO_STRING("Output modes are the same", "");
            file_cfg->lo_fmt_cfg = file_cfg->main_fmt_cfg;
        }
        else {
            TRACE_INFO_STRING("Output modes are the different", "");
            TRACE_INFO_NUMBER("Main mode", file_cfg->outmode);
            TRACE_INFO_NUMBER("Left over's mode", file_cfg->mode_leftovers);

            /* Read the leftover's format configuration details */
            error = file_read_fmt_cfg((void **)(&(file_cfg->lo_fmt_cfg)),
                                      file_cfg->mode_leftovers,
                                      name,
                                      ini_config,
                                      appname);
            if (error) {
                TRACE_ERROR_NUMBER("Failed to read main format configuration", error);
                return error;
            }
        }
    }
    TRACE_FLOW_STRING("file_read_cfg", "Exit");
    return error;
}

/* Function to destroy the context */
static void file_destroy_ctx(struct file_prvdr_ctx **file_ctx)
{
    TRACE_FLOW_STRING("file_destroy_ctx", "Entry");

    if ((file_ctx) && (*file_ctx)) {
        /* Close file if it is open */
        if (((*file_ctx)->outfile >= 0) && ((*file_ctx)->config.ownfile)) {
            TRACE_INFO_STRING("File was open", "");
            close((*file_ctx)->outfile);
        }

        /* Free file name if it is not NULL */
        if ((*file_ctx)->config.filename) {
            TRACE_INFO_STRING("Freeing file name", (*file_ctx)->config.filename);
            free((*file_ctx)->config.filename);
        }

        /* Free set if any */
        if ((*file_ctx)->config.set) {
            TRACE_INFO_NUMBER("Freeing set", (*file_ctx)->config.set);
            col_destroy_collection((*file_ctx)->config.set);
        }

        /* Free main format configuration if it is not NULL */
        if (((*file_ctx)->config.main_fmt_cfg) &&
            ((*file_ctx)->config.main_fmt_cfg != (*file_ctx)->config.lo_fmt_cfg)) {
            TRACE_INFO_NUMBER("Freeing main format config.", (*file_ctx)->config.main_fmt_cfg);
            free((*file_ctx)->config.main_fmt_cfg);
        }

        /* Free left over format configuration if it is not NULL */
        if ((*file_ctx)->config.lo_fmt_cfg) {
            TRACE_INFO_NUMBER("Freeing leftover format config.", (*file_ctx)->config.lo_fmt_cfg);
            free((*file_ctx)->config.lo_fmt_cfg);
        }

        TRACE_FLOW_STRING("Freeing file context", "Entry");
        free(*file_ctx);
        *file_ctx = NULL;
    }

    TRACE_FLOW_STRING("file_destroy_ctx", "Exit");
}

/* Function to create context */
static int file_create_ctx(struct file_prvdr_ctx **file_ctx,
                           const char *name,
                           struct collection_item *ini_config,
                           const char *appname)
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
    ctx->config.main_fmt_cfg = NULL;
    ctx->config.lo_fmt_cfg = NULL;
    ctx->outfile = -1;

    /* Read configuration data */
    error = file_read_cfg(&(ctx->config), name, ini_config, appname);
    if (error) {
        TRACE_ERROR_NUMBER("Error reading sink configuration", error);
        file_destroy_ctx(&ctx);
        return error;
    }

    *file_ctx = ctx;

    TRACE_FLOW_STRING("file_create_ctx", "Exit");
    return error;
}


/* File init function */
int file_init(void **priv_ctx,
              const char *name,
              struct collection_item *ini_config,
              const char *appname)
{
    int error = EOK;
    TRACE_FLOW_STRING("file_init", "Entry point");

    /* Start with creating context */
    error = file_create_ctx((struct file_prvdr_ctx **)priv_ctx,
                            name,
                            ini_config,
                            appname);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to create context", error);
        return error;
    }

    /* Open file */
    /* FIXME: ... */

#ifdef ELAPI_VERBOSE
    printf("Initializaing file provider for sink: [%s]\n", name);
    file_print_ctx(*((struct file_prvdr_ctx **)priv_ctx));
#endif

    TRACE_FLOW_STRING("file_init", "Exit");
    return error;
}

/* File close function */
void file_close(void **priv_ctx)
{
    struct file_prvdr_ctx **ctx = NULL;

    TRACE_FLOW_STRING("file_close", "Entry point");

    ctx = (struct file_prvdr_ctx **)priv_ctx;

#ifdef ELAPI_VERBOSE
    file_print_ctx(*ctx);
#endif

    file_destroy_ctx(ctx);

    TRACE_FLOW_STRING("file_close", "Exit");
}

/* File submit function */
int file_submit(void *priv_ctx, struct collection_item *event)
{
    int error = EOK;
    struct file_prvdr_ctx *ctx = (struct file_prvdr_ctx *)priv_ctx;
    struct elapi_data_out *out_data;

    TRACE_FLOW_STRING("file_submit", "Entry point");

#ifdef ELAPI_VERBOSE
    file_print_ctx(ctx);

    /* FIXME: Placeholder for now */
    col_print_collection(event);
#endif

    /* FIXME: Open file here if it is closed */

    error = file_prep_data(&out_data, ctx, event);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to prepare data", error);
        return error;
    }

    /* FIXME: just print it for now!!! */

    printf("EVENT: [%*s]\n", out_data->length, out_data->buffer);


    /* FIXME: write data base on the synch or not synch mode of the sink */
    /* For now we will just assume synch */
    /* This function will probably be a part of the common callbacks */
    /* elapi_write_to_fd(out_data, ctx_>outfile); */

    /* This one is temporary here too */
    elapi_free_serialized_data(out_data);

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
