/*
    INI LIBRARY

    Object to handle comments

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
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include "config.h"
#include "trace.h"
#include "ref_array.h"
#include "ini_comment.h"

/* The lines will increment in this number */
#define INI_COMMENT_BLOCK 10

/***************************/
/* Internal comment states */
/***************************/
/* Empty - initial */
#define INI_COMMENT_EMPTY   0
/* Read - read from file */
#define INI_COMMENT_READ    1
/* Comment was altered */
#define INI_COMMENT_CHANGED 2


/*********************************/
/* Modes to wrap ref array calls */
/*********************************/
#define INI_COMMENT_MODE_BUILD      1
#define INI_COMMENT_MODE_APPEND     2
#define INI_COMMENT_MODE_INSERT     3
#define INI_COMMENT_MODE_REPLACE    4
#define INI_COMMENT_MODE_REMOVE     5
#define INI_COMMENT_MODE_CLEAR      6

/****************************************/
/* Internal structure to hold a comment */
/****************************************/
struct ini_comment {
    struct ref_array *ra;
    uint32_t state;
};


/****************************************/

/* Destroy the comment object */
void ini_comment_destroy(struct ini_comment *ic)
{

    TRACE_FLOW_STRING("ini_comment_destroy", "Entry");
    if (ic) {
        /* Function will check for NULL */
        ref_array_destroy(ic->ra);
        free(ic);
    }
    TRACE_FLOW_STRING("ini_comment_destroy", "Exit");
}


/* Cleanup callback */
void ini_comment_cb(void *elem,
                    ref_array_del_enum type,
                    void *data)
{

    TRACE_FLOW_STRING("ini_comment_cb", "Entry");
    free(*((char **)elem));
    TRACE_FLOW_STRING("ini_comment_cb", "Exit");
}


/* Create a comment object */
int ini_comment_create(struct ini_comment **ic)
{
    int error = EOK;
    struct ref_array *ra = NULL;
    struct ini_comment *ic_new = NULL;

    TRACE_FLOW_STRING("ini_comment_create", "Entry");

    error = ref_array_create(&ra,
                             sizeof(char *),
                             INI_COMMENT_BLOCK,
                             ini_comment_cb,
                             NULL);
    if (error) {
        TRACE_ERROR_NUMBER("Error creating ref array", error);
        return error;
    }

    ic_new = malloc(sizeof(struct ini_comment));
    if (!ic_new) {
        TRACE_ERROR_NUMBER("Memory allocation error", ENOMEM);
        ref_array_destroy(ic_new->ra);
        return ENOMEM;
    }

    /* Initialize members here */
    ic_new->ra = ra;
    ic_new->state = INI_COMMENT_EMPTY;

    *ic = ic_new;

    TRACE_FLOW_STRING("ini_comment_create", "Exit");
    return error;
}


/* Is the comment valid? */
static int ini_comment_is_valid(const char *line)
{
    int i;

    TRACE_FLOW_STRING("ini_comment_is_valid", "Entry");

    /* Null is ok */
    if (!line) {
        TRACE_FLOW_STRING("ini_comment_is_valid", "Exit - NULL str");
        return 1;
    }

    /* Empty is Ok or starts with a special symbol */
    if ((line[0] == '\0') ||
        (line[0] == ';') ||
        (line[0] == '#')) {
        TRACE_FLOW_STRING("ini_comment_is_valid", "Exit - empty or comment");
        return 1;
    }

    /* All spaces is Ok too */
    TRACE_INFO_STRING("Line to eval", line);

    i = 0;
    while (line[i] != '\0') {
        if (!isspace(line[i])) {
            TRACE_ERROR_STRING("ini_comment_is_valid", "Invalid comment");
            return 0;
        }
        i++;
    }

    TRACE_FLOW_STRING("ini_comment_is_valid", "Exit - empty str");
    return 1;

}


/*
 * Modify the comment object
 */
static int ini_comment_modify(struct ini_comment *ic,
                              int mode,
                              uint32_t idx,
                              const char *line)
{
    int error = EOK;
    char *elem = NULL;
    char *input = NULL;
    char *empty = NULL;
    uint32_t i, len = 0;

    TRACE_FLOW_STRING("ini_comment_modify", "Entry");

    if (!ic) {
        TRACE_ERROR_NUMBER("Invalid comment object", EINVAL);
        return EINVAL;
    }


    if (mode == INI_COMMENT_MODE_BUILD) {
        /*
         * Can use this function only if object is empty or
         * reading from the file.
         */
        if ((ic->state != INI_COMMENT_EMPTY) &&
            (ic->state != INI_COMMENT_READ)) {
            TRACE_ERROR_NUMBER("Invalid use of the function", EINVAL);
            return EINVAL;
        }
    }

    /* Make sure that we ignore "line" in reset case */
    if (mode != INI_COMMENT_MODE_CLEAR)
        memcpy(&input, &line, sizeof(char *));

    if (mode != INI_COMMENT_MODE_REMOVE) {
        /*
         * Check that provided line is a comment or an empty line.
         * Can be NULL too.
         */
        if (!ini_comment_is_valid(input)) {
            TRACE_ERROR_NUMBER("Invalid comment", EINVAL);
            return EINVAL;
        }

        /* Dup it */
        if (input) elem = strdup(input);
        else elem = strdup("");

        if (!elem) {
            TRACE_ERROR_NUMBER("Memory allocation error", ENOMEM);
            return ENOMEM;
        }
    }

    /* Do action depending on mode */
    switch (mode) {
    case INI_COMMENT_MODE_BUILD:

        TRACE_INFO_STRING("BUILD mode", "");
        error = ref_array_append(ic->ra, &elem);
        break;

    case INI_COMMENT_MODE_APPEND:

        TRACE_INFO_STRING("Append mode", "");
        error = ref_array_append(ic->ra, &elem);
        break;

    case INI_COMMENT_MODE_INSERT:

        TRACE_INFO_STRING("Insert mode", "");
        len = ref_array_len(ic->ra);
        if (idx > len) {
            /* Fill in empty lines */
            for (i = 0; i < (idx-len); i++) {
                empty = strdup("");
                if (empty) {
                    TRACE_ERROR_NUMBER("Memory problem", ENOMEM);
                    return ENOMEM;
                }
                error = ref_array_append(ic->ra, &empty);
                if (error) {
                    TRACE_ERROR_NUMBER("Append problem", error);
                    free(empty);
                    return error;
                }
            }
            /* Append last line */
            error = ref_array_append(ic->ra, &elem);
        }
        else {
            /* Insert inside the array */
            error = ref_array_insert(ic->ra, idx, &elem);
        }
        break;


    case INI_COMMENT_MODE_REPLACE:

        TRACE_INFO_STRING("Replace mode", "");
        error = ref_array_replace(ic->ra, idx, &elem);
        break;

    case INI_COMMENT_MODE_REMOVE:

        TRACE_INFO_STRING("Remove mode", "");
        error = ref_array_remove(ic->ra, idx);
        break;

    case INI_COMMENT_MODE_CLEAR:

        TRACE_INFO_STRING("Clear mode", "");
        error = ref_array_replace(ic->ra, idx, &elem);
        break;

    default :

        TRACE_ERROR_STRING("Coding error", "");
        error = EINVAL;

    }

    if (error) {
        TRACE_ERROR_NUMBER("Failed to append line to an array", error);
        free(elem);
        return error;
    }

    /* Change state */
    if (INI_COMMENT_MODE_BUILD) ic->state = INI_COMMENT_READ;
    else ic->state = INI_COMMENT_CHANGED;


    TRACE_FLOW_STRING("ini_comment_modify", "Exit");
    return error;
}

/*
 * Build up a comment object - use this when reading
 * comments from a file.
 */
int ini_comment_build(struct ini_comment *ic, const char *line)
{
    int error = EOK;

    TRACE_FLOW_STRING("ini_comment_build", "Entry");

    error = ini_comment_modify(ic, INI_COMMENT_MODE_BUILD, 0, line);

    TRACE_FLOW_NUMBER("ini_comment_build - Returning", error);
    return error;
}

/*
 * Modify comment by instering a line.
 */
int ini_comment_insert(struct ini_comment *ic,
                       uint32_t idx,
                       const char *line)
{
    int error = EOK;

    TRACE_FLOW_STRING("ini_comment_insert", "Entry");

    error = ini_comment_modify(ic, INI_COMMENT_MODE_INSERT, idx, line);

    TRACE_FLOW_NUMBER("ini_comment_insert - Returning", error);
    return error;
}

/* Modify comment by appending a line. */
int ini_comment_append(struct ini_comment *ic, const char *line)
{
    int error = EOK;

    TRACE_FLOW_STRING("ini_comment_append", "Entry");

    error = ini_comment_modify(ic, INI_COMMENT_MODE_APPEND, 0, line);

    TRACE_FLOW_NUMBER("ini_comment_append - Returning", error);
    return error;
}

/* Remove line from the comment.*/
int ini_comment_remove(struct ini_comment *ic, uint32_t idx)
{
    int error = EOK;

    TRACE_FLOW_STRING("ini_comment_remove", "Entry");

    error = ini_comment_modify(ic, INI_COMMENT_MODE_REMOVE, idx, NULL);

    TRACE_FLOW_NUMBER("ini_comment_remove - Returning", error);
    return error;
}

/* Clear line in the comment. Line is replaced with an empty line */
int ini_comment_clear(struct ini_comment *ic, uint32_t idx)
{
    int error = EOK;

    TRACE_FLOW_STRING("ini_comment_clear", "Entry");

    error = ini_comment_modify(ic, INI_COMMENT_MODE_CLEAR, idx, NULL);

    TRACE_FLOW_NUMBER("ini_comment_clear - Returning", error);
    return error;

}

/* Replace a line in the comment */
int ini_comment_replace(struct ini_comment *ic,
                        uint32_t idx,
                        const char *line)
{
    int error = EOK;

    TRACE_FLOW_STRING("ini_comment_replace", "Entry");

    error = ini_comment_modify(ic, INI_COMMENT_MODE_REPLACE, idx, line);

    TRACE_FLOW_NUMBER("ini_comment_replace - Returning", error);
    return error;
}


/* Reset the comment - clean all lines.*/
int ini_comment_reset(struct ini_comment *ic)
{
    int error = EOK;

    TRACE_FLOW_STRING("ini_comment_reset", "Entry");

    if (!ic) {
        TRACE_ERROR_NUMBER("Invalid comment object", EINVAL);
        return EINVAL;
    }

    /* Reset comment if it is not empty */
    if (ic->state != INI_COMMENT_EMPTY) {
        ref_array_reset(ic->ra);
        ic->state = INI_COMMENT_CHANGED;
    }

    TRACE_FLOW_STRING("ini_comment_reset", "Exit");
    return error;
}

/* Get number of lines */
int ini_comment_get_numlines(struct ini_comment *ic, uint32_t *num)
{
    int error = EOK;

    TRACE_FLOW_STRING("ini_comment_get_numlines", "Entry");

    if ((!ic) || (!num)) {
        TRACE_ERROR_NUMBER("Invalid argument", EINVAL);
        return EINVAL;
    }

    error = ref_array_getlen(ic->ra, num);

    TRACE_FLOW_NUMBER("ini_comment_get_numlines - Returning", error);
    return error;

}

/* Get line */
int ini_comment_get_line(struct ini_comment *ic, uint32_t idx, char **line)
{
    int error = EOK;
    void *res = NULL;

    TRACE_FLOW_STRING("ini_comment_get_line", "Entry");

    if ((!ic) || (!line)) {
        TRACE_ERROR_NUMBER("Invalid argument", EINVAL);
        return EINVAL;
    }

    res = ref_array_get(ic->ra, idx, (void *)line);
    if (!res) {
        error = EINVAL;
        *line = NULL;
    }
    TRACE_FLOW_NUMBER("ini_comment_get_line - Returning", error);
    return error;
}

/* Swap lines */
int ini_comment_swap(struct ini_comment *ic,
                     uint32_t idx1,
                     uint32_t idx2)
{
    int error = EOK;

    TRACE_FLOW_STRING("ini_comment_swap", "Entry");

    if (!ic) {
        TRACE_ERROR_NUMBER("Invalid argument", EINVAL);
        return EINVAL;
    }

    error = ref_array_swap(ic->ra, idx1, idx2);
    if ((!error) && (idx1 != idx2)) {
        ic->state = INI_COMMENT_CHANGED;
    }

    TRACE_FLOW_NUMBER("ini_comment_swap - Returning", error);
    return error;
}


/* Internal function to print comment */
void ini_comment_print(struct ini_comment *ic, FILE *file)
{
    int len;
    int i;
    char *ret = NULL;

    TRACE_FLOW_STRING("ini_comment_print", "Entry");

    if (!file) {
        TRACE_ERROR_NUMBER("Invalid file argument", EINVAL);
        return;
    }

    if (ic) {
        len = ref_array_len(ic->ra);
        for (i = 0; i < len; i++) {
            ref_array_get(ic->ra, i, &ret);
            fprintf(file, "%s\n", ret);
        }
    }

    TRACE_FLOW_STRING("ini_comment_print", "Exit");

}
