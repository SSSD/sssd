/*
    INI LIBRARY

    Low level parsing functions

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
#include "ini_parse.h"
#include "ini_defines.h"
#include "ini_config.h"


/* Reads a line from the file */
int read_line(FILE *file,
              char *buf,
              int read_size,
              char **key, char **value,
              int *length,
              int *ext_error)
{

    char *res;
    int len;
    char *buffer;
    int i;
    char *eq;

    TRACE_FLOW_STRING("read_line", "Entry");

    *ext_error = 0;

    buffer = buf;

    /* Get data from file */
    res = fgets(buffer, read_size - 1, file);
    if (res == NULL) {
        TRACE_ERROR_STRING("Read nothing", "");
        return RET_EOF;
    }

    /* Make sure the buffer is NULL terminated */
    buffer[read_size - 1] = '\0';

    len = strlen(buffer);
    if (len == 0) {
        TRACE_ERROR_STRING("Nothing was read.", "");
        return RET_EMPTY;
    }

    /* Added \r just in case we deal with Windows in future */
    if ((buffer[len - 1] != '\n') && (buffer[len - 1] != '\r')) {
        TRACE_ERROR_STRING("String it too big!", "");
        *ext_error = ERR_LONGDATA;
        return RET_ERROR;
    }

    /* Ingnore comments */
    if ((*buffer == ';') || (*buffer == '#')) {
        TRACE_FLOW_STRING("Comment", buf);
        return RET_COMMENT;
    }

    TRACE_INFO_STRING("BUFFER before trimming:", buffer);

    /* Trucate trailing spaces and CRs */
    /* Make sure not to step before the beginning */
    while (len && isspace(buffer[len - 1])) {
        buffer[len - 1] = '\0';
        len--;
    }

    TRACE_INFO_STRING("BUFFER after trimming trailing spaces:", buffer);

    /* Trucate leading spaces  */
    while (isspace(*buffer)) {
        buffer++;
        len--;
    }

    TRACE_INFO_STRING("BUFFER after trimming leading spaces:", buffer);
    TRACE_INFO_NUMBER("BUFFER length:", len);

    /* Empty line */
    if (len == 0) {
        TRACE_FLOW_STRING("Empty line", buf);
        return RET_EMPTY;
    }

    /* Section */
    if (*buffer == '[') {
        if (buffer[len-1] != ']') {
            TRACE_ERROR_STRING("Invalid format for section", buf);
            *ext_error = ERR_NOCLOSESEC;
            return RET_ERROR;
        }
        buffer++;
        len--;
        while (isspace(*buffer)) {
            buffer++;
            len--;
        }
        if (len == 0) {
            TRACE_ERROR_STRING("Invalid format for section", buf);
            *ext_error = ERR_NOSECTION;
            return RET_ERROR;
        }

        buffer[len - 1] = '\0';
        len--;
        while (isspace(buffer[len - 1])) {
            buffer[len - 1] = '\0';
            len--;
        }
        if (len >= MAX_KEY) {
            TRACE_ERROR_STRING("Section name is too long", buf);
            *ext_error = ERR_SECTIONLONG;
            return RET_ERROR;
        }

        *key = buffer;
        return RET_SECTION;
    }

    /* Assume we are dealing with the K-V here */
    /* Find "=" */
    eq = strchr(buffer, '=');
    if (eq == NULL) {
        TRACE_ERROR_STRING("No equal sign", buf);
        *ext_error = ERR_NOEQUAL;
        return RET_INVALID;
    }

    len -= eq-buffer;

    /* Strip spaces around "=" */
    i = eq - buffer - 1;
    while ((i >= 0) && isspace(buffer[i])) i--;
    if (i < 0) {
        TRACE_ERROR_STRING("No key", buf);
        *ext_error = ERR_NOKEY;
        return RET_INVALID;
    }

    /* Copy key into provided buffer */
    if(i >= MAX_KEY) {
        TRACE_ERROR_STRING("Key name is too long", buf);
        *ext_error = ERR_LONGKEY;
        return RET_INVALID;
    }
    *key = buffer;
    buffer[i + 1] = '\0';
    TRACE_INFO_STRING("KEY:", *key);

    eq++;
    len--;
    while (isspace(*eq)) {
        eq++;
        len--;
    }

    *value = eq;
    /* Make sure we include trailing 0 into data */
    *length = len + 1;

    TRACE_INFO_STRING("VALUE:", *value);
    TRACE_INFO_NUMBER("LENGTH:", *length);

    TRACE_FLOW_STRING("read_line", "Exit");
    return RET_PAIR;
}
