/*
    Authors:
        Simo Sorce <ssorce@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "util/util.h"

const char *debug_prg_name = "sssd";
int debug_level = 0;
int debug_timestamps = 0;

int debug_to_file = 0;
const char *debug_log_file = "sssd";
FILE *debug_file = NULL;


errno_t set_debug_file_from_fd(const int fd)
{
    FILE *dummy;

    dummy = fdopen(fd, "a");
    if (dummy == NULL) {
        DEBUG(1, ("fdopen failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    debug_file = dummy;

    return EOK;
}

void debug_fn(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);

    vfprintf(debug_file ? debug_file : stderr, format, ap);
    fflush(debug_file ? debug_file : stderr);

    va_end(ap);
}

void ldb_debug_messages(void *context, enum ldb_debug_level level,
                        const char *fmt, va_list ap)
{
    int loglevel = -1;
    int ret;
    char * message = NULL;

    switch(level) {
    case LDB_DEBUG_FATAL:
        loglevel = 0;
        break;
    case LDB_DEBUG_ERROR:
        loglevel = 1;
        break;
    case LDB_DEBUG_WARNING:
        loglevel = 6;
        break;
    case LDB_DEBUG_TRACE:
        loglevel = 9;
        break;
    }

    ret = vasprintf(&message, fmt, ap);
    if (ret < 0) {
        /* ENOMEM */
        return;
    }

    if (loglevel <= debug_level) {
        if (debug_timestamps) {
            time_t rightnow = time(NULL);
            char stamp[25];
            memcpy(stamp, ctime(&rightnow), 24);
            stamp[24] = '\0';
            debug_fn("(%s) [%s] [ldb] (%d): %s\n",
                     stamp, debug_prg_name, loglevel, message);
        } else {
            debug_fn("[%s] [ldb] (%d): %s\n",
                     debug_prg_name, loglevel, message);
        }
    }
    free(message);
}

int open_debug_file_ex(const char *filename, FILE **filep)
{
    FILE *f = NULL;
    char *logpath;
    const char *log_file;
    mode_t old_umask;
    int ret;

    if (filename == NULL) {
        log_file = debug_log_file;
    } else {
        log_file = filename;
    }

    ret = asprintf(&logpath, "%s/%s.log", LOG_PATH, log_file);
    if (ret == -1) {
        return ENOMEM;
    }

    if (debug_file && !filep) fclose(debug_file);

    old_umask = umask(0177);
    f = fopen(logpath, "a");
    if (f == NULL) {
        free(logpath);
        return EIO;
    }
    umask(old_umask);

    if (filep == NULL) {
        debug_file = f;
    } else {
        *filep = f;
    }
    free(logpath);
    return EOK;
}

int open_debug_file(void)
{
    return open_debug_file_ex(NULL, NULL);
}
