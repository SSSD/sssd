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
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "util/util.h"

const char *debug_prg_name = "sssd";
int debug_level = 0;
int debug_timestamps = 1;

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
    int debug_fd;
    int flags;

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
    errno = 0;
    f = fopen(logpath, "a");
    if (f == NULL) {
        sss_log(SSS_LOG_EMERG, "Could not open file [%s]. Error: [%d][%s]\n",
                               logpath, errno, strerror(errno));
        free(logpath);
        return EIO;
    }
    umask(old_umask);

    debug_fd = fileno(f);
    if (debug_fd == -1) {
        return EIO;
    }

    flags = fcntl(debug_fd, F_GETFD, 0);
    (void) fcntl(debug_fd, F_SETFD, flags | FD_CLOEXEC);

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

int rotate_debug_files(void)
{
    int ret;
    errno_t error;

    if (!debug_to_file) return EOK;

    do {
        error = 0;
        ret = fclose(debug_file);
        if (ret != 0) {
            error = errno;
        }

        /* Check for EINTR, which means we should retry
         * because the system call was interrupted by a
         * signal
         */
    } while (error == EINTR);

    if (error != 0) {
        /* Even if we were unable to close the debug log, we need to make
         * sure that we open up a new one. Log rotation will remove the
         * current file, so all debug messages will be disappearing.
         *
         * We should write an error to the syslog warning of the resource
         * leak and then proceed with opening the new file.
         */
        sss_log(SSS_LOG_ALERT, "Could not close debug file [%s]. [%d][%s]\n",
                               debug_log_file, error, strerror(error));
        sss_log(SSS_LOG_ALERT, "Attempting to open new file anyway. "
                               "Be aware that this is a resource leak\n");
    }

    debug_file = NULL;

    return open_debug_file();
}
