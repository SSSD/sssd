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

#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#ifdef WITH_JOURNALD
#include <systemd/sd-journal.h>
#endif

#include "util/util.h"

const char *debug_prg_name = "sssd";

int debug_level = SSSDBG_UNRESOLVED;
int debug_timestamps = SSSDBG_TIMESTAMP_UNRESOLVED;
int debug_microseconds = SSSDBG_MICROSECONDS_UNRESOLVED;
int debug_to_file = 0;
int debug_to_stderr = 0;
const char *debug_log_file = "sssd";
FILE *debug_file = NULL;

errno_t set_debug_file_from_fd(const int fd)
{
    FILE *dummy;
    errno_t ret;

    errno = 0;
    dummy = fdopen(fd, "a");
    if (dummy == NULL) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fdopen failed [%d][%s].\n", ret, strerror(ret));
        sss_log(SSS_LOG_ERR,
                "Could not open debug file descriptor [%d]. "
                "Debug messages will not be written to the file "
                "for this child process [%s][%s]\n",
                fd, debug_prg_name, strerror(ret));
        return ret;
    }

    debug_file = dummy;

    return EOK;
}

int debug_convert_old_level(int old_level)
{
    if ((old_level != 0) && !(old_level & 0x000F))
        return old_level;

    int new_level = SSSDBG_FATAL_FAILURE;

    if (old_level <= 0)
        return new_level;

    if (old_level >= 1)
        new_level |= SSSDBG_CRIT_FAILURE;

    if (old_level >= 2)
        new_level |= SSSDBG_OP_FAILURE;

    if (old_level >= 3)
        new_level |= SSSDBG_MINOR_FAILURE;

    if (old_level >= 4)
        new_level |= SSSDBG_CONF_SETTINGS;

    if (old_level >= 5)
        new_level |= SSSDBG_FUNC_DATA;

    if (old_level >= 6)
        new_level |= SSSDBG_TRACE_FUNC;

    if (old_level >= 7)
        new_level |= SSSDBG_TRACE_LIBS;

    if (old_level >= 8)
        new_level |= SSSDBG_TRACE_INTERNAL;

    if (old_level >= 9)
        new_level |= SSSDBG_TRACE_ALL;

    return new_level;
}

static void debug_fflush(void)
{
    fflush(debug_file ? debug_file : stderr);
}

static void debug_vprintf(const char *format, va_list ap)
{
    vfprintf(debug_file ? debug_file : stderr, format, ap);
}

static void debug_printf(const char *format, ...)
                SSS_ATTRIBUTE_PRINTF(1, 2);

static void debug_printf(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);

    debug_vprintf(format, ap);

    va_end(ap);
}

#ifdef WITH_JOURNALD
errno_t journal_send(const char *file,
        long line,
        const char *function,
        int level,
        const char *format,
        va_list ap)
{
    errno_t ret;
    int res;
    char *message = NULL;
    char *code_file = NULL;
    char *code_line = NULL;
    const char *domain;

    /* First, evaluate the message to be sent */
    ret = vasprintf(&message, format, ap);
    if (ret == -1) {
        /* ENOMEM, just return */
        return ENOMEM;
    }

    res = asprintf(&code_file, "CODE_FILE=%s", file);
    if (res == -1) {
        ret = ENOMEM;
        goto journal_done;
    }

    res = asprintf(&code_line, "CODE_LINE=%ld", line);
    if (res == -1) {
        ret = ENOMEM;
        goto journal_done;
    }

    /* If this log message was sent from a provider,
     * track the domain.
     */
    domain = getenv(SSS_DOM_ENV);
    if (domain == NULL) {
        domain = "";
    }

    /* Send the log message to journald, specifying the
     * source code location and other tracking data.
     */
    res = sd_journal_send_with_location(
            code_file, code_line, function,
            "MESSAGE=%s", message,
            "PRIORITY=%i", LOG_DEBUG,
            "SSSD_DOMAIN=%s", domain,
            "SSSD_PRG_NAME=%s", debug_prg_name,
            "SSSD_DEBUG_LEVEL=%x", level,
            NULL);
    ret = -res;

journal_done:
    free(code_line);
    free(code_file);
    free(message);
    return ret;
}
#endif /* WiTH_JOURNALD */

void debug_fn(const char *file,
              long line,
              const char *function,
              int level,
              const char *format, ...)
{
    va_list ap;
    struct timeval tv;
    struct tm *tm;
    char datetime[20];
    int year;

#ifdef WITH_JOURNALD
    errno_t ret;
    va_list ap_fallback;

    if (!debug_file && !debug_to_stderr) {
        /* If we are not outputting logs to files, we should be sending them
         * to journald.
         * NOTE: on modern systems, this is where stdout/stderr will end up
         * from system services anyway. The only difference here is that we
         * can also provide extra structuring data to make it more easily
         * searchable.
         */
        va_start(ap, format);
        va_copy(ap_fallback, ap);
        ret = journal_send(file, line, function, level, format, ap);
        va_end(ap);
        if (ret != EOK) {
            /* Emergency fallback, send to STDERR */
            debug_vprintf(format, ap_fallback);
            debug_fflush();
        }
        va_end(ap_fallback);
        return;
    }
#endif

    if (debug_timestamps) {
        gettimeofday(&tv, NULL);
        tm = localtime(&tv.tv_sec);
        year = tm->tm_year + 1900;
        /* get date time without year */
        memcpy(datetime, ctime(&tv.tv_sec), 19);
        datetime[19] = '\0';
        if (debug_microseconds) {
            debug_printf("(%s:%.6ld %d) [%s] [%s] (%#.4x): ",
                         datetime, tv.tv_usec,
                         year, debug_prg_name,
                         function, level);
        } else {
            debug_printf("(%s %d) [%s] [%s] (%#.4x): ",
                         datetime, year,
                         debug_prg_name, function, level);
        }
    } else {
        debug_printf("[%s] [%s] (%#.4x): ",
                     debug_prg_name, function, level);
    }

    va_start(ap, format);
    debug_vprintf(format, ap);
    va_end(ap);
    debug_fflush();
}

void ldb_debug_messages(void *context, enum ldb_debug_level level,
                        const char *fmt, va_list ap)
{
    int loglevel = SSSDBG_UNRESOLVED;
    int ret;
    char * message = NULL;

    switch(level) {
    case LDB_DEBUG_FATAL:
        loglevel = SSSDBG_FATAL_FAILURE;
        break;
    case LDB_DEBUG_ERROR:
        loglevel = SSSDBG_CRIT_FAILURE;
        break;
    case LDB_DEBUG_WARNING:
        loglevel = SSSDBG_TRACE_FUNC;
        break;
    case LDB_DEBUG_TRACE:
        loglevel = SSSDBG_TRACE_ALL;
        break;
    }

    ret = vasprintf(&message, fmt, ap);
    if (ret < 0) {
        /* ENOMEM */
        return;
    }

    if (DEBUG_IS_SET(loglevel))
        debug_fn(__FILE__, __LINE__, "ldb", loglevel, "%s\n", message);

    free(message);
}

int open_debug_file_ex(const char *filename, FILE **filep, bool want_cloexec)
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
        fclose(f);
        free(logpath);
        return EIO;
    }

    if(want_cloexec) {
        flags = fcntl(debug_fd, F_GETFD, 0);
        (void) fcntl(debug_fd, F_SETFD, flags | FD_CLOEXEC);
    }

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
    return open_debug_file_ex(NULL, NULL, true);
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

void talloc_log_fn(const char *message)
{
    DEBUG(SSSDBG_FATAL_FAILURE, "%s", message);
}
