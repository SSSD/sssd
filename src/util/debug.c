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
enum sss_logger_t sss_logger;
const char *debug_log_file = "sssd";
FILE *debug_file = NULL;

const char *sss_logger_str[] = {
        [STDERR_LOGGER] = "stderr",
        [FILES_LOGGER] = "files",
#ifdef WITH_JOURNALD
        [JOURNALD_LOGGER] = "journald",
#endif
        NULL,
};

#ifdef WITH_JOURNALD
#define JOURNALD_STR " journald,"
#else
#define JOURNALD_STR ""
#endif

void sss_set_logger(const char *logger)
{
    /* use old flags */
    if (logger == NULL) {
        if (debug_to_stderr != 0) {
            sss_logger = STDERR_LOGGER;
        }
        /* It is never described what should be used in case of
         * debug_to_stderr == 1 && debug_to_file == 1. Because neither
         * of binaries provide both command line arguments.
         * Let files have higher priority.
         */
        if (debug_to_file != 0) {
            sss_logger = FILES_LOGGER;
        }
#ifdef WITH_JOURNALD
        if (debug_to_file == 0 && debug_to_stderr == 0) {
            sss_logger = JOURNALD_LOGGER;
        }
#endif
    } else {
        if (strcmp(logger, "stderr") == 0) {
            sss_logger = STDERR_LOGGER;
        } else if (strcmp(logger, "files") == 0) {
            sss_logger = FILES_LOGGER;
#ifdef WITH_JOURNALD
        } else if (strcmp(logger, "journald") == 0) {
            sss_logger = JOURNALD_LOGGER;
#endif
        } else {
            /* unexpected value */
            fprintf(stderr, "Unexpected logger: %s\nExpected:%s stderr, "
                            "files\n", logger, JOURNALD_STR);
            sss_logger = STDERR_LOGGER;
        }
    }
}

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

int get_fd_from_debug_file(void)
{
    if (debug_file == NULL) {
        return STDERR_FILENO;
    }

    return fileno(debug_file);
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
        new_level |= SSSDBG_TRACE_ALL | SSSDBG_BE_FO;

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

void sss_vdebug_fn(const char *file,
                   long line,
                   const char *function,
                   int level,
                   int flags,
                   const char *format,
                   va_list ap)
{
    struct timeval tv;
    struct tm *tm;
    char datetime[20];
    int year;

#ifdef WITH_JOURNALD
    errno_t ret;
    va_list ap_fallback;

    if (sss_logger == JOURNALD_LOGGER) {
        /* If we are not outputting logs to files, we should be sending them
         * to journald.
         * NOTE: on modern systems, this is where stdout/stderr will end up
         * from system services anyway. The only difference here is that we
         * can also provide extra structuring data to make it more easily
         * searchable.
         */
        va_copy(ap_fallback, ap);
        ret = journal_send(file, line, function, level, format, ap);
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

    debug_vprintf(format, ap);
    if (flags & APPEND_LINE_FEED) {
        debug_printf("\n");
    }
    debug_fflush();
}

void sss_debug_fn(const char *file,
                  long line,
                  const char *function,
                  int level,
                  const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    sss_vdebug_fn(file, line, function, level, 0, format, ap);
    va_end(ap);
}

void ldb_debug_messages(void *context, enum ldb_debug_level level,
                        const char *fmt, va_list ap)
{
    int loglevel = SSSDBG_UNRESOLVED;

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

    if (DEBUG_IS_SET(loglevel)) {
        sss_vdebug_fn(__FILE__, __LINE__, "ldb", loglevel, APPEND_LINE_FEED,
                      fmt, ap);
    }
}

/* In cases SSSD used to run as the root user, but runs as the SSSD user now,
 * we need to chown the log files
 */
int chown_debug_file(const char *filename,
                     uid_t uid, gid_t gid)
{
    char *logpath;
    const char *log_file;
    errno_t ret;

    if (filename == NULL) {
        log_file = debug_log_file;
    } else {
        log_file = filename;
    }

    ret = asprintf(&logpath, "%s/%s.log", LOG_PATH, log_file);
    if (ret == -1) {
        return ENOMEM;
    }

    ret = chown(logpath, uid, gid);
    free(logpath);
    if (ret != 0) {
        ret = errno;
        if (ret == ENOENT) {
            /* Log does not exist. We might log to journald
             * or starting for first time.
             * It's not a failure. */
            return EOK;
        }

        DEBUG(SSSDBG_FATAL_FAILURE, "chown failed for [%s]: [%d]\n",
              log_file, ret);
        return ret;
    }

    return EOK;
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

    old_umask = umask(SSS_DFL_UMASK);
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

    if (sss_logger != FILES_LOGGER) return EOK;

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
    DEBUG(SSSDBG_FATAL_FAILURE, "%s\n", message);
}
