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

/* from debug_backtrace.h */
void sss_debug_backtrace_init(void);
void sss_debug_backtrace_vprintf(int level, const char *format, va_list ap);
void sss_debug_backtrace_printf(int level, const char *format, ...);
void sss_debug_backtrace_endmsg(const char *file, long line, int level);

const char *debug_prg_name = "sssd";

int debug_level = SSSDBG_UNRESOLVED;
int debug_timestamps = SSSDBG_TIMESTAMP_UNRESOLVED;
int debug_microseconds = SSSDBG_MICROSECONDS_UNRESOLVED;
enum sss_logger_t sss_logger = STDERR_LOGGER;
const char *debug_log_file = "sssd";
FILE *_sss_debug_file;
uint64_t debug_chain_id;
/* Default value says 'BUG' because this is just a precautionary measure and
 * it is expected value is always set explicitly by every SSSD process. 'BUG'
 * should make any potential oversight more prominent in the logs. */
const char *debug_chain_id_fmt = "BUG%lu %s";

const char *sss_logger_str[] = {
        [STDERR_LOGGER] = "stderr",
        [FILES_LOGGER] = "files",
#ifdef WITH_JOURNALD
        [JOURNALD_LOGGER] = "journald",
#endif
        NULL,
};


/* this function isn't static to let access from debug-tests.c */
void sss_set_logger(const char *logger)
{
    if (logger == NULL) {
        sss_logger = STDERR_LOGGER;
#ifdef WITH_JOURNALD
        sss_logger = JOURNALD_LOGGER;
#endif
    } else if (strcmp(logger, "stderr") == 0) {
        sss_logger = STDERR_LOGGER;
    } else if (strcmp(logger, "files") == 0) {
        sss_logger = FILES_LOGGER;
#ifdef WITH_JOURNALD
    } else if (strcmp(logger, "journald") == 0) {
        sss_logger = JOURNALD_LOGGER;
#endif
    } else {
        /* unexpected value */
        fprintf(stderr, "Unexpected logger: %s\nExpected: ", logger);
        fprintf(stderr, "%s", sss_logger_str[STDERR_LOGGER]);
        fprintf(stderr, "|%s", sss_logger_str[FILES_LOGGER]);
#ifdef WITH_JOURNALD
        fprintf(stderr, "|%s", sss_logger_str[JOURNALD_LOGGER]);
#endif
        fprintf(stderr, "\n");
        sss_logger = STDERR_LOGGER;
    }
}

static int _sss_open_debug_file(void)
{
    return open_debug_file_ex(NULL, NULL, true);
}

void _sss_debug_init(int dbg_lvl, const char *logger)
{
    if (dbg_lvl != SSSDBG_INVALID) {
        debug_level = debug_convert_old_level(dbg_lvl);
    } else {
        debug_level = SSSDBG_UNRESOLVED;
    }

    sss_set_logger(logger);

    /* if 'FILES_LOGGER' is requested then open log file, if it wasn't
     * initialized before via set_debug_file_from_fd().
     */
    if ((sss_logger == FILES_LOGGER) && (_sss_debug_file == NULL)) {
        if (_sss_open_debug_file() != 0) {
            ERROR("Error opening log file, falling back to stderr\n");
            sss_logger = STDERR_LOGGER;
        }
    }

    sss_debug_backtrace_init();
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

    _sss_debug_file = dummy;

    return EOK;
}

int get_fd_from_debug_file(void)
{
    if (_sss_debug_file == NULL) {
        return STDERR_FILENO;
    }

    return fileno(_sss_debug_file);
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
        new_level |= SSSDBG_TRACE_ALL | SSSDBG_BE_FO | SSSDBG_PERF_STAT;

    if (old_level >= 10)
        new_level |= SSSDBG_TRACE_LDB;

    return new_level;
}


#ifdef WITH_JOURNALD
static errno_t journal_send(const char *file,
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
            "SSSD_PRG_NAME=sssd[%s]", debug_prg_name,
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
    static time_t last_time;
    static char last_time_str[128];
    struct timeval tv;
    struct tm tm;
    time_t t;

#ifdef WITH_JOURNALD
    char chain_id_fmt_fixed[256];
    char *chain_id_fmt_dyn = NULL;
    char *result_fmt;
    errno_t ret;
    va_list ap_fallback;

    if (sss_logger == JOURNALD_LOGGER) {
        if (!DEBUG_IS_SET(level)) return; /* no debug backtrace with journald atm */
        /* If we are not outputting logs to files, we should be sending them
         * to journald.
         * NOTE: on modern systems, this is where stdout/stderr will end up
         * from system services anyway. The only difference here is that we
         * can also provide extra structuring data to make it more easily
         * searchable.
         */
        va_copy(ap_fallback, ap);
        if (debug_chain_id > 0 && debug_chain_id_fmt != NULL) {
            result_fmt = chain_id_fmt_fixed;
            ret = snprintf(chain_id_fmt_fixed, sizeof(chain_id_fmt_fixed),
                           debug_chain_id_fmt, debug_chain_id, format);
            if (ret < 0) {
                va_end(ap_fallback);
                return;
            } else if (ret >= sizeof(chain_id_fmt_fixed)) {
                ret = asprintf(&chain_id_fmt_dyn, debug_chain_id_fmt,
                               debug_chain_id, format);
                if (ret < 0) {
                    va_end(ap_fallback);
                    return;
                }
                result_fmt = chain_id_fmt_dyn;
            }

            ret = journal_send(file, line, function, level, result_fmt, ap);
            free(chain_id_fmt_dyn);
        } else {
            ret = journal_send(file, line, function, level, format, ap);
        }
        if (ret != EOK) {
            /* Emergency fallback, send to STDERR */
            vfprintf(stderr, format, ap_fallback);
            fflush(stderr);
        }
        va_end(ap_fallback);
        return;
    }
#endif

    if (debug_timestamps == SSSDBG_TIMESTAMP_ENABLED) {
        if (debug_microseconds == SSSDBG_MICROSECONDS_ENABLED) {
            gettimeofday(&tv, NULL);
            t = tv.tv_sec;
        } else {
            t = time(NULL);
        }
        if (t != last_time) {
            last_time = t;
            localtime_r(&t, &tm);
            snprintf(last_time_str, sizeof(last_time_str),
                     "(%d-%02d-%02d %2d:%02d:%02d",
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec);
        }
        if (debug_microseconds == SSSDBG_MICROSECONDS_ENABLED) {
            sss_debug_backtrace_printf(level, "%s:%.6ld): ",
                                       last_time_str, tv.tv_usec);
        } else {
            sss_debug_backtrace_printf(level, "%s): ", last_time_str);
        }
    }

    sss_debug_backtrace_printf(level, "[%s] [%s] (%#.4x): ",
                               debug_prg_name, function, level);

    if (debug_chain_id > 0 && debug_chain_id_fmt != NULL) {
        sss_debug_backtrace_printf(level, debug_chain_id_fmt, debug_chain_id, "");
    }

    sss_debug_backtrace_vprintf(level, format, ap);

    if (flags & APPEND_LINE_FEED) {
        sss_debug_backtrace_printf(level, "\n");
    }
    sss_debug_backtrace_endmsg(file, line, level);
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

    if (_sss_debug_file && !filep) fclose(_sss_debug_file);

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
        _sss_debug_file = f;
    } else {
        *filep = f;
    }
    free(logpath);
    return EOK;
}

int rotate_debug_files(void)
{
    int ret;
    errno_t error;

    if (sss_logger != FILES_LOGGER) return EOK;

    if (_sss_debug_file != NULL) {
        do {
            error = 0;
            ret = fclose(_sss_debug_file);
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
    }

    _sss_debug_file = NULL;

    return _sss_open_debug_file();
}

void _sss_talloc_log_fn(const char *message)
{
    DEBUG(SSSDBG_FATAL_FAILURE, "%s\n", message);
}
