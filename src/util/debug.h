/*
    Authors:
        Simo Sorce <ssorce@redhat.com>

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

#ifndef __SSSD_DEBUG_H__
#define __SSSD_DEBUG_H__

#include "config.h"

#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>

#include "util/util_errors.h"

#define SSSDBG_TIMESTAMP_UNRESOLVED      -1
#define SSSDBG_TIMESTAMP_DISABLED         0
#define SSSDBG_TIMESTAMP_ENABLED          1
#define SSSDBG_TIMESTAMP_DEFAULT          SSSDBG_TIMESTAMP_ENABLED

#define SSSDBG_MICROSECONDS_UNRESOLVED   -1
#define SSSDBG_MICROSECONDS_DISABLED      0
#define SSSDBG_MICROSECONDS_ENABLED       1
#define SSSDBG_MICROSECONDS_DEFAULT       SSSDBG_MICROSECONDS_DISABLED


enum sss_logger_t {
    STDERR_LOGGER = 0,
    FILES_LOGGER,
#ifdef WITH_JOURNALD
    JOURNALD_LOGGER,
#endif
};

extern const char *sss_logger_str[]; /* mapping: sss_logger_t -> string */
extern const char *debug_prg_name;
extern int debug_level;
extern int debug_timestamps;
extern int debug_microseconds;
extern enum sss_logger_t sss_logger;
extern const char *debug_log_file;   /* only file name, excluding path */


/* converts log level from "old" notation and opens log file if needed */
#define DEBUG_INIT(dbg_lvl, logger) do {   \
    _sss_debug_init(dbg_lvl, logger);      \
    talloc_set_log_fn(_sss_talloc_log_fn); \
} while (0)

/* CLI tools shall debug to stderr */
#define DEBUG_CLI_INIT(dbg_lvl) do {                    \
    DEBUG_INIT(dbg_lvl, sss_logger_str[STDERR_LOGGER]); \
} while (0)

void sss_set_debug_backtrace_enable(bool enable);
bool sss_get_debug_backtrace_enable(void);

/* debug_convert_old_level() converts "old" style decimal notation
 * to bitmask composed of SSSDBG_*
 * Used explicitly, for example, while processing user input
 * in sssctl_logs.
 */
int debug_convert_old_level(int old_level);

/* set_debug_file_from_fd() is used by *_child processes as those
 * don't manage logs files on their own but instead receive fd arg
 * on command line.
 */
errno_t set_debug_file_from_fd(const int fd);

/* get_fd_from_debug_file() is used to redirect STDERR_FILENO
 * to currently open log file fd while running external helpers
 * (e.g. nsupdate, ipa_get_keytab)
 */
int get_fd_from_debug_file(void);

/* open_debug_file_ex() is used to open log file for *_child processes */
int open_debug_file_ex(const char *filename, FILE **filep, bool want_cloexec);

int rotate_debug_files(void);

#define SSS_DOM_ENV           "_SSS_DOM"

/* 0x0800 isn't used for historical reasons */
#define SSSDBG_FATAL_FAILURE  0x0010   /* level 0 */
#define SSSDBG_CRIT_FAILURE   0x0020   /* level 1 */
#define SSSDBG_OP_FAILURE     0x0040   /* level 2 */
#define SSSDBG_MINOR_FAILURE  0x0080   /* level 3 */
#define SSSDBG_CONF_SETTINGS  0x0100   /* level 4 */
#define SSSDBG_FUNC_DATA      0x0200   /* level 5 */
#define SSSDBG_TRACE_FUNC     0x0400   /* level 6 */
#define SSSDBG_TRACE_LIBS     0x1000   /* level 7 */
#define SSSDBG_TRACE_INTERNAL 0x2000   /* level 8 */
#define SSSDBG_TRACE_ALL      0x4000   /* level 9 */
#define SSSDBG_BE_FO          0x8000   /* level 9 */
#define SSSDBG_TRACE_LDB     0x10000   /* level 10 */
#define SSSDBG_PERF_STAT     0x20000   /* level 9 */

/* IMPORTANT_INFO will be logged if any of bits >=  OP_FAILURE are on: */
#define SSSDBG_IMPORTANT_INFO (SSSDBG_OP_FAILURE|SSSDBG_MINOR_FAILURE|\
                               SSSDBG_CONF_SETTINGS|SSSDBG_FUNC_DATA|\
                               SSSDBG_TRACE_FUNC|SSSDBG_TRACE_LIBS|\
                               SSSDBG_TRACE_INTERNAL|SSSDBG_TRACE_ALL|\
                               SSSDBG_BE_FO|SSSDBG_TRACE_LDB|SSSDBG_PERF_STAT)

#define SSSDBG_INVALID        -1
#define SSSDBG_UNRESOLVED      0
#define SSSDBG_DEFAULT   (SSSDBG_FATAL_FAILURE|SSSDBG_CRIT_FAILURE|SSSDBG_OP_FAILURE)
#define SSSDBG_TOOLS_DEFAULT (SSSDBG_FATAL_FAILURE)


/** \def DEBUG(level, format, ...)
    \brief macro to generate debug messages

    \param level the debug level, please use one of the SSSDBG_* macros
    \param format the debug message format string, should result in a
                  newline-terminated message
    \param ... the debug message format arguments
*/
#define DEBUG(level, format, ...) do { \
    sss_debug_fn(__FILE__, __LINE__, __FUNCTION__, \
                 level, \
                 format, ##__VA_ARGS__); \
} while (0)


/* SSSD_*_OPTS are used as 'poptOption' entries */
#define SSSD_LOGGER_OPTS \
        {"logger", '\0', POPT_ARG_STRING, &opt_logger, 0, \
         _("Set logger"), "stderr|files|journald"},

#define SSSD_DEBUG_OPTS \
        {"debug-level", 'd', POPT_ARG_INT, &debug_level, 0, \
         _("Debug level"), NULL}, \
        {"debug-timestamps", 0, POPT_ARG_INT, &debug_timestamps, 0, \
         _("Add debug timestamps"), NULL}, \
        {"debug-microseconds", 0, POPT_ARG_INT, &debug_microseconds, 0, \
         _("Show timestamps with microseconds"), NULL},


#define PRINT(fmt, ...) fprintf(stdout, gettext(fmt), ##__VA_ARGS__)
#define ERROR(fmt, ...) fprintf(stderr, gettext(fmt), ##__VA_ARGS__)


#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
#define SSS_ATTRIBUTE_PRINTF(a1, a2) __attribute__((format (printf, a1, a2)))
#else
#define SSS_ATTRIBUTE_PRINTF(a1, a2)
#endif

/* sss_*debug_fn() are rarely needed to be used explicitly
 * (common example: provision of a logger function to 3rd party lib)
 * For normal logs use DEBUG() instead.
 */
void sss_vdebug_fn(const char *file,
                   long line,
                   const char *function,
                   int level,
                   int flags,
                   const char *format,
                   va_list ap);
void sss_debug_fn(const char *file,
                  long line,
                  const char *function,
                  int level,
                  const char *format, ...) SSS_ATTRIBUTE_PRINTF(5, 6);

#define APPEND_LINE_FEED 0x1 /* can be used as a sss_vdebug_fn() flag */

/* Checks whether level is set in generic debug_level.
   Rarely needed to be used explicitly as everything
   should go to backtrace buffer anyway (regardless debug_level)
   Deciding if "--verbose" should be passed to `adcli` child process
   is one of usage examples.
 */
#define DEBUG_IS_SET(level) (debug_level & (level) || \
                            (debug_level == SSSDBG_UNRESOLVED && \
                                            (level & (SSSDBG_FATAL_FAILURE | \
                                                      SSSDBG_CRIT_FAILURE))))

/* The same as DEBUG but does nothing if requested debug level isn't set,
 * thus avoiding logging to the backtrace in this case.
 * Meant to be used in hot (performance sensitive) code paths only.
 */
#define DEBUG_CONDITIONAL(level, format, ...) do { \
    if (DEBUG_IS_SET(level)) { \
        sss_debug_fn(__FILE__, __LINE__, __FUNCTION__, \
                     level, \
                     format, ##__VA_ARGS__); \
    } \
} while (0)


/* not to be used explictly, use 'DEBUG_INIT' instead */
void _sss_debug_init(int dbg_lvl, const char *logger);
void _sss_talloc_log_fn(const char *msg);

#endif /* __SSSD_DEBUG_H__ */
