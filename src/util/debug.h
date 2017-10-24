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

#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
#define SSS_ATTRIBUTE_PRINTF(a1, a2) __attribute__((format (printf, a1, a2)))
#else
#define SSS_ATTRIBUTE_PRINTF(a1, a2)
#endif

#define APPEND_LINE_FEED 0x1

enum sss_logger_t {
    STDERR_LOGGER = 0,
    FILES_LOGGER,
#ifdef WITH_JOURNALD
    JOURNALD_LOGGER,
#endif
};

extern const char *sss_logger_str[];
extern const char *debug_prg_name;
extern int debug_level;
extern int debug_timestamps;
extern int debug_microseconds;
extern int debug_to_file;
extern int debug_to_stderr;
extern enum sss_logger_t sss_logger;
extern const char *debug_log_file;

void sss_set_logger(const char *logger);

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
int debug_convert_old_level(int old_level);
errno_t set_debug_file_from_fd(const int fd);
int get_fd_from_debug_file(void);

#define SSS_DOM_ENV           "_SSS_DOM"

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
#define SSSDBG_IMPORTANT_INFO SSSDBG_OP_FAILURE

#define SSSDBG_INVALID        -1
#define SSSDBG_UNRESOLVED     0
#define SSSDBG_MASK_ALL       0xFFF0   /* enable all debug levels */
#define SSSDBG_DEFAULT        SSSDBG_FATAL_FAILURE

#define SSSDBG_TIMESTAMP_UNRESOLVED   -1
#define SSSDBG_TIMESTAMP_DEFAULT       1

#define SSSDBG_MICROSECONDS_UNRESOLVED   -1
#define SSSDBG_MICROSECONDS_DEFAULT       0

#define SSSD_LOGGER_OPTS \
        {"logger", '\0', POPT_ARG_STRING, &opt_logger, 0, \
         _("Set logger"), "stderr|files|journald"},


#define SSSD_DEBUG_OPTS \
        {"debug-level", 'd', POPT_ARG_INT, &debug_level, 0, \
         _("Debug level"), NULL}, \
        {"debug-to-files", 'f', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, &debug_to_file, 0, \
         _("Send the debug output to files instead of stderr"), NULL }, \
        {"debug-to-stderr", 0, POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, &debug_to_stderr, 0, \
         _("Send the debug output to stderr directly."), NULL }, \
        {"debug-timestamps", 0, POPT_ARG_INT, &debug_timestamps, 0, \
         _("Add debug timestamps"), NULL}, \
        {"debug-microseconds", 0, POPT_ARG_INT, &debug_microseconds, 0, \
         _("Show timestamps with microseconds"), NULL},

/** \def DEBUG(level, format, ...)
    \brief macro to generate debug messages

    \param level the debug level, please use one of the SSSDBG_* macros
    \param format the debug message format string, should result in a
                  newline-terminated message
    \param ... the debug message format arguments
*/
#define DEBUG(level, format, ...) do { \
    int __debug_macro_level = level; \
    if (DEBUG_IS_SET(__debug_macro_level)) { \
        sss_debug_fn(__FILE__, __LINE__, __FUNCTION__, \
                     __debug_macro_level, \
                     format, ##__VA_ARGS__); \
    } \
} while (0)

/** \def DEBUG_IS_SET(level)
    \brief checks whether level is set in debug_level

    \param level the debug level, please use one of the SSSDBG*_ macros
*/
#define DEBUG_IS_SET(level) (debug_level & (level) || \
                            (debug_level == SSSDBG_UNRESOLVED && \
                                            (level & (SSSDBG_FATAL_FAILURE | \
                                                      SSSDBG_CRIT_FAILURE))))

#define DEBUG_INIT(dbg_lvl) do { \
    if (dbg_lvl != SSSDBG_INVALID) { \
        debug_level = debug_convert_old_level(dbg_lvl); \
    } else { \
        debug_level = SSSDBG_UNRESOLVED; \
    } \
\
    talloc_set_log_fn(talloc_log_fn); \
} while (0)

/* CLI tools shall debug to stderr even when SSSD was compiled with journald
 * support
 */
#define DEBUG_CLI_INIT(dbg_lvl) do { \
    DEBUG_INIT(dbg_lvl);             \
    debug_to_stderr = 1;             \
} while (0)

#define PRINT(fmt, ...) fprintf(stdout, gettext(fmt), ##__VA_ARGS__)
#define ERROR(fmt, ...) fprintf(stderr, gettext(fmt), ##__VA_ARGS__)

#endif /* __SSSD_DEBUG_H__ */
