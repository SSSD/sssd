/*
    Copyright (C) 2021 Red Hat

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

#include <stdbool.h>
#include <stdlib.h>
#include <libintl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "util/debug.h"

extern FILE *_sss_debug_file;


static const unsigned SSS_DEBUG_BACKTRACE_DEFAULT_SIZE = 100*1024; /* bytes */
static const unsigned SSS_DEBUG_BACKTRACE_LEVEL        = SSSDBG_BE_FO;


/*                     -->
 * ring buffer = [*******t...\n............e000]
 * where:
 *    "t" - 'tail', "e" - 'end'
 *    "......" - "old" part of buffer
 *    "******" - "new" part of buffer
 *    "000"    - unoccupied space
 */
static struct {
    bool      enabled;
    bool      initialized;
    int       size;
    char     *buffer;  /* buffer start */
    char     *end;     /* end data border */
    char     *tail;    /* tail of "current" message */
} _bt;


static inline bool _all_levels_enabled(void);
static inline bool _backtrace_is_enabled(int level);
static inline bool _is_trigger_level(int level);
static void _backtrace_vprintf(const char *format, va_list ap);
static void _backtrace_printf(const char *format, ...);
static void _backtrace_dump(void);
static inline void _debug_vprintf(const char *format, va_list ap);
static inline void _debug_fwrite(const char *ptr, const char *end);
static inline void _debug_fflush(void);


void sss_debug_backtrace_init(void)
{
    _bt.size = SSS_DEBUG_BACKTRACE_DEFAULT_SIZE;
    _bt.buffer = (char *)malloc(_bt.size);
    if (!_bt.buffer) {
        ERROR("Failed to allocate debug backtrace buffer, feature is off\n");
        return;
    }

    _bt.end         = _bt.buffer;
    _bt.tail        = _bt.buffer;

    _bt.enabled     = true;
    _bt.initialized = true;

    _backtrace_printf("   *  ");
}


void sss_debug_backtrace_enable(bool enable)
{
    _bt.enabled = enable;
}


void sss_debug_backtrace_vprintf(int level, const char *format, va_list ap)
{
    va_list ap_copy;

    /* Potential optimization: only print to file here if backtrace is disabled,
     * otherwise always print message to backtrace only and then copy message
     * from backtrace to file in sss_debug_backtrace_endmsg().
     * This saves va_copy and another round of format parsing inside printf but
     * results in a little bit less readable output.
     */
    if (DEBUG_IS_SET(level)) {
        va_copy(ap_copy, ap);
        _debug_vprintf(format, ap_copy);
        va_end(ap_copy);
    }

    if (_backtrace_is_enabled(level)) {
        _backtrace_vprintf(format, ap);
    }
}


void sss_debug_backtrace_printf(int level, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    sss_debug_backtrace_vprintf(level, format, ap);
    va_end(ap);
}


void sss_debug_backtrace_endmsg(int level)
{
    if (DEBUG_IS_SET(level)) {
        _debug_fflush();
    }

    if (_backtrace_is_enabled(level)) {
        if (_is_trigger_level(level)) {
            _backtrace_dump();
        }
        _backtrace_printf("   *  ");
    }
}




/* ********** Helpers ********** */


static inline void _debug_vprintf(const char *format, va_list ap)
{
    vfprintf(_sss_debug_file ? _sss_debug_file : stderr, format, ap);
}


static inline void _debug_fwrite(const char *begin, const char *end)
{
    if (end <= begin) {
        return;
    }
    size_t size = (end - begin);
    fwrite_unlocked(begin, size, 1, _sss_debug_file ? _sss_debug_file : stderr);
}


static inline void _debug_fflush(void)
{
    fflush(_sss_debug_file ? _sss_debug_file : stderr);
}


 /* does 'level' trigger backtrace dump? */
static inline bool _is_trigger_level(int level)
{
    return ((level <= SSSDBG_OP_FAILURE) &&
            (level <= debug_level));
}


/* checks if global 'debug_level' has all levels up to 9 enabled */
static inline bool _all_levels_enabled(void)
{
    static const unsigned all_levels =
      SSSDBG_FATAL_FAILURE|SSSDBG_CRIT_FAILURE|SSSDBG_OP_FAILURE|
      SSSDBG_MINOR_FAILURE|SSSDBG_CONF_SETTINGS|SSSDBG_FUNC_DATA|
      SSSDBG_TRACE_FUNC|SSSDBG_TRACE_LIBS|SSSDBG_TRACE_INTERNAL|
      SSSDBG_TRACE_ALL|SSSDBG_BE_FO;

    unsigned level = debug_level & ~SSSDBG_TRACE_LDB;

    return ((level ^ all_levels) == 0);
}


/* should message of this 'level' go to backtrace? */
static inline bool _backtrace_is_enabled(int level)
{
    /* Store message in backtrace buffer if: */
    return (_bt.initialized        && /* backtrace is initialized */
            _bt.enabled            && /* backtrace is enabled */
            sss_logger != STDERR_LOGGER &&
            !_all_levels_enabled() && /* generic log doesn't cover everything */
            level <= SSS_DEBUG_BACKTRACE_LEVEL); /* skip SSSDBG_TRACE_LDB */
}


 /* prints to buffer */
static void _backtrace_vprintf(const char *format, va_list ap)
{
    int buff_tail_size = _bt.size - (_bt.tail - _bt.buffer);
    int written;

    /* make sure there is at least 1kb available to avoid truncation;
     * putting a sane limit on the size of single message (1kb in a worst case)
     * makes logic simpler and avoids performance hit
     */
    if (buff_tail_size < 1024) {
        /* let's wrap */
        _bt.end = _bt.tail;
        _bt.tail = _bt.buffer;
        buff_tail_size = _bt.size;
    }

    written = vsnprintf(_bt.tail, buff_tail_size, format, ap);
    if (written >= buff_tail_size) {
        /* message is > 1kb, just discard */
        return;
    }

    _bt.tail += written;
    if (_bt.tail > _bt.end) {
        _bt.end = _bt.tail;
    }
}


static void _backtrace_printf(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    _backtrace_vprintf(format, ap);
    va_end(ap);
}


static bool _bt_empty(const char *begin, const char *end)
{
    int counter = 0;

    while (begin < end) {
        if (*begin == '\n') {
            counter++;
            if (counter == 2) {
                /* there is least one line in addition to trigger msg */
                return false;
            }
        }
        begin++;
    }

    return true;
}


static void _backtrace_dump(void)
{
    const char *start = NULL;
    static const char *start_marker =
        "********************** PREVIOUS MESSAGE WAS TRIGGERED BY THE FOLLOWING BACKTRACE:\n";
    static const char *end_marker   =
        "********************** BACKTRACE DUMP ENDS HERE *********************************\n\n";

    if (_bt.end > _bt.tail) {
        /* there is something in the "old" part, but don't start mid message */
        start = _bt.tail + 1;
        while ((start < _bt.end) && (*start != '\n')) start++;
        if (start >= _bt.end) start = NULL;
    }

    if (!start) {
        /* do we have anything to dump at all? */
        if (_bt_empty(_bt.buffer, _bt.tail)) {
            return;
        }
    }

    fprintf(_sss_debug_file ? _sss_debug_file : stderr, "%s", start_marker);

    if (start) {
        _debug_fwrite(start + 1, _bt.end); /* dump "old" part of buffer */
    }
    _debug_fwrite(_bt.buffer, _bt.tail); /* dump "new" part of buffer */

    fprintf(_sss_debug_file ? _sss_debug_file : stderr, "%s", end_marker);
    _debug_fflush();

    _bt.end  = _bt.buffer;
    _bt.tail = _bt.buffer;
}
