/*
    COMMON TRACE

    Common header file for tracing.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

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

#ifndef COMMON_TRACE_H
#define COMMON_TRACE_H

#ifdef TRACE_LEVEL
#define HAVE_TRACE
#include <stdio.h>

/* The trace level is a bit mask */
#define TRACE_FLOW      0x0000001  /* - trace messages that are entry exit into functions */
#define TRACE_ERROR     0x0000002  /* - trace messages that are errors */
#define TRACE_INFO      0x0000004  /* - trace things that are informational */


#ifdef TRACE_HOME           /* Define this in the module that contains main */
unsigned trace_level = TRACE_LEVEL;
#else
extern unsigned trace_level;
#endif /* TRACE_HOME */
#endif /* TRACE_LEVEL */



#ifdef HAVE_TRACE
/* Tracing strings */
#define TRACE_STRING(level, msg, str) \
    do { \
        if (level & trace_level) { \
            printf("[DEBUG] %23s (%4d) %s %s\n", \
                   __FILE__, __LINE__, (msg != NULL) ? msg : "MISSING MESSAGE", \
                                       (str != NULL) ? str : "(null)"); \
        } \
    } while(0)

/* Tracing numbers */
#define TRACE_NUMBER(level, msg, num) \
    do { \
        if (level & trace_level) { \
            printf("[DEBUG] %23s (%4d) %s %lu\n", \
                   __FILE__, __LINE__, (msg != NULL) ? msg : "MISSING MESSAGE", \
                                       (unsigned long int)(num)); \
        } \
    } while(0)

/* Tracing doubles */
#define TRACE_DOUBLE(level, msg, num) \
    do { \
        if (level & trace_level) { \
            printf("[DEBUG] %23s (%4d) %s %e\n", \
                   __FILE__, __LINE__, (msg != NULL) ? msg : "MISSING MESSAGE", \
                                       (double)(num)); \
        } \
    } while(0)

/* Assertion */
#define TRACE_ASSERT(expression) expression ? : printf("ASSERTION FAILED\n")
#else /* HAVE_TRACE */

/* Noop in case the tracing is disabled */
#define TRACE_STRING(level, msg, str)
#define TRACE_NUMBER(level, msg, num)
#define TRACE_DOUBLE(level, msg, num)
#endif /* HAVE_TRACE */


/* Convenience wrappers for strings */
#define TRACE_FLOW_STRING(msg, str)  TRACE_STRING(TRACE_FLOW, msg, str)
#define TRACE_ERROR_STRING(msg, str) TRACE_STRING(TRACE_ERROR, msg, str)
#define TRACE_INFO_STRING(msg, str)  TRACE_STRING(TRACE_INFO, msg, str)

/* Convenience wrappers for numbers */
#define TRACE_FLOW_NUMBER(msg, num)  TRACE_NUMBER(TRACE_FLOW, msg, num)
#define TRACE_ERROR_NUMBER(msg, num) TRACE_NUMBER(TRACE_ERROR, msg, num)
#define TRACE_INFO_NUMBER(msg, num)  TRACE_NUMBER(TRACE_INFO, msg, num)

/* Convenience wrappers for numbers */
#define TRACE_FLOW_DOUBLE(msg, num)  TRACE_DOUBLE(TRACE_FLOW, msg, num)
#define TRACE_ERROR_DOUBLE(msg, num) TRACE_DOUBLE(TRACE_ERROR, msg, num)
#define TRACE_INFO_DOUBLE(msg, num)  TRACE_DOUBLE(TRACE_INFO, msg, num)

#endif /* COMMON_TRACE_H */
