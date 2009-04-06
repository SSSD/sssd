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
#define TRACE_STRING(level,message,str)     if(level & trace_level) \
                                            printf("[DEBUG] %23s (%4d) %s %s\n",__FILE__,__LINE__,message,str);
/* Convenience wrappers for strings */
#define TRACE_FLOW_STRING(message,str)      TRACE_STRING(TRACE_FLOW,message,str)
#define TRACE_ERROR_STRING(message,str)     TRACE_STRING(TRACE_ERROR,message,str)
#define TRACE_INFO_STRING(message,str)      TRACE_STRING(TRACE_INFO,message,str)

/* Tracing numbers */
#define TRACE_NUMBER(level,message,number)  if(level & trace_level) \
                                            printf("[DEBUG] %23s (%4d) %s %lu\n",__FILE__,__LINE__,message,(unsigned long int)(number));
/* Convenience wrappers for numbers */
#define TRACE_FLOW_NUMBER(message,number)   TRACE_NUMBER(TRACE_FLOW,message,number)
#define TRACE_ERROR_NUMBER(message,number)  TRACE_NUMBER(TRACE_ERROR,message,number)
#define TRACE_INFO_NUMBER(message,number)   TRACE_NUMBER(TRACE_INFO,message,number)

/* Tracing doubles */
#define TRACE_DOUBLE(level,message,number)  if(level & trace_level) \
                                            printf("[DEBUG] %23s (%4d) %s %e\n",__FILE__,__LINE__,message,(double)(number));
/* Convenience wrappers for numbers */
#define TRACE_FLOW_DOUBLE(message,number)   TRACE_DOUBLE(TRACE_FLOW,message,number)
#define TRACE_ERROR_DOUBLE(message,number)  TRACE_DOUBLE(TRACE_ERROR,message,number)
#define TRACE_INFO_DOUBLE(message,number)   TRACE_DOUBLE(TRACE_INFO,message,number)

/* Assertion */
#define TRACE_ASSERT(expression)             expression ? ; : printf("ASSERTION FAILED\n");
#else
/* Noop in case the tracing is disabled */
#define TRACE_STRING(level,message,str)     ;
#define TRACE_NUMBER(level,message,number)  ;
#define TRACE_DOUBLE(level,message,number)  ;
#define TRACE_FLOW_STRING(message,str)      ;
#define TRACE_ERROR_STRING(message,str)     ;
#define TRACE_INFO_STRING(message,str)      ;
#define TRACE_FLOW_NUMBER(message,str)      ;
#define TRACE_ERROR_NUMBER(message,str)     ;
#define TRACE_INFO_NUMBER(message,str)      ;
#define TRACE_FLOW_DOUBLE(message,str)      ;
#define TRACE_ERROR_DOUBLE(message,str)     ;
#define TRACE_INFO_DOUBLE(message,str)      ;
#define TRACE_ASSERT(expression)            ;
#endif /* HAVE_TRACE */


#endif /* COMMON_TRACE_H */
