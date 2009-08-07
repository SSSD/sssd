AC_INIT([elapi],[0.0.1],[freeipa-devel@redhat.com])
AC_CONFIG_SRCDIR([elapi.h])
AC_CONFIG_AUX_DIR([build])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_INSTALL

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

m4_pattern_allow([AM_SILENT_RULES])
AM_SILENT_RULES

AC_CONFIG_HEADERS([config.h])

# Enable trace build
AC_ARG_ENABLE([trace],
              [AS_HELP_STRING([--enable-trace[=LEVEL]],[build with low level tracing enabled])],
              [trace_level="$enableval"],
              [trace_level="0"])
AS_IF([test ["$trace_level" -gt "0"] -a ["$trace_level" -lt "8"] ],[AC_SUBST([TRACE_VAR],["-DTRACE_LEVEL=$trace_level"])])

m4_include(conf_macros.m4)

WITH_CONFIG_DIR
WITH_CONFIG_APP_DIR
WITH_APP_NAME
WITH_APP_NAME_SIZE

AC_CONFIG_FILES([Makefile elapi.pc])
AC_OUTPUT
