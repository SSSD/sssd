AC_INIT([dhash], [0.3.3], [jdennis@redhat.com])
AC_CONFIG_SRCDIR([dhash.c])
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

AC_CONFIG_FILES([Makefile dhash.pc])
AC_OUTPUT
