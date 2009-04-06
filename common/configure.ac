AC_INIT([elapi], [0.0], [dpal@redhat.com])
AC_CONFIG_SRCDIR([collection/collection.c])
AC_CONFIG_AUX_DIR([build])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AC_CONFIG_HEADERS([config.h])


# Enable trace build
AC_ARG_ENABLE([trace],
              [AS_HELP_STRING([--enable-trace],[build with low level tracing enabled])],
              [trace_level="$enableval"],
              [trace_level="0"])
AS_IF([test ["$trace_level" -gt "0"] -a ["$trace_level" -lt "8"] ],[AC_SUBST([TRACE_VAR],["-DTRACE_LEVEL=$trace_level"])])


AC_CONFIG_FILES([Makefile collection/Makefile])
AC_OUTPUT




