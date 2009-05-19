AC_INIT([collection],[0.3.3],[freeipa-devel@redhat.com])
AC_CONFIG_SRCDIR([collection.c])
AC_CONFIG_AUX_DIR([build])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC

#Until the API is stabilized, we'll statically link
LT_INIT([disable-shared])

AC_CONFIG_MACRO_DIR([m4])
AC_PROG_INSTALL

AC_CONFIG_HEADERS([config.h])

# Enable trace build
AC_ARG_ENABLE([trace],
              [AS_HELP_STRING([--enable-trace[=LEVEL]],[build with low level tracing enabled])],
              [trace_level="$enableval"],
              [trace_level="0"])
AS_IF([test ["$trace_level" -gt "0"] -a ["$trace_level" -lt "8"] ],[AC_SUBST([TRACE_VAR],["-DTRACE_LEVEL=$trace_level"])])

AC_CONFIG_FILES([Makefile collection.pc])
AC_OUTPUT
