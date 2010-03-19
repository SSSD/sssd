AC_INIT([path_utils], [0.2.0], [jdennis@redhat.com])
AC_CONFIG_SRCDIR([path_utils.c])
AC_CONFIG_AUX_DIR([build])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_INSTALL

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

PKG_CHECK_MODULES([CHECK], [check >= 0.9.5], [have_check=1], [have_check=])
if test x$have_check = x; then
    AC_MSG_WARN([Without the 'CHECK' libraries, you will be unable to run all tests in the 'make check' suite])
fi
AM_CONDITIONAL([HAVE_CHECK], [test x$have_check != x])

m4_pattern_allow([AM_SILENT_RULES])
AM_SILENT_RULES

AC_CONFIG_HEADERS([config.h])

AC_PATH_PROG([DOXYGEN], [doxygen], [false])
AM_CONDITIONAL([HAVE_DOXYGEN], [test x$DOXYGEN != xfalse ])

AC_CONFIG_FILES([Makefile path_utils.cfg.doxy path_utils.pc])
AC_OUTPUT
