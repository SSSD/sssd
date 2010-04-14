m4_include([../version.m4])
AC_INIT([sssd_libs],
        VERSION_NUMBER,
        [sssd-devel@lists.fedorahosted.org])
AC_CONFIG_SRCDIR([README])
AC_CONFIG_AUX_DIR([build])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_INSTALL

AC_CONFIG_HEADERS([config.h])


# Enable trace build
AC_ARG_ENABLE([trace],
              [AS_HELP_STRING([--enable-trace[=LEVEL]],[build with low level tracing enabled])],
              [trace_level="$enableval"],
              [trace_level="0"])
AS_IF([test ["$trace_level" -gt "0"] -a ["$trace_level" -lt "8"] ],[AC_SUBST([TRACE_VAR],["-DTRACE_LEVEL=$trace_level"])])


AC_CONFIG_FILES([Makefile
		trace/Makefile])

AC_CONFIG_SUBDIRS([dhash path_utils refarray collection ini])

AC_DEFUN([WITH_SINGLELIB],
  [ AC_ARG_WITH([singlelib],
                [AC_HELP_STRING([--with-singlelib],
                                [Whether to build a shared object containing all sssd_utils [no]]
                               )
                ],
                [],
                with_singlelib=yes
               )
  ])

AM_CONDITIONAL([SINGLELIB], [test x$with_singlelib = xyes ])

AC_OUTPUT
