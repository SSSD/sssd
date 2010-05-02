AC_PREREQ(2.59)
AC_DEFUN([AC_CHECK_LIB_EXT], [
	AC_CHECK_LIB([$1],[$3],[$4],[$5],[$7])
	ac_cv_lib_ext_$1_$3=$ac_cv_lib_$1_$3
])
AC_DEFUN([AC_CHECK_FUNC_EXT], [
	AC_CHECK_FUNC([$1],[$3],[$4])
	ac_cv_func_ext_$1=$ac_cv_func_$1
])
AC_DEFUN([SMB_MODULE_DEFAULT], [echo -n ""])
AC_DEFUN([SMB_LIBRARY_ENABLE], [echo -n ""])
AC_DEFUN([SMB_EXT_LIB], [echo -n ""])
AC_DEFUN([SMB_ENABLE], [echo -n ""])

m4_include([../version.m4])
AC_INIT([sss_daemon],
        VERSION_NUMBER,
        [sssd-devel@lists.fedorahosted.org])

CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE"

AC_CONFIG_SRCDIR([conf_macros.m4])
AC_CONFIG_AUX_DIR([build])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.14])

m4_pattern_allow([AM_SILENT_RULES])
AM_SILENT_RULES

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

AC_CHECK_HEADERS(stdint.h dlfcn.h)
AC_CONFIG_HEADER(config.h)

AC_CHECK_TYPES([errno_t], [], [], [[#include <errno.h>]])

m4_include([build_macros.m4])
BUILD_WITH_SHARED_BUILD_DIR

#Check for PAM headers
AC_CHECK_HEADERS([security/pam_appl.h security/pam_misc.h security/pam_modules.h],
    [AC_CHECK_LIB(pam, pam_get_item, [ PAM_LIBS="-lpam" ], [AC_MSG_ERROR([PAM must support pam_get_item])])],
    [AC_MSG_ERROR([PAM development libraries not installed])]
)

#Set the NSS library install path
AC_ARG_ENABLE([nsslibdir], [AS_HELP_STRING([--enable-nsslibdir],
                                        [Where to install nss libraries ($libdir)])],
              [nsslibdir=$enableval],
              [nsslibdir=$libdir])
AC_SUBST(nsslibdir)

m4_include(conf_macros.m4)
WITH_DB_PATH
WITH_PLUGIN_PATH
WITH_PID_PATH
WITH_LOG_PATH
WITH_PUBCONF_PATH
WITH_PIPE_PATH
WITH_INIT_DIR
WITH_TEST_DIR
WITH_MANPAGES
WITH_XML_CATALOG
WITH_KRB5_PLUGIN_PATH
WITH_PYTHON_BINDINGS
WITH_SELINUX
WITH_NSCD
WITH_SEMANAGE

m4_include([external/platform.m4])
m4_include([external/pkg.m4])
m4_include([external/libpopt.m4])
m4_include([external/libtalloc.m4])
m4_include([external/libtdb.m4])
m4_include([external/libtevent.m4])
m4_include([external/libldb.m4])
m4_include([external/libdhash.m4])
m4_include([external/libcollection.m4])
m4_include([external/libini_config.m4])
m4_include([external/pam.m4])
m4_include([external/ldap.m4])
m4_include([external/libpcre.m4])
m4_include([external/krb5.m4])
m4_include([external/libcares.m4])
m4_include([external/docbook.m4])
m4_include([external/sizes.m4])
m4_include([external/python.m4])
m4_include([external/selinux.m4])
m4_include([external/crypto.m4])
m4_include([external/nscd.m4])
m4_include([external/libkeyutils.m4])
m4_include([external/nsupdate.m4])
m4_include([util/signal.m4])

PKG_CHECK_MODULES([DBUS],[dbus-1])
dnl if test -n "`$PKG_CONFIG --modversion dbus-1 | grep '^0\.'`" ; then
if ! $PKG_CONFIG --atleast-version 1.0.0 dbus-1; then
    DBUS_CFLAGS="$DBUS_CFLAGS -DDBUS_API_SUBJECT_TO_CHANGE"
    AC_MSG_RESULT([setting -DDBUS_API_SUBJECT_TO_CHANGE])
fi

if test x$has_dbus != xno; then
    SAFE_LDFLAGS="$LDFLAGS"
    LDFLAGS="$DBUS_LIBS"
    AC_CHECK_FUNC([dbus_watch_get_unix_fd],
                  AC_DEFINE([HAVE_DBUS_WATCH_GET_UNIX_FD], [1],
                            [Define if dbus_watch_get_unix_fd exists]))
    LDFLAGS="$SAFE_LDFLAGS"
fi

if test x$HAVE_MANPAGES != x; then
    CHECK_XML_TOOLS
    CHECK_STYLESHEET([$SGML_CATALOG_FILES],
                     [http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl],
                     [Docbook XSL templates])
fi

if test x$HAVE_PYTHON_BINDINGS != x; then
    AM_PATH_PYTHON([2.4])
    AM_CHECK_PYTHON_HEADERS([],
                            AC_MSG_ERROR([Could not find python headers]))
    AM_PYTHON_CONFIG
fi

if test x$HAVE_SELINUX != x; then
    AM_CHECK_SELINUX
fi

if test x$HAVE_SEMANAGE != x -a x$HAVE_SELINUX != x; then
    AM_CHECK_SEMANAGE
fi

AC_CHECK_HEADERS([sys/inotify.h])

AC_CHECK_HEADERS([sasl/sasl.h],,AC_MSG_ERROR([Could not find SASL headers]))

PKG_CHECK_MODULES([CHECK], [check >= 0.9.5], [have_check=1], [have_check=])
if test x$have_check = x; then
    AC_MSG_WARN([Without the 'CHECK' libraries, you will be unable to run all tests in the 'make check' suite])
else
    AC_CHECK_HEADERS([check.h],,AC_MSG_ERROR([Could not find CHECK headers]))
fi

AC_PATH_PROG([DOXYGEN], [doxygen], [false])
AM_CONDITIONAL([HAVE_DOXYGEN], [test x$DOXYGEN != xfalse ])

AM_CONDITIONAL([HAVE_CHECK], [test x$have_check != x])

abs_build_dir=`pwd`
AC_DEFINE_UNQUOTED([ABS_BUILD_DIR], ["$abs_build_dir"], [Absolute path to the build directory])
AC_SUBST([abs_builddir], $abs_build_dir)

AC_CONFIG_FILES([Makefile examples/rwtab doxy.config po/Makefile.in])
AC_OUTPUT
