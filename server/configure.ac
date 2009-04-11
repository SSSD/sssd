AC_PREREQ(2.50)
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
AC_INIT(sssd, 0.2.1)
AC_CONFIG_SRCDIR([autogen.sh])

AC_LIBREPLACE_ALL_CHECKS

if test "$ac_cv_prog_gcc" = yes; then
   CFLAGS="$CFLAGS -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings"
fi

AC_CHECK_HEADERS(stdint.h dlfcn.h)
AC_CONFIG_HEADER(config.h)

TESTS=""
EXTRA_OBJ=""

m4_include(build_macros.m4)
BUILD_WITH_SHARED_BUILD_DIR
AC_LD_SONAMEFLAG

m4_include(conf_macros.m4)
WITH_DB_PATH
WITH_PLUGIN_PATH
WITH_PID_PATH
WITH_PIPE_PATH
WITH_INFOPIPE
WITH_POLICYKIT
WITH_TESTS
WITH_INIT_DIR

m4_include(pkg.m4)
m4_include(libpopt.m4)
m4_include(libtalloc.m4)
m4_include(libtdb.m4)
m4_include(libtevent.m4)
m4_include(libldb.m4)
m4_include(pam.m4)
m4_include(ldap.m4)
m4_include(libpcre.m4)
m4_include(util/signal.m4)

PKG_CHECK_MODULES([DBUS],[dbus-1])
if test x$has_dbus != xno; then
    LDFLAGS="$DBUS_LIBS"
    AC_CHECK_FUNC([dbus_watch_get_unix_fd],
                  AC_DEFINE([HAVE_DBUS_WATCH_GET_UNIX_FD], [1],
                            [Define if dbus_watch_get_unix_fd exists]))
fi
if test x$HAVE_TESTS != x; then
    PKG_CHECK_MODULES([CHECK],[check])
fi
PKG_CHECK_MODULES([NSS],[nss])

AC_SUBST(TESTS)
AC_SUBST(EXTRA_OBJ)

AC_LD_EXPORT_DYNAMIC
AC_LD_PICFLAG
AC_LD_SHLIBEXT
AC_LD_SONAMEFLAG
AC_LIBREPLACE_SHLD
AC_LIBREPLACE_SHLD_FLAGS
AC_LIBREPLACE_MDLD
AC_LIBREPLACE_MDLD_FLAGS
AC_LIBREPLACE_RUNTIME_LIB_PATH_VAR

AC_CHECK_HEADERS([sys/inotify.h])

AC_OUTPUT(Makefile)
