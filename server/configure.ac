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
AC_INIT(ldb, 0.9.2)
AC_CONFIG_SRCDIR([server.c])

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

m4_include(pkg.m4)
m4_include(libpopt.m4)
m4_include(libtalloc.m4)
m4_include(libtdb.m4)
m4_include(libevents.m4)
m4_include(util/signal.m4)

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

AC_OUTPUT(Makefile)
