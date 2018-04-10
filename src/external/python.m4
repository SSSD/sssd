dnl Check for python-config and substitute needed CFLAGS and LDFLAGS
dnl Usage:
dnl     AM_PYTHON_CONFIG(python_with_major_version)
dnl     argument python_with_major_version should be either python2 or python3
dnl This function sets the PYTHON_CFLAGS, PYTHON_LIBS and PYTHON_INCLUDES
dnl variables

AC_DEFUN([AM_PYTHON_CONFIG],
[
    AC_PATH_PROG([PYTHON_CONFIG], [python$PYTHON_VERSION-config])
    AS_IF([test x"$PYTHON_CONFIG" = x],
          AC_MSG_ERROR([
The program python$PYTHON_VERSION-config was not found in search path.
Please ensure that it is installed and its directory is included in the search
path. If you want to build sssd without $1 bindings then specify
--without-$1-bindings when running configure.]))

    PYTHON_CFLAGS="` $PYTHON_CONFIG --cflags`"
    PYTHON_LIBS="` $PYTHON_CONFIG --libs`"
    PYTHON_INCLUDES="` $PYTHON_CONFIG --includes`"
])

dnl Taken from GNOME sources
dnl a macro to check for ability to create python extensions
dnl  AM_CHECK_PYTHON_HEADERS([ACTION-IF-POSSIBLE], [ACTION-IF-NOT-POSSIBLE])
AC_DEFUN([AM_CHECK_PYTHON_HEADERS],
[
    AC_REQUIRE([AM_PATH_PYTHON])
    AC_MSG_CHECKING(for headers required to compile python extensions)

    dnl check if the headers exist:
    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $PYTHON_INCLUDES"
    AC_TRY_CPP([#include <Python.h>],dnl
               [AC_MSG_RESULT([found])
                $1],dnl
               [AC_MSG_RESULT([not found])
               $2])
    CPPFLAGS="$save_CPPFLAGS"
])

dnl Clean variables after detection of python
AC_DEFUN([SSS_CLEAN_PYTHON_VARIABLES],
[
    unset pyexecdir pkgpyexecdir pythondir pgkpythondir
    unset PYTHON PYTHON_CFLAGS PYTHON_LIBS PYTHON_INCLUDES
    unset PYTHON_PREFIX PYTHON_EXEC_PREFIX PYTHON_VERSION PYTHON_CONFIG

    dnl removed cached variables, required for reusing of AM_PATH_PYTHON
    unset am_cv_pathless_PYTHON ac_cv_path_PYTHON am_cv_python_version
    unset am_cv_python_platform am_cv_python_pythondir am_cv_python_pyexecdir
    unset ac_cv_path_PYTHON_CONFIG
])

dnl ===========================================================================
dnl     http://www.gnu.org/software/autoconf-archive/ax_python_module.html
dnl ===========================================================================
dnl
dnl SYNOPSIS
dnl
dnl   AM_PYTHON2_MODULE(modname[, fatal])
dnl
dnl DESCRIPTION
dnl
dnl   Checks for Python 2 module.
dnl
dnl   If fatal is non-empty then absence of a module will trigger an error.
dnl
dnl LICENSE
dnl
dnl   Copyright (c) 2008 Andrew Collier
dnl
dnl   Copying and distribution of this file, with or without modification, are
dnl   permitted in any medium without royalty provided the copyright notice
dnl   and this notice are preserved. This file is offered as-is, without any
dnl   warranty.
AC_DEFUN([AM_PYTHON2_MODULE],[
    if test x"$PYTHON2" = x; then
        if test -n "$2"; then
            AC_MSG_ERROR([cannot look for $1 module: Python 2 not found])
        else
            AC_MSG_NOTICE([cannot look for $1 module: Python 2 not found])
            eval AS_TR_CPP(HAVE_PY2MOD_$1)=no
        fi
    else
        AC_MSG_CHECKING($(basename $PYTHON2) module: $1)
        $PYTHON2 -c "import $1" 2>/dev/null
        if test $? -eq 0; then
            AC_MSG_RESULT(yes)
            eval AS_TR_CPP(HAVE_PY2MOD_$1)=yes
        else
            AC_MSG_RESULT(no)
            eval AS_TR_CPP(HAVE_PY2MOD_$1)=no
            #
            if test -n "$2"
            then
                AC_MSG_ERROR(failed to find required module $1)
                exit 1
            fi
        fi
    fi
])
