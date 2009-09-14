dnl Check for python-config and substitute needed CFLAGS and LDFLAGS
dnl Usage:
dnl     AM_PYTHON_CONFIG
AC_DEFUN([AM_PYTHON_CONFIG],
[   AC_SUBST(PYTHON_CFLAGS)
    AC_SUBST(PYTHON_LIBS)

    AC_PATH_PROG(PYTHON_CONFIG, python-config)
    AC_MSG_CHECKING(for working python-config)
    if test -x "$PYTHON_CONFIG"; then
        PYTHON_CFLAGS="`$PYTHON_CONFIG --includes`"
        PYTHON_CFLAGS=$PYTHON_CFLAGS" -fno-strict-aliasing"
        PYTHON_LIBS="`$PYTHON_CONFIG --libs`"
        AC_MSG_RESULT([yes])
    else
        AC_MSG_ERROR([no. Please install python devel package])
    fi
])

dnl Taken from GNOME sources
dnl a macro to check for ability to create python extensions
dnl  AM_CHECK_PYTHON_HEADERS([ACTION-IF-POSSIBLE], [ACTION-IF-NOT-POSSIBLE])
dnl function also defines PYTHON_INCLUDES
AC_DEFUN([AM_CHECK_PYTHON_HEADERS],
[AC_REQUIRE([AM_PATH_PYTHON])
    AC_MSG_CHECKING(for headers required to compile python extensions)

    dnl deduce PYTHON_INCLUDES
    py_prefix=`$PYTHON -c "import sys; print sys.prefix"`
    py_exec_prefix=`$PYTHON -c "import sys; print sys.exec_prefix"`
    PYTHON_INCLUDES="-I${py_prefix}/include/python${PYTHON_VERSION}"
    if test "$py_prefix" != "$py_exec_prefix"; then
        PYTHON_INCLUDES="$PYTHON_INCLUDES -I${py_exec_prefix}/include/python${PYTHON_VERSION}"
    fi

    AC_SUBST(PYTHON_INCLUDES)

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


