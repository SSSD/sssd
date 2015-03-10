dnl A macro to check presence of cmocka on the system
AC_DEFUN([AM_CHECK_CMOCKA],
[
    PKG_CHECK_EXISTS(cmocka >= 1.0.0,
        [AC_CHECK_HEADERS([stdarg.h stddef.h setjmp.h],
            [], dnl We are only intrested in action-if-not-found
            [AC_MSG_WARN([Header files stdarg.h stddef.h setjmp.h are required by cmocka])
             cmocka_required_headers="no"
            ]
        )
        AS_IF([test x"$cmocka_required_headers" != x"no"],
              [PKG_CHECK_MODULES([CMOCKA], [cmocka], [have_cmocka="yes"])]
        )],
        dnl PKG_CHECK_EXISTS ACTION-IF-NOT-FOUND
        [AC_MSG_WARN([No libcmocka-1.0.0 or newer library found, cmocka tests will not be built])]
    )
    AM_CONDITIONAL([HAVE_CMOCKA], [test x$have_cmocka = xyes])
])
