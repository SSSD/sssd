dnl this file will be simplified when cmocka carries a .pc file
AC_SUBST(CMOCKA_LIBS)
AC_SUBST(CMOCKA_CFLAGS)

AC_CHECK_HEADERS(
    [setjmp.h cmocka.h],
    [AC_CHECK_LIB([cmocka], [_will_return],
                  [ CMOCKA_LIBS="-lcmocka"
                    have_cmocka="yes" ],
                  [AC_MSG_WARN([No libcmocka library found])
                    have_cmocka="no" ])],
    [AC_MSG_WARN([libcmocka header files not installed])],
    [[ #include <stdarg.h>
     # include <stddef.h>
     #ifdef HAVE_SETJMP_H
     # include <setjmp.h>
     #endif
    ]]
)
