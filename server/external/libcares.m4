AC_SUBST(CARES_OBJ)
AC_SUBST(CARES_LIBS)
AC_SUBST(CARES_CFLAGS)

AC_CHECK_HEADERS(ares.h,
    [AC_CHECK_LIB([cares], [ares_init], [ CARES_LIBS="-lcares" ], [AC_MSG_ERROR([No usable c-ares library found])])],
    [AC_MSG_ERROR([c-ares header files are not installed])]
)

dnl Check if this particular version of c-ares supports the generic ares_free_data function
AC_CHECK_LIB([cares],
             [ares_free_data],
             [AC_DEFINE([HAVE_ARES_DATA], 1, [Does c-ares have ares_free_data()?])
             ],
             [
                ares_data=1
             ]
)

AM_CONDITIONAL(BUILD_ARES_DATA, test x$ares_data = x1)
