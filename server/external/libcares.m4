AC_SUBST(CARES_OBJ)
AC_SUBST(CARES_LIBS)
AC_SUBST(CARES_CFLAGS)

AC_CHECK_HEADERS(ares.h,
    [AC_CHECK_LIB([cares], [ares_init], [ CARES_LIBS="-lcares" ], [AC_MSG_ERROR([No usable c-ares library found])])],
    [AC_MSG_ERROR([c-ares header files are not installed])]
)

