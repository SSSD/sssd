POPT_OBJ=""
AC_SUBST(POPT_OBJ)
AC_SUBST(POPT_LIBS)
AC_SUBST(POPT_CFLAGS)

AC_CHECK_HEADERS([popt.h],
    [AC_CHECK_LIB(popt, poptGetContext, [ POPT_LIBS="-lpopt" ], [AC_MSG_ERROR([POPT must support poptGetContext])])],
    [AC_MSG_ERROR([POPT development libraries not installed])]
)
