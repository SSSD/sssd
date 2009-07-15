AC_SUBST(CARES_OBJ)
AC_SUBST(CARES_LIBS)
AC_SUBST(CARES_CFLAGS)

AC_CHECK_HEADERS(ares.h,
    [AC_CHECK_LIB([cares], [ares_init], [ CARES_LIBS="-lcares" ], [AC_MSG_ERROR([No usable c-ares library found])])],
    [AC_MSG_ERROR([c-ares header files are not installed])]
)

dnl Check if this particular version of c-ares supports parsing of SRV records
AC_CHECK_LIB([cares],
             [ares_parse_srv_reply],
             [AC_DEFINE([HAVE_ARES_PARSE_SRV], 1, [Does c-ares support srv parsing?])
             ],
             [
                ares_build_srv=1
             ]
)

dnl Check if this particular version of c-ares supports parsing of TXT records
AC_CHECK_LIB([cares],
             [ares_parse_txt_reply],
             [AC_DEFINE([HAVE_ARES_PARSE_TXT], 1, [Does c-ares support txt parsing?])
             ],
             [
                ares_build_txt=1
             ]
)

AM_CONDITIONAL(BUILD_ARES_PARSE_SRV, test x$ares_build_srv = x1)
AM_CONDITIONAL(BUILD_ARES_PARSE_TXT, test x$ares_build_txt = x1)
