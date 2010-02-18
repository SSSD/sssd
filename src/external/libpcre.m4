PCRE_OBJ=""
AC_SUBST(PCRE_OBJ)
AC_SUBST(PCRE_LIBS)
AC_SUBST(PCRE_CFLAGS)

PKG_CHECK_MODULES(PCRE, libpcre)
PKG_CHECK_EXISTS(libpcre >= 7,
                 [AC_MSG_NOTICE([PCRE version is 7 or higher])],
                 [AC_MSG_NOTICE([PCRE version is below 7])
                  AC_DEFINE([HAVE_LIBPCRE_LESSER_THAN_7],
                            1,
                            [Define if libpcre version is less than 7])])

AC_CHECK_HEADERS(pcre.h)
AC_CHECK_LIB(pcre, pcre_compile, [ PCRE_LIBS="-lpcre" ], [AC_MSG_ERROR([PCRE is required])])
