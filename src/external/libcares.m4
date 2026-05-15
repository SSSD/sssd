AC_SUBST(CARES_LIBS)
AC_SUBST(CARES_CFLAGS)

PKG_CHECK_MODULES([CARES], [libcares], [found_libcares=yes], [found_libcares=no])

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_libcares" != xyes],
    [AC_CHECK_HEADERS([ares.h],
        [AC_CHECK_LIB([cares],
                      [ares_init],
                      [CARES_LIBS="-L$sss_extra_libdir -lcares"],
                      [AC_MSG_ERROR([No usable c-ares library found])],
                      [-L$sss_extra_libdir])],
        [AC_MSG_ERROR([c-ares header files are not installed])])]
)
