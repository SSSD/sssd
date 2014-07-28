AC_SUBST(POPT_LIBS)
AC_SUBST(POPT_CFLAGS)

PKG_CHECK_MODULES([POPT], [popt], [found_popt=yes], [found_popt=no])

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_popt" != xyes],
    [AC_CHECK_HEADERS([popt.h],
        [AC_CHECK_LIB([popt],
                      [poptGetContext],
                      [POPT_LIBS="-L$sss_extra_libdir -lpopt"],
                      [AC_MSG_ERROR([POPT library must support poptGetContext])],
                      [-L$sss_extra_libdir])],
        [AC_MSG_ERROR([POPT header files are not installed])])]
)
