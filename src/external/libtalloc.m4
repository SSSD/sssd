AC_SUBST(TALLOC_CFLAGS)
AC_SUBST(TALLOC_LIBS)

PKG_CHECK_MODULES([TALLOC], [talloc], [found_talloc=yes], [found_talloc=no])

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_talloc" != xyes],
    [AC_CHECK_HEADER([talloc.h],
        [AC_CHECK_LIB([talloc],
                      [talloc_init],
                      [TALLOC_LIBS="-L$sss_extra_libdir -ltalloc"],
                      [AC_MSG_ERROR([libtalloc missing talloc_init])],
                      [-L$sss_extra_libdir])],
        [AC_MSG_ERROR([libtalloc header files are not installed])])]
)
