AC_SUBST(JANSSON_LIBS)
AC_SUBST(JANSSON_CFLAGS)

PKG_CHECK_MODULES([JANSSON], [jansson], [found_jansson=yes], [found_jansson=no])

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_jansson" != xyes],
    [AC_CHECK_HEADERS([jansson.h],
        [AC_CHECK_LIB([jansson],
                      [jansson_loads],
                      [JANSSON_LIBS="-L$sss_extra_libdir -ljansson"],
                      [AC_MSG_ERROR([libjansson missing jansson_loads])],
                      [-L$sss_extra_libdir -ljanson])],
        [AC_MSG_ERROR([You must have the header file jansson.h installed])]
    )]
)
