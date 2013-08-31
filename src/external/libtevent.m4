AC_SUBST(TEVENT_OBJ)
AC_SUBST(TEVENT_CFLAGS)
AC_SUBST(TEVENT_LIBS)

PKG_CHECK_MODULES([TEVENT], [tevent], [found_tevent=yes], [found_tevent=no])

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_tevent" != xyes],
    [AC_CHECK_HEADER([tevent.h],
        [AC_CHECK_LIB([tevent],
                      [tevent_context_init],
                      [TEVENT_LIBS="-L$sss_extra_libdir -ltevent -ltalloc"],
                      [AC_MSG_ERROR([libtevent missing tevent_context_init])],
                      [-L$sss_extra_libdir -ltalloc])],
        [AC_MSG_ERROR([tevent header files are not installed])])]
)
