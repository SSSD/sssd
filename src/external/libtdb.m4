AC_SUBST(TDB_CFLAGS)
AC_SUBST(TDB_LIBS)

PKG_CHECK_MODULES([TDB], [tdb >= 1.1.3], [found_tdb=yes], [found_tdb=no])

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_tdb" != xyes],
    [AC_CHECK_HEADERS([tdb.h],
        [AC_CHECK_LIB([tdb],
                      [tdb_repack],
                      [TDB_LIBS="-L$sss_extra_libdir -ltdb"],
                      [AC_MSG_ERROR([library TDB must support tdb_repack])],
                      [-L$sss_extra_libdir])],
        [AC_MSG_ERROR([tdb header files are not installed])])]
)
