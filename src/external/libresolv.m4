AC_SUBST(RESOLV_CFLAGS)
AC_SUBST(RESOLV_LIBS)

# Some unit tests require libresolv to fake DNS packets
SSS_AC_EXPAND_LIB_DIR()
AC_CHECK_LIB([resolv],
             [ns_name_compress],
             [RESOLV_LIBS="-L$sss_extra_libdir -lresolv"],
             [AC_MSG_WARN([No libresolv detected, some tests will not run])],
             [-L$sss_extra_libdir])

AM_CONDITIONAL([HAVE_LIBRESOLV], [test x"$RESOLV_LIBS" != "x"])
