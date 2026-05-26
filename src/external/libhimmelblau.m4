AC_SUBST(HIMMELBLAU_LIBS)
AC_SUBST(HIMMELBLAU_CFLAGS)

found_himmelblau=no
BUILD_VENDORED_HIMMELBLAU=no

AS_IF([test x$with_himmelblau != xno], [
    PKG_CHECK_MODULES([HIMMELBLAU], [himmelblau >= 0.8.0],
                      [found_himmelblau=yes],
                      [found_himmelblau=no])

    AS_IF([test x"$found_himmelblau" = xno],
        [AC_CHECK_PROG([CARGO], [cargo], [cargo])
         AC_CHECK_PROG([CARGO_CBUILD], [cargo-cbuild], [cargo-cbuild])

         AS_IF([test x"$CARGO" != x -a x"$CARGO_CBUILD" != x],
            [AS_IF([test -f "$srcdir/src/external/libhimmelblau/Cargo.toml"],
                [AC_MSG_NOTICE([Will build vendored libhimmelblau])
                 found_himmelblau=vendored
                 BUILD_VENDORED_HIMMELBLAU=yes
                 HIMMELBLAU_CFLAGS="-I\$(top_builddir)/src/external/libhimmelblau/target/include"
                 HIMMELBLAU_LIBS="-L\$(top_builddir)/src/external/libhimmelblau/target/\$(host)/release -lhimmelblau"],
                [AC_MSG_WARN([No system libhimmelblau and no vendored source found])]
            )]
         )]
    )
])

AM_CONDITIONAL([BUILD_VENDORED_HIMMELBLAU], [test x"$BUILD_VENDORED_HIMMELBLAU" = xyes])
AM_CONDITIONAL([HAVE_LIBHIMMELBLAU], [test x"$found_himmelblau" != xno])
