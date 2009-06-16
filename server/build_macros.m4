AC_DEFUN([BUILD_WITH_SHARED_BUILD_DIR],
  [ AC_ARG_WITH([shared-build-dir],
                [AC_HELP_STRING([--with-shared-build-dir=DIR],
                                [temporary build directory where libraries are installed [$srcdir/sharedbuild]])])

    sharedbuilddir="$srcdir/sharedbuild"
    if test x"$with_shared_build_dir" != x; then
        sharedbuilddir=$with_shared_build_dir
        CFLAGS="$CFLAGS -I$with_shared_build_dir/include"
        CPPFLAGS="$CPPFLAGS -I$with_shared_build_dir/include"
        LDFLAGS="$LDFLAGS -L$with_shared_build_dir/lib"
    fi
    AC_SUBST(sharedbuilddir)
  ])

AC_DEFUN([BUILD_WITH_AUX_INFO],
  [ AC_ARG_WITH([aux-info],
                [AC_HELP_STRING([--with-aux-info],
                                [Build with -aux-info output])])
  ])
AM_CONDITIONAL([WANT_AUX_INFO], [test x$with_aux_info = xyes])
