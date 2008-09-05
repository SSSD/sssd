AC_DEFUN(BUILD_WITH_BUILD_INST_DIR,
  [ AC_ARG_WITH([build-install-dir],
                [AC_HELP_STRING([--with-build-install-dir=DIR],
                                [temporary build directory where libraries are installed [$srcdir/buildinst]])])

    buildinstdir="$srcdir/buildinst"
    if test x"$with_build_install_dir" != x; then
        buildinstdir=$with_build_install_dir
        CFLAGS="$CFLAGS -I$with_build_install_dir/include"
        LDFLAGS="$LDFLAGS -L$with_build_install_dir/lib"
    fi
    AC_SUBST(buildinstdir)
  ])

