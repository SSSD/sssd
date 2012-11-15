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

dnl AC_CONFIG_FILES conditionalization requires using AM_COND_IF, however
dnl dnl AM_COND_IF is new to Automake 1.11.  To use it on new Automake without
dnl dnl requiring same, a fallback implementation for older Autoconf is provided.
dnl dnl Note that disabling of AC_CONFIG_FILES requires Automake 1.11, this code
dnl dnl is correct only in terms of m4sh generated script.
m4_ifndef([AM_COND_IF], [AC_DEFUN([AM_COND_IF], [
if test -z "$$1_TRUE"; then :
m4_n([$2])[]dnl
m4_ifval([$3],
[else
$3
])dnl
fi[]dnl
])])
