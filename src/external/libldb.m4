AC_SUBST(LDB_CFLAGS)
AC_SUBST(LDB_LIBS)

PKG_CHECK_MODULES(LDB, ldb >= 0.9.2)

AC_CHECK_HEADERS(ldb.h ldb_module.h,
   [AC_CHECK_LIB(ldb, ldb_init, [LDB_LIBS="-lldb"], , -ltevent -ltdb -ldl -lldap) ],
   [AC_MSG_ERROR([LDB header files are not installed])]
)

AC_ARG_WITH([ldb-lib-dir],
            [AC_HELP_STRING([--with-ldb-lib-dir=PATH],
                            [Path to store ldb modules [${libdir}/ldb]]
                           )
            ]
           )

if test x"$with_ldb_lib_dir" != x; then
    ldblibdir=$with_ldb_lib_dir
else
    ldblibdir="`$PKG_CONFIG --variable=modulesdir ldb`"
    if ! test -d $ldblibdir; then
        ldblibdir="${libdir}/ldb"
    fi
fi

AC_MSG_CHECKING([feature ldb runtime version check])
AC_ARG_ENABLE(ldb-version-check,
              [AS_HELP_STRING([--enable-ldb-version-check],
                              [compile with ldb runtime version check [default=no]])],
              enable_ldb_version_check="$enableval",
              enable_ldb_version_check="no")
if test x"$enable_ldb_version_check" = xyes ; then
    AC_MSG_RESULT([yes])
    AC_DEFINE([SSS_LDB_VERSION_CHECK], [1],
              [Define to 1 if you want ldb version check.])
else
    AC_MSG_RESULT([no])
fi

AC_MSG_NOTICE([ldb lib directory: $ldblibdir])
AC_SUBST(ldblibdir)
