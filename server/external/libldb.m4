AC_SUBST(LDB_OBJ)
AC_SUBST(LDB_CFLAGS)
AC_SUBST(LDB_LIBS)

AC_CHECK_HEADER(ldb.h,
   [AC_CHECK_LIB(ldb, ldb_init, [LDB_LIBS="-lldb"], , -levents) ],
   [PKG_CHECK_MODULES(LDB, ldb >= 0.9.2)])
