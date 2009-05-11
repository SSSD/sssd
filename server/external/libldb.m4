AC_SUBST(LDB_OBJ)
AC_SUBST(LDB_CFLAGS)
AC_SUBST(LDB_LIBS)

PKG_CHECK_MODULES(LDB, ldb >= 0.9.2)

AC_CHECK_HEADERS(ldb.h ldb_module.h,
   [AC_CHECK_LIB(ldb, ldb_init, [LDB_LIBS="-lldb"], , -ltevent) ],
   [AC_MSG_ERROR([LDB header files are not installed])]
)
