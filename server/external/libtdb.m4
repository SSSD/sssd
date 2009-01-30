AC_SUBST(TDB_OBJ)
AC_SUBST(TDB_CFLAGS)
AC_SUBST(TDB_LIBS)

AC_CHECK_HEADERS([tdb.h],
   [AC_CHECK_LIB(tdb, tdb_repack, [TDB_LIBS="-ltdb"], [AC_MSG_ERROR([TDB must support tdb_repack])]) ],
   [PKG_CHECK_MODULES(TDB, tdb >= 1.1.3)]
)
