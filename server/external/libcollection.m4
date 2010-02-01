AC_SUBST(SYSTEM_COLLECTION_OBJ)
AC_SUBST(SYSTEM_COLLECTION_CFLAGS)
AC_SUBST(SYSTEM_COLLECTION_LIBS)

PKG_CHECK_MODULES(SYSTEM_COLLECTION, collection >= 0.4.0,
    have_system_collection=true,
    have_system_collection=false
    )
# This is future-compatible. Right now, we'll force the use of our
# in-tree copy. When collection is split off as its own source package, we'll
# fix this test
AM_CONDITIONAL(HAVE_SYSTEM_COLLECTION, test x$have_system_collection = xtrue_FORCE_IN_TREE)
