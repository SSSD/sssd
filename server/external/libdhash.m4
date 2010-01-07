AC_SUBST(SYSTEM_DHASH_OBJ)
AC_SUBST(SYSTEM_DHASH_CFLAGS)
AC_SUBST(SYSTEM_DHASH_LIBS)

PKG_CHECK_MODULES(SYSTEM_DHASH, dhash >= 0.4.0,
    have_system_dhash=true,
    have_system_dhash=false
    )
# This is future-compatible. Right now, we'll force the use of our
# in-tree copy. When dhash is split off as its own source package, we'll
# fix this test
AM_CONDITIONAL(HAVE_SYSTEM_DHASH, test x$have_system_dhash = xtrue_FORCE_IN_TREE)
