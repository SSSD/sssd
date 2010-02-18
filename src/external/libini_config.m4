AC_SUBST(SYSTEM_INI_CONFIG_OBJ)
AC_SUBST(SYSTEM_INI_CONFIG_CFLAGS)
AC_SUBST(SYSTEM_INI_CONFIG_LIBS)

PKG_CHECK_MODULES(SYSTEM_INI_CONFIG, ini_config >= 0.4.0,
    have_system_ini_config=true,
    have_system_ini_config=false
    )
# This is future-compatible. Right now, we'll force the use of our
# in-tree copy. When ini_config is split off as its own source package, we'll
# fix this test
AM_CONDITIONAL(HAVE_SYSTEM_INI_CONFIG, test x$have_system_ini_config = xtrue_FORCE_IN_TREE)
