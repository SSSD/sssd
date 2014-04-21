AC_SUBST(AUGEAS_OBJ)
AC_SUBST(AUGEAS_CFLAGS)
AC_SUBST(AUGEAS_LIBS)

PKG_CHECK_MODULES(AUGEAS,
    augeas >= 1.0.0,
    ,
    AC_MSG_ERROR([
Please install augeas-devel or disable this dependency
by specifying --disable-config-lib when running configure.])
    )
