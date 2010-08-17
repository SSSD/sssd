AC_SUBST(INI_CONFIG_OBJ)
AC_SUBST(INI_CONFIG_CFLAGS)
AC_SUBST(INI_CONFIG_LIBS)

PKG_CHECK_MODULES(INI_CONFIG,
    ini_config >= 0.6.1,
    ,
    AC_MSG_ERROR("Please install libini_config-devel")
    )

