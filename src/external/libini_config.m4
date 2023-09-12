PKG_CHECK_MODULES(INI_CONFIG_V1_3, [
    ini_config >= 1.3.0], [
        INI_CONFIG_CFLAGS="$INI_CONFIG_V1_3_CFLAGS"
        INI_CONFIG_LIBS="$INI_CONFIG_V1_3_LIBS"
    ], [
        AC_MSG_ERROR([Please install libini_config-devel version 1.3.0 or greater])
    ]
)

AC_SUBST(INI_CONFIG_CFLAGS)
AC_SUBST(INI_CONFIG_LIBS)
