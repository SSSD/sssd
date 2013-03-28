PKG_CHECK_MODULES(INI_CONFIG, [
    ini_config >= 1.0.0], [

        AC_DEFINE_UNQUOTED(HAVE_LIBINI_CONFIG_V1, 1, [libini_config version greater than 1.0.0])
    ], [
        AC_MSG_WARN([libini_config-devel >= 1.0.0 not available, trying older version])
        PKG_CHECK_MODULES(INI_CONFIG, [
            ini_config >= 0.6.1], [

                AC_DEFINE_UNQUOTED(HAVE_LIBINI_CONFIG_V0, 1, [libini_config version lesser than 1.0.0])
            ], [
                AC_MSG_ERROR([Please install libini_config-devel])
            ]
        )
    ]
)

AC_SUBST(INI_CONFIG_OBJ)
AC_SUBST(INI_CONFIG_CFLAGS)
AC_SUBST(INI_CONFIG_LIBS)
