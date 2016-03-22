PKG_CHECK_MODULES(INI_CONFIG_V0, [
    ini_config >= 0.6.1], [

        INI_CONFIG_CFLAGS="$INI_CONFIG_V0_CFLAGS"
        INI_CONFIG_LIBS="$INI_CONFIG_V0_LIBS"
        HAVE_LIBINI_CONFIG_V0=1
        AC_DEFINE_UNQUOTED(HAVE_LIBINI_CONFIG_V0, 1, [libini_config version 0.6.1 or greater])
        PKG_CHECK_MODULES(INI_CONFIG_V1, [
            ini_config >= 1.0.0], [

                INI_CONFIG_CFLAGS="$INI_CONFIG_V1_CFLAGS"
                INI_CONFIG_LIBS="$INI_CONFIG_V1_LIBS"
                HAVE_LIBINI_CONFIG_V1=1
                AC_DEFINE_UNQUOTED(HAVE_LIBINI_CONFIG_V1, 1, [libini_config version 1.0.0 or greater])
                PKG_CHECK_MODULES(INI_CONFIG_V1_1, [
                    ini_config >= 1.1.0], [

                        INI_CONFIG_CFLAGS="$INI_CONFIG_V1_1_CFLAGS"
                        INI_CONFIG_LIBS="$INI_CONFIG_V1_1_LIBS"
                        HAVE_LIBINI_CONFIG_V1_1=1
                        AC_DEFINE_UNQUOTED(HAVE_LIBINI_CONFIG_V1_1, 1, [libini_config version 1.1.0 or greater])
                        PKG_CHECK_MODULES(INI_CONFIG_V1_3, [
                            ini_config >= 1.3.0], [

                                INI_CONFIG_CFLAGS="$INI_CONFIG_V1_3_CFLAGS"
                                INI_CONFIG_LIBS="$INI_CONFIG_V1_3_LIBS"
                                HAVE_LIBINI_CONFIG_V1_3=1
                                AC_DEFINE_UNQUOTED(HAVE_LIBINI_CONFIG_V1_3, 1,
                                                   [libini_config version 1.3.0 or greater])
                            ], [
                                AC_MSG_WARN([libini_config-devel >= 1.3.0 not available, using older version])
                            ]
                        )
                    ], [
                        AC_MSG_WARN([libini_config-devel >= 1.1.0 not available, using older version])
                    ]
                )
            ], [
                AC_MSG_WARN([libini_config-devel >= 1.0.0 not available, using older version])
            ]
        )
    ], [
        AC_MSG_ERROR([Please install libini_config-devel])
    ]
)

AC_SUBST(INI_CONFIG_CFLAGS)
AC_SUBST(INI_CONFIG_LIBS)
