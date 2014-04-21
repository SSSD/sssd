AC_ARG_ENABLE([config-lib],
              [AS_HELP_STRING([--disable-config-lib],
                              [do not build internal config library])],
              [build_config_lib=$enableval],
              [build_config_lib=yes])

AM_CONDITIONAL([BUILD_CONFIG_LIB],
               [test x$build_config_lib = xyes])

AM_COND_IF([BUILD_CONFIG_LIB],
           [AC_DEFINE_UNQUOTED(HAVE_CONFIG_LIB, 1,
            [Build with internal config library])])