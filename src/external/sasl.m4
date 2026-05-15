AC_SUBST(SASL_LIBS)
AC_SUBST(SASL_CFLAGS)

PKG_CHECK_MODULES([SASL], [libsasl2], [found_sasl=yes], [found_sasl=no])

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_sasl" != xyes],
    [AC_CHECK_HEADERS([sasl/sasl.h],
        [AC_CHECK_LIB([sasl2],
                      [sasl_client_init],
                      [SASL_LIBS="-L$sss_extra_libdir -lsasl2"],
                      [AC_MSG_ERROR([SASL library must support sasl_client_init])],
                      [-L$sss_extra_libdir])],
        [AC_MSG_ERROR([SASL header files are not installed])])]
)
