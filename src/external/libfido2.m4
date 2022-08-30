AC_SUBST(FIDO2_LIBS)
AC_SUBST(FIDO2_CFLAGS)

PKG_CHECK_MODULES([FIDO2], [libfido2], [found_fido2=yes], [found_fido2=no])

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_fido2" = xyes],
    [AC_CHECK_HEADER([fido.h],
        [AC_CHECK_LIB([fido2],
                      [fido_dev_has_uv],
                      [found_fido2=yes],
                      [found_fido2=no])],
        [ble=no]
    )]
)
