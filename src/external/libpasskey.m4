AC_SUBST(PASSKEY_LIBS)
AC_SUBST(PASSKEY_CFLAGS)

PKG_CHECK_MODULES([FIDO2], [libfido2], [found_passkey=yes], [found_passkey=no])

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_passkey" = xyes],
    [AC_CHECK_HEADER([fido.h],
        [AC_CHECK_LIB([fido2],
                      [es256_pk_from_EVP_PKEY],
                      [found_passkey=yes] [PASSKEY_LIBS="-lfido2"],
                      [found_passkey=no])],
        [found_passkey=no]
    )]
)
