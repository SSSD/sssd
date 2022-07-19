AC_SUBST(FIDO2_LIBS)
AC_SUBST(FIDO2_CFLAGS)

PKG_CHECK_MODULES([FIDO2], [libfido2], [found_fido2=yes], [found_fido2=no])
