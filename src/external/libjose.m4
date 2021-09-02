AC_SUBST(JOSE_LIBS)
AC_SUBST(JOSE_CFLAGS)

PKG_CHECK_MODULES([JOSE], [jose], [found_jose=yes], [found_jose=no])
