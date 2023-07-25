AC_SUBST(CURL_LIBS)
AC_SUBST(CURL_CFLAGS)

PKG_CHECK_MODULES([CURL], [libcurl], [found_libcurl=yes], [found_libcurl=no])
