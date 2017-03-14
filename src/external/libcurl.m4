AC_ARG_ENABLE([curl],
              [AS_HELP_STRING([--disable-curl-support],
                              [do not build with libcurl support])],
              [enable_libcurl=$enableval],
              [enable_libcurl=yes])

found_libcurl="no"
AS_IF([test x$enable_libcurl = xyes],
      [PKG_CHECK_MODULES([CURL],
                         [libcurl],
                         [found_libcurl=yes],
                         [AC_MSG_WARN([
The libcurl development library was not found. Some features will be disabled.])
      ])])

AS_IF([test x"$found_libcurl" = xyes],
    CFLAGS="$CFLAGS $CURL_CFLAGS"

    AC_MSG_CHECKING([For CURLOPT_UNIX_SOCKET_PATH support in libcurl])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
    [[#include <curl/curl.h>
    CURLoption opt = CURLOPT_UNIX_SOCKET_PATH;
    ]])],
                    [have_curlopt_unix_sockpath=yes]
                    [AC_MSG_RESULT([yes])],
                    [have_curlopt_unix_sockpath=no]
                    [AC_MSG_RESULT([no, libcurl support will be disabled])],)

    CFLAGS=$SAVE_CFLAGS
)

AC_SUBST(CURL_LIBS)
AC_SUBST(CURL_CFLAGS)

AM_CONDITIONAL([BUILD_WITH_LIBCURL],
               [test x"$have_curlopt_unix_sockpath" = xyes])
AM_COND_IF([BUILD_WITH_LIBCURL],
           [AC_DEFINE_UNQUOTED(HAVE_LIBCURL, 1, [Build with libcurl support])])
