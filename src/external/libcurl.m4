PKG_CHECK_MODULES([CURL], [libcurl], [found_libcurl=yes],
              [AC_MSG_ERROR([The libcurl development library was not found.
You must have the header file curl/curl.h installed to build sssd
with secrets and KCM responder. If you want to build sssd without these
responders then specify --without-secrets --without-kcm when running configure.
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

AM_COND_IF([BUILD_WITH_LIBCURL],
           [AC_DEFINE_UNQUOTED(HAVE_LIBCURL, 1, [Build with libcurl support])])
