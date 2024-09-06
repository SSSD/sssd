AC_SUBST(CURL_LIBS)
AC_SUBST(CURL_CFLAGS)

PKG_CHECK_MODULES([CURL], [libcurl], [found_libcurl=yes], [found_libcurl=no])

AC_MSG_CHECKING([whether libcurl knows CURLOPT_PROTOCOLS_STR])

AC_LINK_IFELSE(
    [AC_LANG_SOURCE([
#include <curl/curl.h>
int main () {
    return CURLOPT_PROTOCOLS_STR;
}])],
    [AC_MSG_RESULT([yes]); AC_DEFINE_UNQUOTED([HAVE_CURLOPT_PROTOCOLS_STR], [1], [CURLOPT_PROTOCOLS_STR available]) ],
    [AC_MSG_RESULT([no])]
)
