AC_DEFUN([AM_CHECK_LIBCRYPTO],
         [PKG_CHECK_MODULES([CRYPTO],[libcrypto])
          PKG_CHECK_MODULES([SSL],[libssl])
])

AC_MSG_CHECKING([whether OpenSSL's x400Address is ASN1_STRING])
SAVE_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS -Werror -Wall -Wextra"
AC_COMPILE_IFELSE(
                  [AC_LANG_SOURCE([
                      #include <openssl/x509v3.h>

                      int main(void)
                      {
                          GENERAL_NAME gn = { 0 };

                          return ASN1_STRING_length(gn.d.x400Address);
                      }
                  ])],
                  [
                      AC_MSG_RESULT([yes])
                      AC_DEFINE([HAVE_X400ADDRESS_STRING],
                             [1],
                             [whether OpenSSL's x400Address is ASN1_STRING])],
                  [
                      AC_MSG_RESULT([no])
                      AC_MSG_WARN([OpenSSL's x400Address is not of ASN1_STRING type])
                  ])

CFLAGS=$SAVE_CFLAGS
