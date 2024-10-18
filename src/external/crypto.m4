AC_DEFUN([AM_CHECK_LIBCRYPTO],
         [PKG_CHECK_MODULES([CRYPTO], [libcrypto >= 1.0.1], [],
                            [AC_MSG_ERROR([Please install libcrypto version 1.0.1 or greater])])
          PKG_CHECK_MODULES([SSL],[libssl])
])

AC_MSG_CHECKING([whether OpenSSL's x400Address is ASN1_STRING])
AC_COMPILE_IFELSE(
                  [AC_LANG_SOURCE([
                      #include <openssl/x509v3.h>

                      int main(void)
                      {
                          GENERAL_NAME gn = { 0 };
                          /* If the types are different, the compiler will error out. */
                          gn.d.x400Address - (ASN1_STRING *)0;
                          return 0;
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
