AC_DEFUN([AM_CHECK_NSS],
         [PKG_CHECK_MODULES([NSS],[nss])
          AC_DEFINE_UNQUOTED(HAVE_NSS, 1, [Build with NSS crypto back end])
])

AC_DEFUN([AM_CHECK_LIBCRYPTO],
         [PKG_CHECK_MODULES([CRYPTO],[libcrypto])
          PKG_CHECK_MODULES([SSL],[libssl])
          AC_DEFINE_UNQUOTED(HAVE_LIBCRYPTO, 1, [Build with libcrypt crypto back end])
])
