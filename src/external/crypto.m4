AC_DEFUN([AM_CHECK_LIBCRYPTO],
         [PKG_CHECK_MODULES([CRYPTO],[libcrypto])
          PKG_CHECK_MODULES([SSL],[libssl])
])
