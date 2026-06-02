AC_DEFUN([AM_CHECK_LIBCRYPTO],
         [PKG_CHECK_MODULES([CRYPTO], [libcrypto >= 3.0.8], [],
                            [AC_MSG_ERROR([Please install libcrypto version 3.0.8 or greater])])
          PKG_CHECK_MODULES([SSL],[libssl])
])
