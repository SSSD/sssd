AC_SUBST(KEYUTILS_LIBS)

AC_CHECK_HEADERS([keyutils.h],
                 [AC_CHECK_LIB([keyutils], [add_key],
                               [AC_DEFINE(USE_KEYRING, 1, [Define if the keyring should be used])
                                KEYUTILS_LIBS="-lkeyutils"
                               ],
                               [AC_MSG_WARN([No usable keyutils library found])]
                              )],
                 [AC_MSG_WARN([keyutils header files are not available])]
)
