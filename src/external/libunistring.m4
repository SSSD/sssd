SSS_AC_EXPAND_LIB_DIR()

AC_CHECK_HEADERS([unistr.h],
    [AC_CHECK_LIB([unistring],
                  [u8_strlen],
                  [UNISTRING_LIBS="-lunistring"],
                  [AC_MSG_ERROR([No usable libunistring library found])],
                  [-L$sss_extra_libdir])],
    [AC_MSG_ERROR([libunistring header files are not installed])]
)

AC_CHECK_HEADERS([unicase.h],
    [AC_CHECK_LIB([unistring],
                  [u8_casecmp],
                  [UNISTRING_LIBS="-lunistring"],
                  [AC_MSG_ERROR([No usable libunistring library found])],
                  [-L$sss_extra_libdir])],
    [AC_MSG_ERROR([libunistring header files are not installed])]
)

AC_CHECK_HEADERS([unistr.h],
    [AC_CHECK_LIB([unistring],
                  [u8_check],
                  [UNISTRING_LIBS="-lunistring"],
                  [AC_MSG_ERROR([No usable libunistring library found])],
                  [-L$sss_extra_libdir])],
    [AC_MSG_ERROR([libunistring header files are not installed])]
)


UNISTRING_LIBS="-L$sss_extra_libdir $UNISTRING_LIBS "
