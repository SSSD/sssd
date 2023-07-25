AC_SUBST(PCRE_LIBS)
AC_SUBST(PCRE_CFLAGS)

PKG_CHECK_MODULES(
    [PCRE],
    [libpcre2-8],
    [
        found_libpcre=yes
        AC_DEFINE(
            [HAVE_LIBPCRE2],
            1,
            [Define if libpcre2 is present]
        )
        AC_DEFINE(
            [PCRE2_CODE_UNIT_WIDTH],
            8,
            [Define libpcre2 unit size]
        )
    ],
    [
        PKG_CHECK_MODULES(
            [PCRE],
            [libpcre],
            [
                found_libpcre=yes
                PKG_CHECK_EXISTS(
                    libpcre >= 7,
                    [AC_MSG_NOTICE([PCRE version is 7 or higher])],
                    [
                        AC_MSG_NOTICE([PCRE version is below 7])
                        AC_DEFINE(
                            [HAVE_LIBPCRE_LESSER_THAN_7],
                            1,
                            [Define if libpcre version is less than 7]
                        )
                    ]
                )
            ],
            [found_libpcre=no]
        )
    ]
)

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_libpcre" != xyes],
    [AC_CHECK_HEADERS([pcre.h],
        [AC_CHECK_LIB([pcre],
                      [pcre_compile],
                      [PCRE_LIBS="-L$sss_extra_libdir -lpcre"],
                      [AC_MSG_ERROR([No usable PCRE library found])],
                      [-L$sss_extra_libdir])],
        [AC_MSG_ERROR([pcre header files are not installed])])]
)
