AC_SUBST(PCRE_LIBS)
AC_SUBST(PCRE_CFLAGS)

PKG_CHECK_MODULES(
    [PCRE],
    [libpcre2-8],
    [
        found_libpcre=yes
        AC_DEFINE(
            [PCRE2_CODE_UNIT_WIDTH],
            8,
            [Define libpcre2 unit size]
        )
    ],
    [
        found_libpcre=no
    ]
)

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_libpcre" != xyes],
    [AC_CHECK_HEADERS([pcre2.h],
        [AC_CHECK_LIB([libpcre2-8],
                      [pcre2_compile],
                      [PCRE_LIBS="-L$sss_extra_libdir -lpcre2-8"],
                      [AC_MSG_ERROR([No usable PCRE2 library found])],
                      [-L$sss_extra_libdir])],
        [AC_MSG_ERROR([pcre2 header files are not installed])])]
)
