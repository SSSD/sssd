AC_SUBST(DHASH_CFLAGS)
AC_SUBST(DHASH_LIBS)

PKG_CHECK_MODULES(DHASH,
    dhash >= 0.4.2,
    ,
    AC_MSG_ERROR("Please install libdhash-devel")
    )

