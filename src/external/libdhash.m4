AC_SUBST(DHASH_OBJ)
AC_SUBST(DHASH_CFLAGS)
AC_SUBST(DHASH_LIBS)

PKG_CHECK_MODULES(DHASH,
    dhash >= 0.4.0,
    ,
    AC_MSG_ERROR("Please install libdhash-devel")
    )

