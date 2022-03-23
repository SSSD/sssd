AC_SUBST(PATHUTILS_CFLAGS)
AC_SUBST(PATHUTILS_LIBS)

PKG_CHECK_MODULES(PATHUTILS,
    path_utils,
    found_libpath_utils=yes,
    AC_MSG_ERROR("Please install path_utils")
    )
