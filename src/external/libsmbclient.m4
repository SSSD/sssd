AC_SUBST(SMBCLIENT_CFLAGS)
AC_SUBST(SMBCLIENT_LIBS)

PKG_CHECK_MODULES(SMBCLIENT, smbclient, ,
    AC_MSG_ERROR("Please install libsmbclient development libraries"))
