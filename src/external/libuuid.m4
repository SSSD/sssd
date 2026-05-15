AC_SUBST(UUID_LIBS)
AC_SUBST(UUID_CFLAGS)

PKG_CHECK_MODULES([UUID], [uuid], [found_uuid=yes], [found_uuid=no])

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_uuid" != xyes],
    [AC_CHECK_HEADERS([uuid/uuid.h],
        [AC_CHECK_LIB([uuid],
                      [uuid_generate],
                      [UUID_LIBS="-L$sss_extra_libdir -luuid"],
                      [AC_MSG_ERROR([libuuid missing uuid_generate])],
                      [-L$sss_extra_libdir -luuid])],
        [AC_MSG_ERROR([
You must have the header file uuid.h installed to build sssd
with KCM responder. If you want to build sssd without KCM responder
then specify --without-kcm when running configure.])])])
