AC_SUBST(CARES_OBJ)
AC_SUBST(CARES_LIBS)
AC_SUBST(CARES_CFLAGS)

PKG_CHECK_MODULES([CARES], [libcares], [found_libcares=yes], [found_libcares=no])

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_libcares" != xyes],
    [AC_CHECK_HEADERS([ares.h],
        [AC_CHECK_LIB([cares],
                      [ares_init],
                      [CARES_LIBS="-L$sss_extra_libdir -lcares"],
                      [AC_MSG_ERROR([No usable c-ares library found])],
                      [-L$sss_extra_libdir])],
        [AC_MSG_ERROR([c-ares header files are not installed])])]
)

dnl Check if this particular version of c-ares supports the generic ares_free_data function
AC_CHECK_LIB([cares],
             [ares_free_data],
             [AC_DEFINE([HAVE_ARES_DATA], 1, [Does c-ares have ares_free_data()?])
             ],
             [ares_data=1],
             [$CARES_LIBS]
)

AM_CONDITIONAL(BUILD_ARES_DATA, test x$ares_data = x1)

dnl Check if this particular version of c-ares support the new TTL structures
AC_CHECK_TYPES([struct ares_addrttl, struct ares_addr6ttl], [], [], [#include <ares.h>])
