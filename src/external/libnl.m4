dnl A macro to check if this particular version of libnl supports particular common libnl functions
AC_DEFUN([AM_CHECK_LIBNL_FCS],
[
    AC_CHECK_LIB($1,
                 [nl_socket_add_membership],
                 [AC_DEFINE([HAVE_NL_SOCKET_ADD_MEMBERSHIP], 1, [Does libnl have nl_socket_add_membership?])
                 ],
    )

    AC_CHECK_LIB($1,
                 [nl_socket_modify_cb],
                 [AC_DEFINE([HAVE_NL_SOCKET_MODIFY_CB], 1, [Does libnl have nl_socket_modify_cb?])
                 ],
    )

    AC_CHECK_LIB($1,
                 [rtnl_route_get_oif],
                 [AC_DEFINE([HAVE_RTNL_ROUTE_GET_OIF], 1, [Does libnl have rtnl_route_get_oif?])
                 ],
    )

    AC_CHECK_LIB($1,
                 [nl_set_passcred],
                 [AC_DEFINE([HAVE_NL_SET_PASSCRED], 1, [Does libnl have nl_set_passcred?])
                 ],
    )

    AC_CHECK_LIB($1,
                 [nl_socket_set_passcred],
                 [AC_DEFINE([HAVE_NL_SOCKET_SET_PASSCRED], 1, [Does libnl have nl_socket_set_passcred?])
                 ],
    )
])

dnl A macro to check the availability and version of libnetlink
AC_DEFUN([AM_CHECK_LIBNL1],
[
    PKG_CHECK_MODULES(LIBNL1, libnl-1 >= 1.1,[

        HAVE_LIBNL=1
        HAVE_LIBNL1=1

        LIBNL_CFLAGS="$LIBNL1_CFLAGS"
        LIBNL_LIBS="$LIBNL1_LIBS"

        AC_DEFINE_UNQUOTED(HAVE_LIBNL, 1, [Build with libnetlink support])
        AC_DEFINE_UNQUOTED(HAVE_LIBNL1, 1, [Libnetlink version = 1])

        AC_MSG_NOTICE([Building with libnl])

        AC_CHECK_HEADERS(netlink.h)
        AC_CHECK_LIB(nl, nl_connect, [ LIBNL_LIBS="-lnl" ], [AC_MSG_ERROR([libnl is required])])

        AM_CHECK_LIBNL_FCS(nl)


    ],[AC_MSG_WARN([Netlink v1 support unavailable or too old])])

    AC_SUBST(LIBNL_CFLAGS)
    AC_SUBST(LIBNL_LIBS)
])

dnl A macro to check the availability of libnetlink version 3

AC_DEFUN([AM_CHECK_LIBNL3],
[
    PKG_CHECK_MODULES(LIBNL3, [
        libnl-3.0 >= 3.0
        libnl-route-3.0 >= 3.0], [

        HAVE_LIBNL=1
        HAVE_LIBNL3=1

        LIBNL_CFLAGS="$LIBNL3_CFLAGS"
        LIBNL_LIBS="$LIBNL3_LIBS"

        AC_DEFINE_UNQUOTED(HAVE_LIBNL, 1, [Build with libnetlink support])
        AC_DEFINE_UNQUOTED(HAVE_LIBNL3, 1, [Libnetlink version = 3])

        AC_MSG_NOTICE([Building with libnl3])

        AM_CHECK_LIBNL_FCS(nl-3)

    ],[AC_MSG_WARN([Netlink v3 support unavailable or too old])])

    AC_SUBST(LIBNL_CFLAGS)
    AC_SUBST(LIBNL_LIBS)
])
