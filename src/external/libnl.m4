dnl A macro to check the availability and version of libnetlink
AC_DEFUN([AM_CHECK_LIBNL],
[
    PKG_CHECK_MODULES(libnl, libnl-1)

    AC_CHECK_HEADERS(netlink.h)
    AC_CHECK_LIB(nl, nl_connect, [ LIBNL_LIBS="-lnl" ], [AC_MSG_ERROR([libnl is required])])

    AC_CHECK_LIB([nl],
                 [nl_handle_get_fd],
                 [AC_DEFINE([HAVE_LIBNL_OLDER_THAN_1_1], 1, [Does libnl have pre-1.1 API?])
                 ],
    )

    dnl Check if this particular version of libnl supports particular functions
    AC_CHECK_LIB([nl],
                 [nl_socket_add_membership],
                 [AC_DEFINE([HAVE_NL_SOCKET_ADD_MEMBERSHIP], 1, [Does libnl have nl_socket_add_membership?])
                 ],
    )

    AC_CHECK_LIB([nl],
                 [nl_socket_modify_cb],
                 [AC_DEFINE([HAVE_NL_SOCKET_MODIFY_CB], 1, [Does libnl have nl_socket_modify_cb?])
                 ],
    )

    AC_CHECK_LIB([nl],
                 [nl_set_passcred],
                 [AC_DEFINE([HAVE_NL_SET_PASSCRED], 1, [Does libnl have nl_set_passcred?])
                 ],
    )

    AC_SUBST(LIBNL_CFLAGS)
    AC_SUBST(LIBNL_LIBS)
])
