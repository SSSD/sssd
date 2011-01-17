dnl A macro to check the availability and version of libnetlink

AC_DEFUN([AM_CHECK_LIBNL],
[
    PKG_CHECK_MODULES(libnl, libnl-1 >= 1.1,[
        HAVE_LIBNL=1
        AC_SUBST(HAVE_LIBNL)
        AC_DEFINE_UNQUOTED(HAVE_LIBNL, 1, [Build with libnetlink support])

	    AC_CHECK_HEADERS(netlink.h)
	    AC_CHECK_LIB(nl, nl_connect, [ LIBNL_LIBS="-lnl" ], [AC_MSG_ERROR([libnl is required])])

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
    ],[AC_MSG_WARN([Netlink support unavailable or too old])])

    AC_SUBST(LIBNL_CFLAGS)
    AC_SUBST(LIBNL_LIBS)
])
