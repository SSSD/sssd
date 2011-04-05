dnl A macro to check presence of systemd on the system
AC_DEFUN([AM_CHECK_SYSTEMD],
[
    PKG_CHECK_EXISTS(systemd,
                     [ HAVE_SYSTEMD=1, AC_SUBST(HAVE_SYSTEMD) ],
                     [AC_MSG_ERROR([Could not detect systemd presence])]
                    )
])
