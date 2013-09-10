dnl A macro to check presence of systemd on the system
AC_DEFUN([AM_CHECK_SYSTEMD],
[
    PKG_CHECK_EXISTS(systemd,
                     [ HAVE_SYSTEMD=1, AC_SUBST(HAVE_SYSTEMD) ],
                     [AC_MSG_ERROR([Could not detect systemd presence])]
                    )
])
AM_COND_IF([HAVE_SYSTEMD],
           [PKG_CHECK_MODULES([SYSTEMD_LOGIN], [libsystemd-login],
            [AC_DEFINE_UNQUOTED(HAVE_SYSTEMD_LOGIN, 1, [Build with libsystemdlogin support])],
            [AC_DEFINE_UNQUOTED(HAVE_SYSTEMD_LOGIN, 0, [Build without libsystemd-login support])])])
