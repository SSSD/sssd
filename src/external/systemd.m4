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
            [AC_MSG_NOTICE([Build without libsystemd-login support])])])

dnl A macro to check presence of journald on the system
AC_DEFUN([AM_CHECK_JOURNALD],
[
       PKG_CHECK_MODULES(JOURNALD,
                         libsystemd-journal,
                         [AC_DEFINE_UNQUOTED([WITH_JOURNALD], 1, [journald is available])])
       dnl Some older versions of pkg-config might not set these automatically
       dnl while setting CFLAGS and LIBS manually twice doesn't hurt.
       AC_SUBST([JOURNALD_CFLAGS])
       AC_SUBST([JOURNALD_LIBS])
])
