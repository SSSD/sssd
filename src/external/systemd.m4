dnl There are no module libsystemd-journal and libsystem-login
dnl up systemd version 209
PKG_CHECK_EXISTS([libsystemd],
                 [HAVE_LIBSYSTEMD=yes],
                 [HAVE_LIBSYSTEMD=no])

dnl A macro to check presence of systemd on the system
AC_DEFUN([AM_CHECK_SYSTEMD],
[
    PKG_CHECK_EXISTS(systemd,
                     [ HAVE_SYSTEMD=1, AC_SUBST(HAVE_SYSTEMD) ],
                     [AC_MSG_ERROR([Could not detect systemd presence])])
])

AS_IF([test x$HAVE_LIBSYSTEMD = xyes],
      [login_lib_name=libsystemd],
      [login_lib_name=libsystemd-login])

AM_COND_IF([HAVE_SYSTEMD],
           [AC_DEFINE_UNQUOTED([HAVE_SYSTEMD], 1, [Build with libsystemd support])],
           [AC_MSG_NOTICE([Build without libsystemd support])])

AM_COND_IF([HAVE_SYSTEMD],
           [PKG_CHECK_MODULES([SYSTEMD_LOGIN],
                              [$login_lib_name],
                              [AC_DEFINE_UNQUOTED([HAVE_SYSTEMD_LOGIN], 1,
                                          [Build with libsystemdlogin support])
                              ],
           [AC_MSG_NOTICE([Build without libsystemd-login support])])])

dnl A macro to check presence of journald on the system
AC_DEFUN([AM_CHECK_JOURNALD],
[
    AS_IF([test x$HAVE_LIBSYSTEMD = xyes],
          [journal_lib_name=libsystemd],
          [journal_lib_name=libsystemd-journal])

    PKG_CHECK_MODULES(JOURNALD, [$journal_lib_name],
                      [AC_DEFINE_UNQUOTED([WITH_JOURNALD], 1,
                                          [journald is available])])
    dnl Some older versions of pkg-config might not set these automatically
    dnl while setting CFLAGS and LIBS manually twice doesn't hurt.
    AC_SUBST([JOURNALD_CFLAGS])
    AC_SUBST([JOURNALD_LIBS])
])
