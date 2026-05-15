if test x"$with_syslog" = xjournald || \
     test x"$with_initscript" = xsystemd;  then

    dnl A macro to check presence of systemd on the system
    PKG_CHECK_EXISTS([systemd],
                     [HAVE_SYSTEMD=yes],
                     [HAVE_SYSTEMD=no])

    dnl Libraries libsystemd-journal and libsystem-login are deprecarted
    dnl since systemd 209 and are removed in systemd 230. The library libsystemd
    dnl is replacement of libsystemd-{login,journal,daemon,id128} libraries
    PKG_CHECK_EXISTS([libsystemd],
                     [HAVE_LIBSYSTEMD=yes],
                     [HAVE_LIBSYSTEMD=no])

    AS_IF([test x$HAVE_LIBSYSTEMD = xyes],
          [login_lib_name=libsystemd],
          [login_lib_name=libsystemd-login])

    AS_IF([test x$HAVE_SYSTEMD = xyes],
          [AC_DEFINE_UNQUOTED([HAVE_SYSTEMD], 1, [Build with systemd support])],
          [AC_MSG_NOTICE([Build without systemd support])])

    AS_IF([test x$HAVE_SYSTEMD = xyes],
          [PKG_CHECK_MODULES(
              [SYSTEMD_LOGIN],
              [$login_lib_name],
              [AC_DEFINE_UNQUOTED([HAVE_SYSTEMD_LOGIN], 1,
                                  [Build with $login_lib_name support])],
              [AC_MSG_NOTICE([Build without $login_lib_name support])])],
          [AC_MSG_NOTICE([Build without $login_lib_name support])])

    AS_IF([test x$HAVE_LIBSYSTEMD = xyes],
          [daemon_lib_name=libsystemd],
          [daemon_lib_name=libsystemd-daemon])

    AS_IF([test x$HAVE_SYSTEMD = xyes],
          [PKG_CHECK_MODULES(
              [SYSTEMD_DAEMON],
              [$daemon_lib_name],
              [AC_DEFINE_UNQUOTED([HAVE_SYSTEMD_DAEMON], 1,
                                  [Build with $daemon_lib_name support])],
              [AC_MSG_NOTICE([Build without $daemon_lib_name support])])],
          [AC_MSG_NOTICE([Build without $daemon_lib_name support])])

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
fi
