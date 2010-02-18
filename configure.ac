m4_include([version.m4])
AC_INIT([sssd],
        VERSION_NUMBER,
        [sssd-devel@lists.fedorahosted.org])
AC_CONFIG_SRCDIR([BUILD.txt])
AC_CONFIG_AUX_DIR([build])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_INSTALL

AC_CONFIG_SUBDIRS([common src])

AC_SUBST([PRERELEASE_VERSION],
         PRERELEASE_VERSION_NUMBER)

AM_CONDITIONAL([GIT_CHECKOUT], [git log -1 &>/dev/null])

AC_CONFIG_FILES([Makefile contrib/sssd.spec])
AC_OUTPUT
