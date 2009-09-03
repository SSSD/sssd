AC_INIT([sssd],
        m4_esyscmd([cat VERSION |head -n1 | tr -d '\n']),
        [sssd-devel@lists.fedorahosted.org])
AC_CONFIG_SRCDIR([BUILD.txt])
AC_CONFIG_AUX_DIR([build])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_INSTALL

AC_CONFIG_SUBDIRS([replace common server sss_client])

AC_CONFIG_FILES([Makefile contrib/sssd.spec])
AC_OUTPUT
