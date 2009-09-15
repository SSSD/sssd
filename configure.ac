AC_INIT([sssd],
        m4_esyscmd([cat VERSION |head -n1 | tr -d '\n']),
        [sssd-devel@lists.fedorahosted.org])
AC_CONFIG_SRCDIR([BUILD.txt])
AC_CONFIG_AUX_DIR([build])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_INSTALL

AC_CONFIG_SUBDIRS([replace common server sss_client])

# If the VERSION file has a second line, we'll append it
# to the release tag when creating an RPM or SRPM
# This is intended for build systems to create snapshot
# RPMs. The format should be something like:
# .20090915gitf1bcde7
# and would result in an SRPM looking like:
# sssd-0.5.0-0.20090915gitf1bcde7.fc11.src.rpm
AC_SUBST([PRERELEASE_VERSION],
         m4_esyscmd([cat VERSION |tail --lines=+2 |head -n1 | tr -d '\n']))

AC_CONFIG_FILES([Makefile contrib/sssd.spec])
AC_OUTPUT
