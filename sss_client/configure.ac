AC_PREREQ(2.50)
AC_INIT([sss_client], 0.4.0, [freeipa-devel@redhat.com])
AC_CONFIG_SRCDIR([common.c])
AC_CONFIG_HEADER(config.h)
AC_CONFIG_AUX_DIR([build])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AM_GNU_GETTEXT([external])

AC_SUBST(PAM_LIBS)

#Check for PAM headers
AC_CHECK_HEADERS([security/pam_appl.h security/pam_misc.h security/pam_modules.h],
    [AC_CHECK_LIB(pam, pam_get_item, [ PAM_LIBS="-lpam" ], [AC_MSG_ERROR([PAM must support pam_get_item])])],
    [AC_MSG_ERROR([PAM development libraries not installed])]
)

#Set the NSS library install path
AC_ARG_ENABLE([nsslibdir], [AS_HELP_STRING([--enable-nssdir],
                                        [Where to install nss libraries ($(prefix)/lib)])],
              [nsslibdir=$enableval],
              [nsslibdir=$prefix/lib64])
AC_SUBST(nsslibdir)
AC_CONFIG_FILES([Makefile po/Makefile.in])
AC_OUTPUT
