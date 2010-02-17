AC_PREREQ(2.50)
m4_include([../version.m4])
AC_INIT([sss_client],
        VERSION_NUMBER,
        [sssd-devel@lists.fedorahosted.org])
AC_CONFIG_SRCDIR([common.c])
AC_CONFIG_HEADER(config.h)
AC_CONFIG_AUX_DIR([build])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.14])

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

AC_CHECK_TYPES([errno_t], [], [], [[#include <errno.h>]])

m4_pattern_allow([AM_SILENT_RULES])
AM_SILENT_RULES

AC_SUBST(PAM_LIBS)

#Check for PAM headers
AC_CHECK_HEADERS([security/pam_appl.h security/pam_misc.h security/pam_modules.h],
    [AC_CHECK_LIB(pam, pam_get_item, [ PAM_LIBS="-lpam" ], [AC_MSG_ERROR([PAM must support pam_get_item])])],
    [AC_MSG_ERROR([PAM development libraries not installed])]
)

#Set the NSS library install path
AC_ARG_ENABLE([nsslibdir], [AS_HELP_STRING([--enable-nsslibdir],
                                        [Where to install nss libraries ($libdir)])],
              [nsslibdir=$enableval],
              [nsslibdir=$libdir])
AC_SUBST(nsslibdir)

m4_include([conf_macros.m4])
BUILD_WITH_AUX_INFO
WITH_PIPE_PATH
WITH_MANPAGES
WITH_XML_CATALOG

m4_include([external/docbook.m4])
if test x$HAVE_MANPAGES != x; then
    CHECK_XML_TOOLS
    CHECK_STYLESHEET([$SGML_CATALOG_FILES],
                     [http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl],
                     [Docbook XSL templates])
fi

AC_CONFIG_FILES([Makefile po/Makefile.in])
AC_OUTPUT
