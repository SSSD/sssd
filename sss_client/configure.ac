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
AM_GNU_GETTEXT_VERSION([0.17])

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

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

AC_DEFUN([BUILD_WITH_AUX_INFO],
  [ AC_ARG_WITH([aux-info],
                [AC_HELP_STRING([--with-aux-info],
                                [Build with -aux-info output])])
  ])
AM_CONDITIONAL([WANT_AUX_INFO], [test x$with_aux_info = xyes])
BUILD_WITH_AUX_INFO

AC_DEFUN([WITH_PIPE_PATH],
  [ AC_ARG_WITH([pipe-path],
                [AC_HELP_STRING([--with-pipe-path=PATH],
                                [Where to store pipe files for the SSSD interconnects [/var/lib/sss/pipes]]
                               )
                ]
               )
    config_pipepath="\"VARDIR\"/lib/sss/pipes"
    pipepath="${localstatedir}/lib/sss/pipes"
    if test x"$with_pipe_path" != x; then
        config_pipepath=$with_pipe_path
        pipepath=$with_pipe_path
    fi
    AC_SUBST(pipepath)
    AC_DEFINE_UNQUOTED(PIPE_PATH, "$config_pipepath", [Where to store pipe files for the SSSD interconnects])
  ])
WITH_PIPE_PATH

AC_CONFIG_FILES([Makefile po/Makefile.in])
AC_OUTPUT
