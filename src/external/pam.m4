AC_SUBST(PAM_LIBS)
AC_SUBST(PAM_MISC_LIBS)

AC_CHECK_HEADERS([security/pam_appl.h security/pam_modules.h],
    [AC_CHECK_LIB([pam], [pam_get_item],
        [PAM_LIBS="-lpam"],
        [AC_MSG_ERROR([PAM must support pam_get_item])])],
    [AC_MSG_ERROR([PAM development libraries not installed])]
)

AC_CHECK_HEADERS([security/pam_ext.h security/pam_modutil.h])
AC_CHECK_HEADERS([security/pam_misc.h security/_pam_macros.h])
AC_CHECK_HEADERS([security/openpam.h],,,[
      #ifdef HAVE_SECURITY_PAM_APPL_H
      #include <security/pam_appl.h>
      #endif
    ])

AC_CHECK_LIB([pam_misc], [misc_conv],
    [PAM_MISC_LIBS="-lpam_misc"])

dnl save LIBS to restore later
save_LIBS="$LIBS"
LIBS="$PAM_LIBS"

AC_CHECK_FUNCS(pam_modutil_getlogin pam_vsyslog)

dnl restore LIBS
LIBS="$save_LIBS"
