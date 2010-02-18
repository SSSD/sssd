AC_SUBST(PAM_LIBS)

AC_CHECK_HEADERS([security/pam_appl.h security/pam_misc.h security/pam_modules.h],
    [AC_CHECK_LIB(pam, pam_get_item, [ PAM_LIBS="-lpam" ], [AC_MSG_ERROR([PAM must support pam_get_item])])],
    [AC_MSG_ERROR([PAM development libraries not installed])]
)
