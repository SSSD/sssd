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

PKG_CHECK_MODULES([GDM_PAM_EXTENSIONS], [gdm-pam-extensions],
                  [found_gdm_pam_extensions=yes],
                  [AC_MSG_NOTICE([gdm-pam-extensions were not found. gdm support
for multiple certificates will not be build.
])])

AC_SUBST(GDM_PAM_EXTENSIONS_CFLAGS)

AS_IF([test x"$found_gdm_pam_extensions" = xyes],
      [AC_DEFINE_UNQUOTED(HAVE_GDM_PAM_EXTENSIONS, 1,
                          [Build with gdm-pam-extensions support])])

AS_IF([test x"$found_gdm_pam_extensions" = xyes],
      [AC_CHECK_HEADER([gdm/gdm-custom-json-pam-extension.h],
                       [AC_DEFINE_UNQUOTED(HAVE_GDM_CUSTOM_JSON_PAM_EXTENSION, 1,
                            [Build with gdm-custom-json-pam-extension support])])])
AM_CONDITIONAL([HAVE_GDM_CUSTOM_JSON_PAM_EXTENSION],
               [test x"$found_gdm_pam_extensions" = xyes])
