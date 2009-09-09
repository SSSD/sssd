AC_SUBST(KRB5_CFLAGS)
AC_SUBST(KRB5_LIBS)
AC_PATH_PROG(KRB5_CONFIG, krb5-config)
AC_MSG_CHECKING(for working krb5-config)
if test -x "$KRB5_CONFIG"; then
  KRB5_CFLAGS="`$KRB5_CONFIG --cflags`"
  KRB5_LIBS="`$KRB5_CONFIG --libs`"
  AC_MSG_RESULT(yes)
else
  AC_MSG_ERROR(no. Please install MIT kerberos devel package)
fi

SAVE_CFLAGS=$CFLAGS
SAVE_LIBS=$LIBS
CFLAGS="$CFLAGS $KRB5_CFLAGS"
LIBS="$LIBS $KRB5_LIBS"
AC_CHECK_HEADERS([krb5.h krb5/krb5.h])
AC_CHECK_FUNCS([krb5_get_init_creds_opt_alloc krb5_get_error_message])
CFLAGS=$SAVE_CFLAGS
LIBS=$SAVE_LIBS

if test x$ac_cv_header_krb5_h != xyes -a x$ac_cv_header_krb5_krb5_h != xyes
then
  AC_MSG_ERROR(you must have Kerberos 5 header files to build sssd)
fi

AC_ARG_ENABLE([krb5-locator-plugin],
              [AS_HELP_STRING([--disable-krb5-locator-plugin],
                              [do not build Kerberos locator plugin])],
              [build_locator=$enableval],
              [build_locator=yes])

AC_CHECK_HEADER([krb5/locate_plugin.h],
                [have_locate_plugin=yes],
                [have_locate_plugin=no]
                [AC_MSG_NOTICE([Kerberos locator plugin cannot be build])])
AM_CONDITIONAL([BUILD_KRB5_LOCATOR_PLUGIN],
               [test x$have_locate_plugin == xyes -a x$build_locator == xyes])

