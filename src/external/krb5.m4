AC_SUBST(KRB5_CFLAGS)
AC_SUBST(KRB5_LIBS)

if test x$KRB5_LIBS != x; then
    KRB5_PASSED_LIBS=$KRB5_LIBS
fi

if test x$KRB5_CFLAGS != x; then
    KRB5_PASSED_CFLAGS=$KRB5_CFLAGS
fi

AC_PATH_PROG(KRB5_CONFIG, krb5-config)
AC_MSG_CHECKING(for working krb5-config)
if test -x "$KRB5_CONFIG"; then
  KRB5_CFLAGS="`$KRB5_CONFIG --cflags`"
  KRB5_LIBS="`$KRB5_CONFIG --libs`"
  AC_MSG_RESULT(yes)
else
    if test x$KRB5_PASSED_LIBS = x; then
        AC_MSG_ERROR(no. Please install MIT kerberos devel package)
    fi
fi

if test x$KRB5_PASSED_LIBS != x; then
    KRB5_LIBS=$KRB5_PASSED_LIBS
fi

if test x$KRB5_PASSED_CFLAGS != x; then
    KRB5_CFLAGS=$KRB5_PASSED_CFLAGS
fi

AC_ARG_VAR([KRB5_CFLAGS], [C compiler flags for kerberos, overriding krb5-config])dnl
AC_ARG_VAR([KRB5_LIBS], [linker flags for kerberos, overriding krb5-config])dnl

SAVE_CFLAGS=$CFLAGS
SAVE_LIBS=$LIBS
CFLAGS="$CFLAGS $KRB5_CFLAGS"
LIBS="$LIBS $KRB5_LIBS"
AC_CHECK_HEADERS([krb5.h krb5/krb5.h])
AC_CHECK_TYPES([krb5_ticket_times, krb5_times], [], [],
               [ #ifdef HAVE_KRB5_KRB5_H
                 #include <krb5/krb5.h>
                 #else
                 #include <krb5.h>
                 #endif
               ])
AC_CHECK_FUNCS([krb5_get_init_creds_opt_alloc krb5_get_error_message \
                krb5_free_unparsed_name \
                krb5_get_init_creds_opt_set_expire_callback \
                krb5_get_init_creds_opt_set_fast_ccache_name \
                krb5_get_init_creds_opt_set_fast_flags \
                krb5_get_init_creds_opt_set_canonicalize \
                krb5_unparse_name_flags \
                krb5_get_init_creds_opt_set_change_password_prompt \
                krb5_free_keytab_entry_contents \
                krb5_kt_free_entry \
                krb5_princ_realm \
                krb5_get_time_offsets \
                krb5_principal_get_realm \
                krb5_cc_cache_match \
                krb5_timestamp_to_sfstring \
                krb5_set_trace_callback \
                krb5_cc_get_full_name])
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
                [AC_MSG_NOTICE([Kerberos locator plugin cannot be built])],
                [ #ifdef HAVE_KRB5_KRB5_H
                  #include <krb5/krb5.h>
                  #else
                  #include <krb5.h>
                  #endif
                ])
AM_CONDITIONAL([BUILD_KRB5_LOCATOR_PLUGIN],
               [test x$have_locate_plugin = xyes -a x$build_locator = xyes])

