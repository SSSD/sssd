AC_SUBST(NDR_KRB5PAC_CFLAGS)
AC_SUBST(NDR_KRB5PAC_LIBS)

AC_ARG_ENABLE([pac-responder],
              [AS_HELP_STRING([--enable-pac-responder],
                              [build pac responder])],
              [build_pac_responder=$enableval],
              [build_pac_responder=yes])

ndr_krb5pac_ok=no
krb5_version_ok=no
if test x$build_pac_responder == xyes
then
    PKG_CHECK_MODULES(NDR_KRB5PAC, ndr_krb5pac, ndr_krb5pac_ok=yes,
        AC_MSG_WARN([Cannot build pac responder without libndr_krb5pac]))

    AC_PATH_PROG(KRB5_CONFIG, krb5-config)
    AC_MSG_CHECKING(for supported MIT krb5 version)
    KRB5_VERSION="`$KRB5_CONFIG --version`"
    case $KRB5_VERSION in
        Kerberos\ 5\ release\ 1.9* | \
        Kerberos\ 5\ release\ 1.10*)
            krb5_version_ok=yes
            AC_MSG_RESULT(yes)
            ;;
        *)
            AC_MSG_WARN([Cannot build authdata plugin with this version of
                         MIT Kerberos, please use 1.9.x or 1.10.x])
    esac
fi

AM_CONDITIONAL([BUILD_PAC_RESPONDER], [test x$build_pac_responder = xyes -a x$ndr_krb5pac_ok = xyes -a x$krb5_version_ok = xyes ])
