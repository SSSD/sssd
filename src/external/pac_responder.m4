AC_ARG_ENABLE([pac-responder],
              [AS_HELP_STRING([--enable-pac-responder],
                              [build pac responder])],
              [build_pac_responder=$enableval],
              [build_pac_responder=yes])

krb5_version_ok=no
if test x$build_pac_responder = xyes
then
    AC_PATH_PROG(KRB5_CONFIG, krb5-config)
    AC_MSG_CHECKING(for supported MIT krb5 version)
    KRB5_VERSION="`$KRB5_CONFIG --version`"
    case $KRB5_VERSION in
        Kerberos\ 5\ release\ 1.9* | \
        Kerberos\ 5\ release\ 1.10* | \
        Kerberos\ 5\ release\ 1.11* | \
        Kerberos\ 5\ release\ 1.12* | \
        Kerberos\ 5\ release\ 1.13* | \
        Kerberos\ 5\ release\ 1.14* | \
        Kerberos\ 5\ release\ 1.15* | \
        Kerberos\ 5\ release\ 1.16* | \
        Kerberos\ 5\ release\ 1.17* | \
        Kerberos\ 5\ release\ 1.18* | \
        Kerberos\ 5\ release\ 1.19* | \
        Kerberos\ 5\ release\ 1.20*)
            krb5_version_ok=yes
            AC_MSG_RESULT([yes])
            ;;
        *)
            AC_MSG_RESULT([no])
            AC_MSG_WARN([Cannot build authdata plugin with this version of
                         MIT Kerberos, please use 1.9.x or later])
    esac
fi

if test x$with_samba != xyes
then
    AC_MSG_WARN([Cannot build PAC responder without Samba])
fi

AM_CONDITIONAL([BUILD_PAC_RESPONDER], [test x$build_pac_responder = xyes -a x$with_samba = xyes -a x$krb5_version_ok = xyes ])
AM_COND_IF([BUILD_PAC_RESPONDER],
           [AC_DEFINE_UNQUOTED(HAVE_PAC_RESPONDER, 1, [Build with the PAC responder])])
