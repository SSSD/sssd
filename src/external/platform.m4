AC_ARG_WITH([os],
            [AC_HELP_STRING([--with-os=OS_TYPE], [Type of your operation system (fedora|redhat|suse)])]
           )
osname=""
if test x"$with_os" != x ; then
    if test x"$with_os" == xfedora -o \
            x"$with_os" == xredhat -o \
            x"$with_os" == xsuse ; then
        osname=$with_os
    else
        AC_MSG_ERROR([Illegal value -$with_os- for option --with-os])
    fi
fi

if test x"$osname" = x ; then
    if test -f /etc/fedora-release ; then
        osname="fedora"
    elif test -f /etc/redhat-release ; then
        osname="redhat"
    elif test -f /etc/SuSE-release ; then
        osname="suse"
    fi

    AC_MSG_NOTICE([Detected operation system type: $osname])
fi

AM_CONDITIONAL([HAVE_FEDORA], [test x"$osname" == xfedora])
AM_CONDITIONAL([HAVE_REDHAT], [test x"$osname" == xredhat])
AM_CONDITIONAL([HAVE_SUSE], [test x"$osname" == xsuse])
