AC_ARG_WITH([os],
            [AC_HELP_STRING([--with-os=OS_TYPE], [Type of your operation system (fedora|redhat|suse|gentoo)])]
           )
osname=""
if test x"$with_os" != x ; then
    if test x"$with_os" = xfedora || \
       test x"$with_os" = xredhat || \
       test x"$with_os" = xsuse || \
       test x"$with_os" = xgentoo || \
       test x"$with_os" = xdebian ; then
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
    elif test -f /etc/debian_version ; then
        osname="debian"
    elif test -f /etc/gentoo-release ; then
        osname="gentoo"
    fi

    AC_MSG_NOTICE([Detected operating system type: $osname])
fi

AM_CONDITIONAL([HAVE_FEDORA], [test x"$osname" = xfedora])
AM_CONDITIONAL([HAVE_REDHAT], [test x"$osname" = xredhat])
AM_CONDITIONAL([HAVE_SUSE], [test x"$osname" = xsuse])
AM_CONDITIONAL([HAVE_DEBIAN], [test x"$osname" = xdebian])
AM_CONDITIONAL([HAVE_GENTOO], [test x"$osname" = xgentoo])

AS_CASE([$osname],
        [redhat], [AC_DEFINE_UNQUOTED([HAVE_REDHAT], 1, [Build with redhat config])],
        [fedora], [AC_DEFINE_UNQUOTED([HAVE_FEDORA], 1, [Build with fedora config])],
        [suse], [AC_DEFINE_UNQUOTED([HAVE_SUSE], 1, [Build with suse config])],
        [gentoo], [AC_DEFINE_UNQUOTED([HAVE_GENTOO], 1, [Build with gentoo config])],
        [debian], [AC_DEFINE_UNQUOTED([HAVE_DEBIAN], 1, [Build with debian config])],
        [AC_MSG_NOTICE([Build with $osname config])])

AC_CHECK_MEMBERS([struct ucred.pid, struct ucred.uid, struct ucred.gid], , ,
                 [[#include <sys/socket.h>]])

if test x"$ac_cv_member_struct_ucred_pid" = xyes -a \
        x"$ac_cv_member_struct_ucred_uid" = xyes -a \
        x"$ac_cv_member_struct_ucred_gid" = xyes ; then
    AC_DEFINE([HAVE_UCRED], [1], [Define if struct ucred is available])
else
    AC_MSG_WARN([struct ucred is not available])
fi
