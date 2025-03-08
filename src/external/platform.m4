AC_ARG_WITH([os],
            [AC_HELP_STRING([--with-os=OS_TYPE], [Type of your operation system (unknown|fedora|redhat|suse|debian|gentoo)])]
           )
osname=""
if test x"$with_os" != x ; then
    osname=$with_os
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
    elif test -f /etc/os-release ; then
        . /etc/os-release
        if ([[ "${ID}" = "suse" ]]) || ([[ "${ID_LIKE#*suse*}" != "${ID_LIKE}" ]]); then
            osname="suse"
        fi
    else
        osname="unknown"
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

AC_CHECK_MEMBERS([struct xucred.cr_pid, struct xucred.cr_uid, struct xucred.cr_groups], , ,
                 [[#include <sys/ucred.h>]])

if test x"$ac_cv_member_struct_ucred_pid" = xyes -a \
        x"$ac_cv_member_struct_ucred_uid" = xyes -a \
        x"$ac_cv_member_struct_ucred_gid" = xyes ; then
    AC_DEFINE([HAVE_UCRED], [1], [Define if struct ucred is available])
elif test x"$ac_cv_member_struct_xucred_cr_pid" = xyes -a \
        x"$ac_cv_member_struct_xucred_cr_uid" = xyes -a \
        x"$ac_cv_member_struct_xucred_cr_groups" = xyes ; then
    AC_DEFINE([HAVE_XUCRED], [1], [Define if struct xucred is available])
else
    AC_MSG_ERROR([struct ucred is not available])
fi
