AC_CHECK_PROG([HAVE_FAKEROOT], [fakeroot], [yes], [no])

dnl Check for pytest binary. When available, we will use py.test-2 for python2
dnl version. If it is not available we will try to use py.test.
AC_PATH_PROG([PYTEST], [py.test])
AC_PATH_PROG([PYTEST2], [py.test-2], [$PYTEST])
AS_IF([test -n "$PYTEST2"], [HAVE_PYTEST2=yes], [HAVE_PYTEST2=no])

dnl Check for variable and fail unless value is "yes"
dnl The second argument will be printed in error message in case of error
dnl Usage:
dnl     SSS_INTGCHECK_REQ(variable, message)

AC_DEFUN([SSS_INTGCHECK_REQ], [
    AS_IF([test x$$1 = xyes], , [
          AC_MSG_ERROR([cannot enable integration tests: $2 not found])])
])

AC_DEFUN([SSS_ENABLE_INTGCHECK_REQS], [
    AC_ARG_ENABLE(intgcheck-reqs,
        [AS_HELP_STRING([--enable-intgcheck-reqs],
                        [enable checking for integration test requirements [default=no]])],
        [enable_intgcheck_reqs="$enableval"],
        [enable_intgcheck_reqs="no"])
    if test x"$enable_intgcheck_reqs" = xyes; then
        SSS_INTGCHECK_REQ([HAVE_UID_WRAPPER], [uid_wrapper])
        SSS_INTGCHECK_REQ([HAVE_NSS_WRAPPER], [nss_wrapper])
        SSS_INTGCHECK_REQ([HAVE_PAM_WRAPPER], [pam_wrapper])
        SSS_INTGCHECK_REQ([HAVE_SLAPD], [slapd])
        SSS_INTGCHECK_REQ([HAVE_LDAPMODIFY], [ldapmodify])
        SSS_INTGCHECK_REQ([HAVE_FAKEROOT], [fakeroot])
        SSS_INTGCHECK_REQ([HAVE_PYTHON2], [python2])
        SSS_INTGCHECK_REQ([HAVE_PYTEST2], [pytest2])
        SSS_INTGCHECK_REQ([HAVE_PY2MOD_LDAP], [python-ldap])
        SSS_INTGCHECK_REQ([HAVE_PY2MOD_LDB], [pyldb])
    fi
])

AM_CONDITIONAL([INTG_BUILD], [test x"$enable_intgcheck_reqs" = xyes])
