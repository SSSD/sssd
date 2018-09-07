AC_CHECK_PROG([HAVE_FAKEROOT], [fakeroot], [yes], [no])

dnl Check for variable and fail unless value is "yes"
dnl The second argument will be printed in error message in case of error
dnl Usage:
dnl     SSS_INTGCHECK_REQ(variable, message)

AC_DEFUN([SSS_INTGCHECK_REQ], [
    AS_IF([test x$$1 = xyes], , [
          AC_MSG_ERROR([cannot enable integration tests: $2 not found])])
])

dnl Check for python variable and fail/warn unless value is "yes"
dnl The second argument will be printed in error message in case of error
dnl Any value in 3rd argument will make change error to info
dnl Usage:
dnl     SSS_INTGCHECK_PYTHON_REQ(variable, message, [non_fatal])

AC_DEFUN([SSS_INTGCHECK_PYTHON_REQ], [
    AS_IF([test x$$1 = xyes], [],
          [sss_have_py_intg_deps=no
           AS_IF([test -n "$3"],
                 [AC_MSG_NOTICE([missing python dependency for integration tests: $2 not found])],
                 [AC_MSG_ERROR([cannot enable integration tests: $2 not found])])
          ])
])

dnl Check for variable and fail unless value is "yes"
dnl The second argument will be printed in error message in case of error
dnl Usage:
dnl     SSS_CHECK_PYTHON_INTG_REQ(python_version, [non_fatal])
AC_DEFUN([SSS_CHECK_PYTHON_INTG_REQ], [
    sss_have_py_intg_deps="no"

    SSS_INTGCHECK_PYTHON_REQ([HAVE_PYTHON$1_BINDINGS],
                             [sssd python$1 bindings], [$2])

    AS_IF([test x$HAVE_PYTHON$1_BINDINGS = xyes],
          [SSS_CHECK_PYTEST([$PYTHON$1], [PY$1_PYTEST])
           []AM_PYTHON$1_MODULE([ldap])
           []AM_PYTHON$1_MODULE([ldb])
           []AM_PYTHON$1_MODULE([requests])
           []AM_PYTHON$1_MODULE([dbus])
           []AM_PYTHON$1_MODULE([psutil])

           sss_have_py_intg_deps="yes"

           SSS_INTGCHECK_PYTHON_REQ([HAVE_PY$1_PYTEST],
                                    [python$1 pytest], [$2])
           SSS_INTGCHECK_PYTHON_REQ([HAVE_PY$1MOD_LDAP],
                                    [python$1 module ldap], [$2])
           SSS_INTGCHECK_PYTHON_REQ([HAVE_PY$1MOD_LDB],
                                    [python$1 module ldb], [$2])
           SSS_INTGCHECK_PYTHON_REQ([HAVE_PY$1MOD_REQUESTS],
                                    [python$1 module requests], [$2])
           SSS_INTGCHECK_PYTHON_REQ([HAVE_PY$1MOD_DBUS],
                                    [python$1 module dbus], [$2])
           SSS_INTGCHECK_PYTHON_REQ([HAVE_PY$1MOD_PSUTIL],
                             [python$1 module psutil], [$2])])

    AS_IF([test "x$sss_have_py_intg_deps" = xyes],
          [HAVE_PYTHON_INTG_DEPS=yes
           PYTHON_EXEC_INTG=$PYTHON$1
           AC_SUBST(PYTHON_EXEC_INTG)],
          [HAVE_PYTHON_INTG_DEPS=no])
    unset sss_have_py_intg_deps
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

        SSS_CHECK_PYTHON_INTG_REQ([3], [just_warning])

        AS_IF([test "x$HAVE_PYTHON_INTG_DEPS" = xyes], [],
              dnl fallback to python2 checks due to missing
              dnl python3 dependencies for intgcheck
              [SSS_CHECK_PYTHON_INTG_REQ([2])])
    fi
])

AM_CONDITIONAL([INTG_BUILD], [test x"$enable_intgcheck_reqs" = xyes])
