dnl Check for tools needed to run the test CA
AC_DEFUN([AM_CHECK_TEST_CA],
[
    AC_PATH_PROG([OPENSSL], [openssl])
    if test ! -x "$OPENSSL"; then
        AC_MSG_NOTICE([Could not find openssl])
    fi

    AC_PATH_PROG([SSH_KEYGEN], [ssh-keygen])
    if test ! -x "$SSH_KEYGEN"; then
        AC_MSG_NOTICE([Could not find ssh-keygen])
    else
        AC_MSG_CHECKING([for -m option of ssh-keygen])
        if AC_RUN_LOG([$SSH_KEYGEN --help 2>&1 |grep -- '-m ' > /dev/null]); then
            AC_MSG_RESULT([yes])
        else
            SSH_KEYGEN=""
            AC_MSG_RESULT([no])
        fi
    fi

    if test x$cryptolib = xnss; then
        AC_PATH_PROG([CERTUTIL], [certutil])
        if test ! -x "$CERTUTIL"; then
            AC_MSG_NOTICE([Could not find certutil])
        fi

        AC_PATH_PROG([PK12UTIL], [pk12util])
        if test ! -x "$PK12UTIL"; then
            AC_MSG_NOTICE([Could not find pk12util])
        fi

        AM_CONDITIONAL([BUILD_TEST_CA], [test -x "$OPENSSL" -a -x "$SSH_KEYGEN" -a -x "$CERTUTIL" -a -x "$PK12UTIL"])
    else
        AM_CONDITIONAL([BUILD_TEST_CA], [test -x "$OPENSSL" -a -x "$SSH_KEYGEN"])
    fi

    AM_COND_IF([BUILD_TEST_CA],
               [AC_DEFINE_UNQUOTED(HAVE_TEST_CA, 1,
                                   [Build with certificates from test CA])],
               [AC_MSG_WARN([Test CA cannot be build, skiping some tests])])
])
