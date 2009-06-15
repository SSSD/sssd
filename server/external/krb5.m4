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
