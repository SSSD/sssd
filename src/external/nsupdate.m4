AC_PATH_PROG(NSUPDATE, nsupdate)
AC_MSG_CHECKING(for executable nsupdate)
if test -x "$NSUPDATE"; then
  AC_DEFINE_UNQUOTED([NSUPDATE_PATH], ["$NSUPDATE"], [The path to nsupdate])
  AC_MSG_RESULT(yes)

  AC_MSG_CHECKING(for nsupdate 'realm' support')
  if AC_RUN_LOG([echo realm |$NSUPDATE >&2]); then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([nsupdate does not support 'realm'])
  fi

else
  AC_MSG_RESULT([no])
  AC_MSG_ERROR([nsupdate is not available])
fi
