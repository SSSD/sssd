AC_PATH_PROG(NSUPDATE, nsupdate)
AC_MSG_CHECKING(for executable nsupdate)
if test -x "$NSUPDATE"; then
  AC_DEFINE_UNQUOTED([NSUPDATE_PATH], ["$NSUPDATE"], [The path to nsupdate])
  AC_MSG_RESULT(yes)

  AC_MSG_CHECKING(for nsupdate 'realm' support')
  if AC_RUN_LOG([echo realm |$NSUPDATE >&2]); then
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED([HAVE_NSUPDATE_REALM], 1, [Whether to use the 'realm' directive with nsupdate])
  else
    AC_MSG_RESULT([no])
    AC_MSG_WARN([Will build without the 'realm' directive])
  fi

else
  AC_MSG_RESULT([no])
  AC_MSG_ERROR([nsupdate is not available])
fi
