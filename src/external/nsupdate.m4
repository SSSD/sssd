AC_PATH_PROG(NSUPDATE, nsupdate)
AC_MSG_CHECKING(for nsupdate)
if test -x "$NSUPDATE"; then
  AC_DEFINE_UNQUOTED([NSUPDATE_PATH], ["$NSUPDATE"], [The path to nsupdate])
  AC_MSG_RESULT(yes)
else
  AC_MSG_ERROR([no. nsupdate is not available])
fi
