AC_PATH_PROG(NSCD, nscd, $NSCD_PATH)
AC_MSG_CHECKING(for nscd)
AC_DEFINE_UNQUOTED([NSCD_PATH], "$NSCD", [The path to nscd, if available])

if test -x "$NSCD"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT([not installed, assuming standard location])
fi
