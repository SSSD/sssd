AC_PATH_PROG(NSCD, nscd)
AC_MSG_CHECKING(for nscd)
if test -x "$NSCD"; then
  AC_DEFINE_UNQUOTED([NSCD_PATH], "$NSCD", [The path to nscd, if available])
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no. Manipulating nscd cache will not be available.)
fi

