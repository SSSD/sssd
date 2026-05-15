AC_DEFUN([CHECK_SERVICE_EXECUTABLE],
    [ AC_PATH_PROG([SERVICE], [service], [], [/sbin:/usr/sbin])
      AC_MSG_CHECKING(for the executable \"service\")
      if test -x "$SERVICE"; then
        AC_DEFINE(HAVE_SERVICE, 1, [Whether the service command is available])
        AC_DEFINE_UNQUOTED([SERVICE_PATH], ["$SERVICE"], [The path to service])
        AC_MSG_RESULT(yes)
      else
        AC_MSG_RESULT([no])
        AC_MSG_WARN([the service executable is not available])
      fi
    ]
)
