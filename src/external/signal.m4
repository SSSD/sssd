AC_CHECK_FUNCS(sigprocmask sigblock sigaction getpgrp prctl)

# Check for the procctl facility found on FreeBSD
AC_CHECK_HEADERS([sys/procctl.h])
