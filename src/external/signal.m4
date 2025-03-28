AC_CHECK_FUNCS(sigprocmask sigblock sigaction getpgrp prctl procctl)

if test x"$ac_cv_func_prctl" = xno -a \
        x"$ac_cv_func_procctl" = xno ; then
    AC_MSG_ERROR([Process control API is not available])
fi
