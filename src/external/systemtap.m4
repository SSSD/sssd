dnl A macro to check the availability of systemtap user-space probes
AC_DEFUN([AM_CHECK_SYSTEMTAP],
[
    AC_ARG_ENABLE([systemtap],
                [AS_HELP_STRING([--enable-systemtap],
                                [Enable inclusion of systemtap trace support])],
                [ENABLE_SYSTEMTAP="${enableval}"], [ENABLE_SYSTEMTAP='no'])

    if test "x${ENABLE_SYSTEMTAP}" = xyes; then
        AC_CHECK_PROGS(DTRACE, dtrace)
        if test -z "$DTRACE"; then
            AC_MSG_ERROR([dtrace not found])
        fi

        AC_CHECK_HEADER([sys/sdt.h], [SDT_H_FOUND='yes'],
                        [SDT_H_FOUND='no';
                        AC_MSG_ERROR([systemtap support needs sys/sdt.h header])])

        AC_DEFINE([HAVE_SYSTEMTAP], [1], [Define to 1 if systemtap is enabled])
        HAVE_SYSTEMTAP=1

        AC_ARG_WITH([tapset-install-dir],
                    [AS_HELP_STRING([--with-tapset-install-dir],
                                    [The absolute path where the tapset dir will be installed])],
                    [if test "x${withval}" = x; then
                        tapset_dir="\$(datadir)/systemtap/tapset"
                    else
                        tapset_dir="${withval}"
                    fi],
                    [tapset_dir="\$(datadir)/systemtap/tapset"])
        AC_SUBST(tapset_dir)
    fi

    AM_CONDITIONAL([BUILD_SYSTEMTAP], [test x$HAVE_SYSTEMTAP = x1])
])
