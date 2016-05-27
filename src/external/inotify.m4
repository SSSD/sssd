dnl A macro to check if inotify works
AC_DEFUN([AM_CHECK_INOTIFY],
[
    AC_CHECK_HEADERS([sys/inotify.h])

    AC_MSG_CHECKING([whether sys/inotify.h actually works])
    AC_LINK_IFELSE(
        [AC_LANG_SOURCE([
#ifdef HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif
int main () {
    return (-1 == inotify_init());
}])],
        [AC_MSG_RESULT([yes]); inotify_works=yes],
        [AC_MSG_RESULT([no])]
    )

    SSS_AC_EXPAND_LIB_DIR()
    AS_IF([test x"$inotify_works" != xyes],
          [AC_CHECK_LIB([inotify],
                        [inotify_init],
                        [INOTIFY_LIBS="$sss_extra_libdir -linotify"
                         inotify_works=yes],
                        [inotify_works=no],
                        [$sss_extra_libdir])]
    )

    AS_IF([test x"$inotify_works" = xyes],
          [AC_DEFINE_UNQUOTED([HAVE_INOTIFY], [1], [Inotify works])])
    AC_SUBST(INOTIFY_LIBS)

    AM_CONDITIONAL([HAVE_INOTIFY], [test x"$inotify_works" = xyes])
])
