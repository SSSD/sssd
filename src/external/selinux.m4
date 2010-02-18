dnl A macro to check the availability of SELinux
AC_DEFUN([AM_CHECK_SELINUX],
[
    AC_CHECK_HEADERS(selinux/selinux.h,
                     [AC_CHECK_LIB(selinux, is_selinux_enabled,
                                            [SELINUX_LIBS="-lselinux"],
                                            [AC_MSG_ERROR([SELinux library is missing])]
                                  )
                     ],
                     [AC_MSG_ERROR([SELinux headers are missing])])
    AC_SUBST(SELINUX_LIBS)
])

