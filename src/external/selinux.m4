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

dnl A macro to check the availability of SELinux management library
AC_DEFUN([AM_CHECK_SEMANAGE],
[
    AC_CHECK_HEADERS(semanage/semanage.h,
                     [AC_CHECK_LIB(semanage, semanage_handle_create,
                                            [SEMANAGE_LIBS="-lsemanage"],
                                            [AC_MSG_ERROR([libsemanage is missing])]
                                  )
                     ],
                     [AC_MSG_ERROR([libsemanage is missing])])
    AC_SUBST(SEMANAGE_LIBS)
])
