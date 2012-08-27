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

dnl Check if the SELinux login directory exists
AC_DEFUN([AM_CHECK_SELINUX_LOGIN_DIR],
[
  AC_CHECK_FILE(/etc/selinux/targeted/logins/,
                [AC_DEFINE([HAVE_SELINUX_LOGIN_DIR], [1],
                           [The directory to store SELinux user login is available])],
                [AC_MSG_WARN([SELinux login directory is not available])])
])
