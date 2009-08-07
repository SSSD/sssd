
AC_DEFUN([WITH_CONFIG_DIR],
  [ AC_ARG_WITH([config-dir],
                [AC_HELP_STRING([--with-config-dir=DIR],
                                [The name of the default ELAPI config directory [SYSCONFDIR/elapi]]
                               )
                ]
               )
    elapiconfdir="$sysconfdir/elapi"
    if test x"$with_config_dir" != x; then
        elapiconfdir=$with_config_dir
    fi
    AC_SUBST(elapiconfdir)
  ])

AC_DEFUN([WITH_CONFIG_APP_DIR],
  [ AC_ARG_WITH([config-app-dir],
                [AC_HELP_STRING([--with-config-app-dir=DIR],
                                [The name of the ELAPI application config directory [SYSCONFDIR/elapi/apps.d]]
                               )
                ]
               )
    elapiconfappdir="$sysconfdir/elapi/apps.d"
    if test x"$with_config_app_dir" != x; then
        elapiconfappdir=$with_config_app_dir
    fi
    AC_SUBST(elapiconfappdir)
  ])

AC_DEFUN([WITH_APP_NAME],
  [ AC_ARG_WITH([app-name],
                [AC_HELP_STRING([--with-app-name=<name>],
                                [The name of the default ELAPI application [default]]
                               )
                ]
               )
    appname="default"
    if test x"$with_app_name" != x; then
        appname=$with_app_name
    fi
    AC_SUBST(appname)
  ])

AC_DEFUN([WITH_APP_NAME_SIZE],
  [ AC_ARG_WITH([app-name-size],
                [AC_HELP_STRING([--with-app-name-size=<size>],
                                [The maximum size of the name for an ELAPI application [127]]
                               )
                ]
               )
    appnamesize="127"
    if test x"$with_app_name_size" != x; then
        appnamesize=$with_app_name_size
    fi
    AC_SUBST(appnamesize)
  ])
