AC_DEFUN([WITH_DB_PATH],
  [ AC_ARG_WITH([db-path],
                [AC_HELP_STRING([--with-db-path=PATH],
                                [Path to the SSSD databases [/var/lib/sss/db]]
                               )
                ]
               )
    config_dbpath="\"VARDIR\"/lib/sss/db"
    dbpath="${localstatedir}/lib/sss/db"
    if test x"$with_db_path" != x; then
        config_dbpath=$with_db_path
        dbpath=$with_db_path
    fi
    AC_SUBST(dbpath)
    AC_DEFINE_UNQUOTED(DB_PATH, "$config_dbpath", [Path to the SSSD databases])
  ])

AC_DEFUN([WITH_PLUGIN_PATH],
  [ AC_ARG_WITH([plugin-path],
                [AC_HELP_STRING([--with-plugin-path=PATH],
                                [Path to the SSSD data provider plugins [/usr/lib/sssd]]
                               )
                ]
               )
    pluginpath="${libdir}/sssd"
    config_pluginpath="\"LIBDIR\"/sssd"
    if test x"$with_plugin_path" != x; then
        pluginpath=$with_plugin_path
        config_pluginpath=$with_plugin_path
    fi
    AC_SUBST(pluginpath)
    AC_DEFINE_UNQUOTED(DATA_PROVIDER_PLUGINS_PATH, "$config_pluginpath", [Path to the SSSD data provider plugins])
  ])

AC_DEFUN([WITH_PID_PATH],
  [ AC_ARG_WITH([pid-path],
                [AC_HELP_STRING([--with-pid-path=PATH],
                                [Where to store pid files for the SSSD [/var/run]]
                               )
                ]
               )
    config_pidpath="\"VARDIR\"/run"
    pidpath="${localstatedir}/run"
    if test x"$with_pid_path" != x; then
        config_pidpath=$with_pid_path
        pidpath=$with_pid_path
    fi
    AC_SUBST(pidpath)
    AC_DEFINE_UNQUOTED(PID_PATH, "$config_pidpath", [Where to store pid files for the SSSD])
  ])

AC_DEFUN([WITH_LOG_PATH],
  [ AC_ARG_WITH([log-path],
                [AC_HELP_STRING([--with-log-path=PATH],
                                [Where to store log files for the SSSD [/var/log/sssd]]
                               )
                ]
               )
    config_logpath="\"VARDIR\"/log/sssd"
    logpath="${localstatedir}/log/sssd"
    if test x"$with_log_path" != x; then
        config_logpath=$with_log_path
        logpath=$with_log_path
    fi
    AC_SUBST(logpath)
    AC_DEFINE_UNQUOTED(LOG_PATH, "$config_logpath", [Where to store log files for the SSSD])
  ])

AC_DEFUN([WITH_PUBCONF_PATH],
  [ AC_ARG_WITH([pubconf-path],
                [AC_HELP_STRING([--with-pubconf-path=PATH],
                                [Where to store pubconf files for the SSSD [/var/lib/sss/pubconf]]
                               )
                ]
               )
    config_pubconfpath="\"VARDIR\"/lib/sss/pubconf"
    pubconfpath="${localstatedir}/lib/sss/pubconf"
    if test x"$with_pubconf_path" != x; then
        config_pubconfpath=$with_pubconf_path
        pubconfpath=$with_pubconf_path
    fi
    AC_SUBST(pubconfpath)
    AC_DEFINE_UNQUOTED(PUBCONF_PATH, "$config_pubconfpath", [Where to store pubconf files for the SSSD])
  ])

AC_DEFUN([WITH_PIPE_PATH],
  [ AC_ARG_WITH([pipe-path],
                [AC_HELP_STRING([--with-pipe-path=PATH],
                                [Where to store pipe files for the SSSD interconnects [/var/lib/sss/pipes]]
                               )
                ]
               )
    config_pipepath="\"VARDIR\"/lib/sss/pipes"
    pipepath="${localstatedir}/lib/sss/pipes"
    if test x"$with_pipe_path" != x; then
        config_pipepath=$with_pipe_path
        pipepath=$with_pipe_path
    fi
    AC_SUBST(pipepath)
    AC_DEFINE_UNQUOTED(PIPE_PATH, "$config_pipepath", [Where to store pipe files for the SSSD interconnects])
  ])

AC_DEFUN([WITH_INIT_DIR],
  [ AC_ARG_WITH([init-dir],
                [AC_HELP_STRING([--with-init-dir=DIR],
                                [Where to store init script for sssd [/etc/rc.d/init.d]]
                               )
                ]
               )
    initdir="${sysconfdir}/rc.d/init.d"
    if test x$osname == xgentoo; then
        initdir="${sysconfdir}/init.d"
    fi
    if test x"$with_init_dir" != x; then
        initdir=$with_init_dir
    fi
    AC_SUBST(initdir)
  ])

AC_DEFUN([WITH_MANPAGES],
  [ AC_ARG_WITH([manpages],
                [AC_HELP_STRING([--with-manpages],
                                [Whether to regenerate man pages from DocBook sources [yes]]
                               )
                ],
                [],
                with_manpages=yes
               )
    if test x"$with_manpages" = xyes; then
        HAVE_MANPAGES=1
        AC_SUBST(HAVE_MANPAGES)
    fi
  ])
AM_CONDITIONAL([BUILD_MANPAGES], [test x$with_manpages = xyes])

AC_DEFUN([WITH_XML_CATALOG],
  [ AC_ARG_WITH([xml-catalog-path],
                [AC_HELP_STRING([--with-xml-catalog-path=PATH],
                                [Where to look for XML catalog [/etc/xml/catalog]]
                               )
                ]
               )
    SGML_CATALOG_FILES="/etc/xml/catalog"
    if test x"$with_xml_catalog_path" != x; then
        SGML_CATALOG_FILES="$with_xml_catalog_path"
    fi
    AC_SUBST([SGML_CATALOG_FILES])
  ])

AC_DEFUN([WITH_KRB5_PLUGIN_PATH],
  [ AC_ARG_WITH([krb5-plugin-path],
                [AC_HELP_STRING([--with-krb5-plugin-path=PATH],
                                [Path to kerberos plugin store [/usr/lib/krb5/plugins/libkrb5]]
                               )
                ]
               )
    krb5pluginpath="${libdir}/krb5/plugins/libkrb5"
    if test x"$with_krb5_plugin_path" != x; then
        krb5pluginpath=$with_krb5_plugin_path
    fi
    AC_SUBST(krb5pluginpath)
  ])

AC_DEFUN([WITH_KRB5_RCACHE_DIR],
  [ AC_ARG_WITH([krb5-rcache-dir],
                [AC_HELP_STRING([--with-krb5-rcache-dir=PATH],
                                [Path to store Kerberos replay caches [__LIBKRB5_DEFAULTS__]]
                               )
                ]
               )
    krb5rcachedir="__LIBKRB5_DEFAULTS__"
    if test x"$with_krb5_rcache_dir" != x; then
        krb5rcachedir=$with_krb5_rcache_dir
    fi
    AC_SUBST(krb5rcachedir)
    AC_DEFINE_UNQUOTED(KRB5_RCACHE_DIR, "$krb5rcachedir", [Directory used for storing Kerberos replay caches])
  ])

AC_DEFUN([WITH_PYTHON_BINDINGS],
  [ AC_ARG_WITH([python-bindings],
                [AC_HELP_STRING([--with-python-bindings],
                                [Whether to build python bindings [yes]]
                               )
                ],
                [],
                with_python_bindings=yes
               )
    if test x"$with_python_bindings" = xyes; then
        HAVE_PYTHON_BINDINGS=1
        AC_SUBST(HAVE_PYTHON_BINDINGS)
    fi
    AM_CONDITIONAL([BUILD_PYTHON_BINDINGS], [test x"$with_python_bindings" = xyes])
  ])

AC_DEFUN([WITH_SELINUX],
  [ AC_ARG_WITH([selinux],
                [AC_HELP_STRING([--with-selinux],
                                [Whether to build with SELinux support [yes]]
                               )
                ],
                [],
                with_selinux=yes
               )
    if test x"$with_selinux" = xyes; then
        HAVE_SELINUX=1
        AC_SUBST(HAVE_SELINUX)
        AC_DEFINE_UNQUOTED(HAVE_SELINUX, 1, [Build with SELinux support])
    fi
    AM_CONDITIONAL([BUILD_SELINUX], [test x"$with_selinux" = xyes])
  ])

AC_DEFUN([WITH_TEST_DIR],
  [ AC_ARG_WITH([test-dir],
                [AC_HELP_STRING([--with-test-dir=PATH],
                                [Directory used for make check temporary files [$builddir]]
                               )
                ]
               )
    TEST_DIR=$with_test_dir
    AC_SUBST(TEST_DIR)
    AC_DEFINE_UNQUOTED(TEST_DIR, "$with_test_dir", [Directory used for 'make check' temporary files])
  ])

AC_DEFUN([WITH_NSCD],
  [ AC_ARG_WITH([nscd],
                [AC_HELP_STRING([--with-nscd],
                                [Whether to attempt to flush nscd cache after local domain operations [yes]]
                               )
                ],
                [],
                with_nscd=yes
               )
    if test x"$with_nscd" = xyes; then
        AC_DEFINE_UNQUOTED(HAVE_NSCD, 1, [flush nscd cache after local domain operations])
    fi
  ])

AC_DEFUN([WITH_SEMANAGE],
  [ AC_ARG_WITH([semanage],
                [AC_HELP_STRING([--with-semanage],
                                [Whether to build with SELinux user management support [yes]]
                               )
                ],
                [],
                with_semanage=yes
               )
    if test x"$with_semanage" = xyes; then
        HAVE_SEMANAGE=1
        AC_SUBST(HAVE_SEMANAGE)
        AC_DEFINE_UNQUOTED(HAVE_SEMANAGE, 1, [Build with SELinux support])
    fi
    AM_CONDITIONAL([BUILD_SEMANAGE], [test x"$with_semanage" = xyes])
  ])

AC_DEFUN([WITH_LIBNL],
  [ AC_ARG_WITH([libnl],
                [AC_HELP_STRING([--with-libnl],
                                [Whether to build with libnetlink support [AUTO]]
                               )
                ],
                [],
                with_libnl=yes
               )
    if test x"$with_libnl" = xyes; then
        BUILD_LIBNL=1
        AC_SUBST(BUILD_LIBNL)
    fi
  ])

AC_DEFUN([WITH_NOLOGIN_SHELL],
  [ AC_ARG_WITH([nologin-shell],
                [AC_HELP_STRING([--with-nologin-shell=PATH],
                                [The shell used to deny access to users [/sbin/nologin]]
                               )
                ]
               )
    nologin_shell="/sbin/nologin"
    if test x"$with_nologin_shell" != x; then
        nologin_shell=$with_nologin_shell
    fi
    AC_DEFINE_UNQUOTED(NOLOGIN_SHELL, "$nologin_shell", [The shell used to deny access to users])
  ])

AC_DEFUN([WITH_UNICODE_LIB],
  [ AC_ARG_WITH([unicode-lib],
                [AC_HELP_STRING([--with-unicode-lib=<library>],
                                [Which library to use for unicode processing (libunistring, glib2) [libunistring]]
                               )
                ]
               )
    unicode_lib="libunistring"
    if test x"$with_unicode_lib" != x; then
        unicode_lib=$with_unicode_lib
    fi

    if test x"$unicode_lib" != x"libunistring" -a x"$unicode_lib" != x"glib2"; then
        AC_MSG_ERROR([Unsupported unicode library])
    fi

    AM_CONDITIONAL([WITH_LIBUNISTRING], test x"$unicode_lib" = x"libunistring")
    AM_CONDITIONAL([WITH_GLIB], test x"$unicode_lib" = x"glib2")
  ])
