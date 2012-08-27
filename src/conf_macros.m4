AC_DEFUN([WITH_DISTRO_VERSION],
  [ AC_ARG_WITH([distro-version],
                [AC_HELP_STRING([--with-distro-version=VERSION],
                                [Distro version number []]
                               )
                ]
               )
    AC_DEFINE_UNQUOTED(DISTRO_VERSION, "$with_distro_version",
                           [Distro version number])
  ])

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

AC_DEFUN([WITH_MCACHE_PATH],
  [ AC_ARG_WITH([mcache-path],
                [AC_HELP_STRING([--with-mcache-path=PATH],
                                [Where to store mmap cache files for the SSSD interconnects [/var/lib/sss/mc]]
                               )
                ]
               )
    config_mcpath="\"VARDIR\"/lib/sss/mc"
    mcpath="${localstatedir}/lib/sss/mc"
    if test x"$with_mcache_path" != x; then
        config_mcpath=$with_mcache_path
        mcpath=$with_mcache_path
    fi
    AC_SUBST(mcpath)
    AC_DEFINE_UNQUOTED(MCACHE_PATH, "$config_mcpath", [Where to store mmap cache files for the SSSD interconnects])
  ])

AC_DEFUN([WITH_INITSCRIPT],
  [ AC_ARG_WITH([initscript],
                [AC_HELP_STRING([--with-initscript=INITSCRIPT_TYPE],
                                [Type of your init script (sysv|systemd). [sysv]]
                               )
                ]
               )
  default_initscript=sysv
  if test x"$with_initscript" = x; then
    with_initscript=$default_initscript
  fi

  if test x"$with_initscript" = xsysv || \
     test x"$with_initscript" = xsystemd; then
        initscript=$with_initscript
  else
      AC_MSG_ERROR([Illegal value -$with_initscript- for option --with-initscript])
  fi

  AM_CONDITIONAL([HAVE_SYSV], [test x"$initscript" = xsysv])
  AM_CONDITIONAL([HAVE_SYSTEMD_UNIT], [test x"$initscript" = xsystemd])
  AC_MSG_NOTICE([Will use init script type: $initscript])
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

dnl A macro to configure the directory to install the systemd unit files to
AC_DEFUN([WITH_SYSTEMD_UNIT_DIR],
  [ AC_ARG_WITH([systemdunitdir],
                [ AC_HELP_STRING([--with-systemdunitdir=DIR],
                                 [Directory for systemd service files [Auto]]
                                ),
                ],
               )
  if test x"$with_systemdunitdir" != x; then
    systemdunitdir=$with_systemdunitdir
  else
    systemdunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
    if test x"$systemdunitdir" = x; then
      AC_MSG_ERROR([Could not detect systemd unit directory])
    fi
  fi
  AC_SUBST(systemdunitdir)
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

AC_DEFUN([WITH_DEFAULT_CCACHE_DIR],
  [ AC_ARG_WITH([default-ccache-dir],
                [AC_HELP_STRING([--with-default-ccache-dir=CCACHEDIR],
                                [The default value of krb5_ccachedir [/tmp]]
                               )
                ]
               )
    config_def_ccache_dir="/tmp"
    if test x"$with_default_ccache_dir" != x; then
        config_def_ccache_dir=$with_default_ccache_dir
    fi
    AC_SUBST(config_def_ccache_dir)
    AC_DEFINE_UNQUOTED(DEFAULT_CCACHE_DIR, "$config_def_ccache_dir", [The default value of krb5_ccachedir])
  ])

AC_DEFUN([WITH_DEFAULT_CCNAME_TEMPLATE],
  [ AC_ARG_WITH([default-ccname-template],
                [AC_HELP_STRING([--with-default-ccname-template=CCACHE],
                                [The default value of krb5_ccname_template [FILE:%d/krb5cc_%U_XXXXXX]]
                               )
                ]
               )
    config_def_ccname_template="FILE:%d/krb5cc_%U_XXXXXX"
    if test x"$with_default_ccname_template" != x; then
        config_def_ccname_template=$with_default_ccname_template
    fi
    AC_SUBST(config_def_ccname_template)
    AC_DEFINE_UNQUOTED(DEFAULT_CCNAME_TEMPLATE, "$config_def_ccname_template", [The default value of krb5_ccname_template])
  ])

AC_DEFUN([WITH_KRB5AUTHDATA_PLUGIN_PATH],
  [ AC_ARG_WITH([krb5authdata-plugin-path],
                [AC_HELP_STRING([--with-krb5authdata-plugin-path=PATH],
                                [Path to kerberos authdata plugin store [/usr/lib/krb5/plugins/authdata]]
                               )
                ]
               )
    krb5authdatapluginpath="${libdir}/krb5/plugins/authdata"
    if test x"$with_krb5authdata_plugin_path" != x; then
        krb5authdatapluginpath=$with_krb5authdata_plugin_path
    fi
    AC_SUBST(krb5authdatapluginpath)
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
                [AC_HELP_STRING([--with-nscd=PATH],
                                [Path to nscd binary to attempt to flush nscd cache after local domain operations [/usr/sbin/nscd]]
                               )
                ]
               )
    NSCD_PATH="/usr/sbin/nscd"
    if test x"$with_nscd" != x; then
        NSCD_PATH=$with_nscd
        AC_SUBST(NSCD_PATH)
    fi
    AC_DEFINE_UNQUOTED(HAVE_NSCD, $NSCD_PATH, [flush nscd cache after local domain operations])
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

AC_DEFUN([WITH_CRYPTO],
    [ AC_ARG_WITH([crypto],
                  [AC_HELP_STRING([--with-crypto=CRYPTO_LIB],
                                  [The cryptographic library to use (nss|libcrypto). The default is nss.]
                                 )
                  ],
                  [],
                  with_crypto=nss
                 )

      cryptolib=""
      if test x"$with_crypto" != x; then
          if test x"$with_crypto" = xnss || \
          test x"$with_crypto" = xlibcrypto; then
              cryptolib="$with_crypto";
          else
              AC_MSG_ERROR([Illegal value -$with_crypto- for option --with-crypto])
          fi
      fi
      AM_CONDITIONAL([HAVE_NSS], [test x"$cryptolib" = xnss])
      AM_CONDITIONAL([HAVE_LIBCRYPTO], [test x"$cryptolib" = xlibcrypto])
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

AC_ARG_ENABLE([all-experimental-features],
              [AS_HELP_STRING([--enable-all-experimental-features],
                              [build all experimental features])],
              [build_all_experimental_features=$enableval],
              [build_all_experimental_features=no])


AC_DEFUN([WITH_UNICODE_LIB],
  [ AC_ARG_WITH([unicode-lib],
                [AC_HELP_STRING([--with-unicode-lib=<library>],
                                [Which library to use for unicode processing (libunistring, glib2) [glib2]]
                               )
                ]
               )
    unicode_lib="glib2"
    if test x"$with_unicode_lib" != x; then
        unicode_lib=$with_unicode_lib
    fi
    
    if test x"$unicode_lib" != x"libunistring" -a x"$unicode_lib" != x"glib2"; then
		AC_MSG_ERROR([Unsupported unicode library])
    fi
    
    AM_CONDITIONAL([WITH_LIBUNISTRING], test x"$unicode_lib" = x"libunistring")
    AM_CONDITIONAL([WITH_GLIB], test x"$unicode_lib" = x"glib2")
  ])

AC_DEFUN([WITH_APP_LIBS],
  [ AC_ARG_WITH([app-libs],
                [AC_HELP_STRING([--with-app-libs=<path>],
                                [Path to the 3rd party application plugins [/usr/lib/sssd/modules]]
                               )
                ]
               )
    appmodpath="${libdir}/sssd/modules"
    config_appmodpath="\"LIBDIR\"/sssd/modules"
    if test x"$with_app_libs" != x; then
        appmodpath=$with_app_libs
        config_appmodpath=$with_app_libs
    fi
    AC_SUBST(appmodpath)
    AC_DEFINE_UNQUOTED(APP_MODULES_PATH, "$config_appmodpath", [Path to the 3rd party modules])
  ])

AC_DEFUN([WITH_SUDO],
  [ AC_ARG_WITH([sudo],
                [AC_HELP_STRING([--with-sudo],
                                [Whether to build with sudo support [yes]]
                               )
                ],
                [with_sudo=$withval],
                with_sudo=yes
               )

    if test x"$with_sudo" = xyes; then
        AC_DEFINE(BUILD_SUDO, 1, [whether to build with SUDO support])
    fi
    AM_CONDITIONAL([BUILD_SUDO], [test x"$with_sudo" = xyes])
  ])

AC_DEFUN([WITH_SUDO_LIB_PATH],
  [ AC_ARG_WITH([sudo-lib-path],
                [AC_HELP_STRING([--with-sudo-lib-path=<path>],
                                [Path to the sudo library [/usr/lib/]]
                               )
                ]
               )
    sudolibpath="${libdir}"
    if test x"$with_sudo_lib_path" != x; then
        sudolibpath=$with_sudo_lib_path
    fi
    AC_SUBST(sudolibpath)
  ])

AC_DEFUN([WITH_AUTOFS],
  [ AC_ARG_WITH([autofs],
                [AC_HELP_STRING([--with-autofs],
                                [Whether to build with autofs support [yes]]
                               )
                ],
                [with_autofs=$withval],
                with_autofs=yes
               )

    if test x"$with_autofs" = xyes; then
        AC_DEFINE(BUILD_AUTOFS, 1, [whether to build with AUTOFS support])
    fi
    AM_CONDITIONAL([BUILD_AUTOFS], [test x"$with_autofs" = xyes])
  ])

AC_DEFUN([WITH_SSH],
  [ AC_ARG_WITH([ssh],
                [AC_HELP_STRING([--with-ssh],
                                [Whether to build with SSH support [yes]]
                               )
                ],
                [with_ssh=$withval],
                with_ssh=yes
               )

    if test x"$with_ssh" = xyes; then
        AC_DEFINE(BUILD_SSH, 1, [whether to build with SSH support])
    fi
    AM_CONDITIONAL([BUILD_SSH], [test x"$with_ssh" = xyes])
  ])
