AC_DEFUN([WITH_DB_PATH],
  [ AC_ARG_WITH([db-path],
                [AC_HELP_STRING([--with-db-path=PATH],
                                [Path to the SSSD databases [/var/lib/sss/db]]
                               )
                ]
               )
    config_dbpath="\"SSS_STATEDIR\"/db"
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
    config_pubconfpath="\"SSS_STATEDIR\"/pubconf"
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
    config_pipepath="\"SSS_STATEDIR\"/pipes"
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
    config_mcpath="\"SSS_STATEDIR\"/mc"
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

AC_DEFUN([WITH_SYSLOG],
  [ AC_ARG_WITH([syslog],
                [AC_HELP_STRING([--with-syslog=SYSLOG_TYPE],
                                [Type of your system logger (syslog|journald). [syslog]]
                               )
                ],
                [],
                [with_syslog="syslog"]
               )

  if test x"$with_syslog" = xsyslog || \
     test x"$with_syslog" = xjournald; then
        syslog=$with_syslog
  else
      AC_MSG_ERROR([Uknown syslog type, supported types are syslog and journald])
  fi

  AM_CONDITIONAL([WITH_JOURNALD], [test x"$syslog" = xjournald])
  ])

AC_DEFUN([WITH_ENVIRONMENT_FILE],
  [ AC_ARG_WITH([environment_file],
                [AC_HELP_STRING([--with-environment-file=PATH], [Path to environment file [/etc/sysconfig/sssd]])
                ]
               )

    ENVIRONMENT_FILE_PATH="${sysconfdir}/sysconfig/sssd"
    if test x"$with_environment_file" != x; then
        ENVIRONMENT_FILE_PATH=$with_environment_file
    fi
    AC_SUBST(environment_file, [$ENVIRONMENT_FILE_PATH])
  ])

AC_DEFUN([WITH_INIT_DIR],
  [ AC_ARG_WITH([init-dir],
                [AC_HELP_STRING([--with-init-dir=DIR],
                                [Where to store init script for sssd [/etc/rc.d/init.d]]
                               )
                ]
               )
    initdir="${sysconfdir}/rc.d/init.d"
    if test x$osname = xgentoo; then
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

dnl A macro to configure the directory to install the systemd unit file
dnl overrides to
AC_DEFUN([WITH_SYSTEMD_CONF_DIR],
  [ AC_ARG_WITH([systemdconfdir],
                [ AC_HELP_STRING([--with-systemdconfdir=DIR],
                                 [Directory for systemd service file overrides [Auto]]
                                ),
                ],
               )
  if test x"$with_systemdconfdir" != x; then
    systemdconfdir=$with_systemdconfdir
  else
    systemdconfdir=$($PKG_CONFIG --variable=systemdsystemconfdir systemd)
    if test x"$systemdconfdir" = x; then
      AC_MSG_ERROR([Could not detect systemd config directory])
    fi
  fi
  AC_SUBST(systemdconfdir, [$systemdconfdir/sssd.service.d])
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

AC_DEFUN([WITH_CIFS_PLUGIN_PATH],
  [ AC_ARG_WITH([cifs-plugin-path],
                [AC_HELP_STRING([--with-cifs-plugin-path=PATH],
                                [Path to cifs-utils plugin store [/usr/lib/cifs-utils]]
                               )
                ]
               )
    cifspluginpath="${libdir}/cifs-utils"
    if test x"$with_cifs_plugin_path" != x; then
        cifspluginpath=$with_cifs_plugin_path
    fi
    AC_SUBST(cifspluginpath)
  ])

AC_DEFUN([WITH_WINBIND_PLUGIN_PATH],
  [ AC_ARG_WITH([winbind-plugin-path],
                [AC_HELP_STRING([--with-winbind-plugin-path=PATH],
                                [Path to winbind idmap plugin store [/usr/lib/samba/idmap]]
                               )
                ]
               )
    winbindpluginpath="${libdir}/samba/idmap"
    if test x"$with_winbind_plugin_path" != x; then
        winbindpluginpath=$with_winbind_plugin_path
    fi
    AC_SUBST(winbindpluginpath)
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
                                [The default fallback value of krb5_ccname_template [FILE:%d/krb5cc_%U_XXXXXX]]
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

AC_DEFUN([WITH_KRB5_CONF],
  [ AC_ARG_WITH([krb5_conf],
                [AC_HELP_STRING([--with-krb5-conf=PATH], [Path to krb5.conf file [/etc/krb5.conf]])
                ]
               )

    KRB5_CONF_PATH="\"SYSCONFDIR\"/krb5.conf"
    if test x"$with_krb5_conf" != x; then
        KRB5_CONF_PATH=$with_krb5_conf
    fi
    AC_DEFINE_UNQUOTED([KRB5_CONF_PATH], ["$KRB5_CONF_PATH"], [KRB5 configuration file])
  ])

AC_DEFUN([WITH_PYTHON2_BINDINGS],
  [ AC_ARG_WITH([python2-bindings],
                [AC_HELP_STRING([--with-python2-bindings],
                                [Whether to build python2 bindings [yes]])
                ],
                [],
                [with_python2_bindings=yes]
               )
    if test x"$with_python2_bindings" = xyes; then
        AC_SUBST([HAVE_PYTHON2_BINDINGS], [1])
        AC_DEFINE_UNQUOTED([HAVE_PYTHON2_BINDINGS], [1],
                           [Build with python2 bindings])
    fi
    AM_CONDITIONAL([BUILD_PYTHON2_BINDINGS],
                   [test x"$with_python2_bindings" = xyes])
  ])

AC_DEFUN([WITH_PYTHON3_BINDINGS],
  [ AC_ARG_WITH([python3-bindings],
                [AC_HELP_STRING([--with-python3-bindings],
                                [Whether to build python3 bindings [yes]])
                ],
                [],
                [with_python3_bindings=yes]
               )
    if test x"$with_python3_bindings" = xyes; then
        AC_SUBST([HAVE_PYTHON3_BINDINGS], [1])
        AC_DEFINE_UNQUOTED([HAVE_PYTHON3_BINDINGS], [1],
                           [Build with python3 bindings])
    fi
    AM_CONDITIONAL([BUILD_PYTHON3_BINDINGS],
                   [test x"$with_python3_bindings" = xyes])
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
                ],
                [TEST_DIR=$withval],
                [TEST_DIR="."]
               )
    AC_SUBST(TEST_DIR)
    AC_DEFINE_UNQUOTED(TEST_DIR, "$TEST_DIR", [Directory used for 'make check' temporary files])
  ])

AC_DEFUN([WITH_IPA_GETKEYTAB],
  [ AC_ARG_WITH([ipa_getkeytab],
                [AC_HELP_STRING([--with-ipa-getkeytab=PATH],
                                [Path to ipa_getkeytab binary to retrieve keytabs from FreeIPA server [/usr/sbin/ipa-getkeytab]]
                               )
                ]
               )
    IPA_GETKEYTAB_PATH="/usr/sbin/ipa-getkeytab"
    if test x"$with_ipa_getkeytab" != x; then
        IPA_GETKEYTAB_PATH=$with_ipa_getkeytab
    fi
    AC_DEFINE_UNQUOTED(IPA_GETKEYTAB_PATH, "$IPA_GETKEYTAB_PATH", [The path to the ipa-getkeytab utility])
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

AC_DEFUN([WITH_NSCD_CONF],
  [ AC_ARG_WITH([nscd_conf],
                [AC_HELP_STRING([--with-nscd-conf=PATH], [Path to nscd.conf file [/etc/nscd.conf]])
                ]
               )

    NSCD_CONF_PATH="/etc/nscd.conf"
    if test x"$with_nscd_conf" != x; then
        NSCD_CONF_PATH=$with_nscd_conf
    fi
    AC_DEFINE_UNQUOTED([NSCD_CONF_PATH], ["$NSCD_CONF_PATH"], [NSCD configuration file])
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

AC_DEFUN([WITH_GPO_CACHE_PATH],
  [ AC_ARG_WITH([gpo-cache-path],
                [AC_HELP_STRING([--with-gpo-cache-path=PATH],
                                [Where to store GPO policy files [/var/lib/sss/gpo_cache]]
                               )
                ]
               )
    config_gpocachepath="\"SSS_STATEDIR\"/gpo_cache"
    gpocachepath="${localstatedir}/lib/sss/gpo_cache"
    if test x"$with_gpo_cache_path" != x; then
        config_gpocachepath=$with_gpo_cache_path
        gpocachepath=$with_gpo_cache_path
    fi
    AC_SUBST(gpocachepath)
    AC_DEFINE_UNQUOTED(GPO_CACHE_PATH, "$config_gpocachepath", [Where to store GPO policy files])
  ])

AC_DEFUN([WITH_LIBNL],
  [ AC_ARG_WITH([libnl],
                [AC_HELP_STRING([--with-libnl],
                                [Whether to build with libnetlink support (libnl3, libnl1, no) [auto]]
                               )
                ],
                [],
                with_libnl=yes
               )

    if test x"$with_libnl" = xyes; then

        AM_CHECK_LIBNL3

        if test x"$HAVE_LIBNL" != x1; then
            AM_CHECK_LIBNL1
        fi

        if test x"$HAVE_LIBNL" != x1; then
            AC_MSG_WARN([Building without netlink])
        fi

    elif test x"$with_libnl" = xlibnl3; then

        AM_CHECK_LIBNL3

        if test x"$HAVE_LIBNL" != x1; then
            AC_MSG_ERROR([Libnl3 required, but not available])
        fi

    elif test x"$with_libnl" = xlibnl1; then

        AM_CHECK_LIBNL1

        if test x"$HAVE_LIBNL" != x1; then
            AC_MSG_ERROR([Libnl required, but not available])
        fi
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

AC_DEFUN([WITH_IFP],
  [ AC_ARG_WITH([infopipe],
                [AC_HELP_STRING([--with-infopipe],
                                [Whether to build with InfoPipe support [yes]]
                               )
                ],
                [with_infopipe=$withval],
                with_infopipe=yes
               )

    if test x"$with_infopipe" = xyes; then
        AC_DEFINE(BUILD_IFP, 1, [whether to build with InfoPipe support])
    fi
    AM_CONDITIONAL([BUILD_IFP], [test x"$with_infopipe" = xyes])
  ])

AC_DEFUN([WITH_LIBWBCLIENT],
  [ AC_ARG_WITH([libwbclient],
                [AC_HELP_STRING([--with-libwbclient],
                                [Whether to build SSSD implementation of libwbclient [yes]]
                               )
                ],
                [with_libwbclient=$withval],
                with_libwbclient=yes
               )

    if test x"$with_libwbclient" = xyes; then
        AC_DEFINE(BUILD_LIBWBCLIENT, 1, [whether to build SSSD implementation of libwbclient])

        libwbclient_version="0.13"
        AC_SUBST(libwbclient_version)

        libwbclient_version_info="13:0:13"
        AC_SUBST(libwbclient_version_info)
    fi
    AM_CONDITIONAL([BUILD_LIBWBCLIENT], [test x"$with_libwbclient" = xyes])
  ])

AC_DEFUN([WITH_SAMBA],
  [ AC_ARG_WITH([samba],
                [AC_HELP_STRING([--with-samba],
                                [Whether to build with samba4 libraries [yes]]
                               )
                ],
                [with_samba=$withval],
                [with_samba=yes]
               )

    if test x"$with_samba" = xyes; then
        AC_DEFINE(BUILD_SAMBA, 1, [whether to build with samba support])
    fi
    AM_CONDITIONAL([BUILD_SAMBA], [test x"$with_samba" = xyes])
  ])

AC_ARG_ENABLE([dbus-tests],
              [AS_HELP_STRING([--enable-dbus-tests],
                              [enable running tests using a dbus server instance [default=yes]])],
              [build_dbus_tests=$enableval],
              [build_dbus_tests=yes])
AM_CONDITIONAL([BUILD_DBUS_TESTS], [test x$build_dbus_tests = xyes])

AC_ARG_ENABLE([sss-default-nss-plugin],
              [AS_HELP_STRING([--enable-sss-default-nss-plugin],
                              [This option change standard behaviour of sss nss
                               plugin. If this option is enabled the sss nss
                               plugin will behave as it was not in
                               nsswitch.conf when sssd is not running.
                               [default=no]])],
              [enable_sss_default_nss_plugin=$enableval],
              [enable_sss_default_nss_plugin=no])
AS_IF([test x$enable_sss_default_nss_plugin = xyes],
      AC_DEFINE_UNQUOTED([NONSTANDARD_SSS_NSS_BEHAVIOUR], [1],
          [whether to build sssd nss plugin with nonstandard glibc behaviour]))

AC_DEFUN([WITH_NFS],
  [ AC_ARG_WITH([nfsv4-idmapd-plugin],
                [AC_HELP_STRING([--with-nfsv4-idmapd-plugin],
                                [Whether to build with NFSv4 IDMAP support [yes]]
                               )
                ],
                [with_nfsv4_idmap=$withval],
                [with_nfsv4_idmap=yes]
               )

    if test x"$with_nfsv4_idmap" = xyes; then
        AC_DEFINE(BUILD_NFS_IDMAP, 1, [whether to build with NFSv4 IDMAP support])
    fi
    AM_CONDITIONAL([BUILD_NFS_IDMAP], [test x"$with_nfsv4_idmap" = xyes])
  ])

AC_DEFUN([WITH_NFS_LIB_PATH],
  [ AC_ARG_WITH([nfs-lib-path],
                [AC_HELP_STRING([--with-nfs-lib-path=<path>],
                                [Path to the nfs library [${libdir}]]
                               )
                ]
               )
    nfslibpath="${libdir}"
    if test x"$with_nfs_lib_path" != x; then
        nfslibpath=$with_nfs_lib_path
    fi
    AC_SUBST(nfslibpath)
  ])

AC_DEFUN([WITH_SSSD_USER],
  [ AC_ARG_WITH([sssd-user],
                [AS_HELP_STRING([--with-sssd-user=<user>],
                                [User for running SSSD (root)]
                               )
                ]
               )

    SSSD_USER=root

    if test x"$with_sssd_user" != x; then
        SSSD_USER=$with_sssd_user
    fi

    AC_SUBST(SSSD_USER)
    AC_DEFINE_UNQUOTED(SSSD_USER, "$SSSD_USER", ["The default user to run SSSD as"])
    AM_CONDITIONAL([SSSD_USER], [test x"$with_sssd_user" != x])
  ])

  AC_DEFUN([WITH_AD_GPO_DEFAULT],
    [ AC_ARG_WITH([ad-gpo-default],
                  [AS_HELP_STRING([--with-ad-gpo-default=[enforcing|permissive]],
                                  [Default enforcing level for AD GPO access-control (enforcing)]
                                 )
                  ]
                 )
      GPO_DEFAULT=enforcing

      if test x"$with_ad_gpo_default" != x; then
          if test ! "$with_ad_gpo_default" = "enforcing" -a ! "$with_ad_gpo_default" = "permissive"; then
              AC_MSG_ERROR("GPO Default must be either "enforcing" or "permissive")
          else
              GPO_DEFAULT=$with_ad_gpo_default
          fi
      fi

      AC_SUBST(GPO_DEFAULT)
      AC_DEFINE_UNQUOTED(AD_GPO_ACCESS_MODE_DEFAULT, "$GPO_DEFAULT", ["The default enforcing level for AD GPO access-control"])
      AM_CONDITIONAL([GPO_DEFAULT_ENFORCING], [test x"$GPO_DEFAULT" = xenforcing])
  ])

AC_DEFUN([ENABLE_POLKIT_RULES_PATH],
  [
    polkitdir="/usr/share/polkit-1/rules.d"
    AC_ARG_ENABLE([polkit-rules-path],
                  [AC_HELP_STRING([--enable-polkit-rules-path=PATH],
                                  [Path to store polkit rules at. Use --disable to not install the rules at all. [/usr/share/polkit-1/rules.d]]
                                 )
                  ],
                  [ polkitdir=$enableval ],
                 )

    if test x"$polkitdir" != xno; then
        HAVE_POLKIT_RULES_D=1
        AC_SUBST(polkitdir)
    fi

    AM_CONDITIONAL([HAVE_POLKIT_RULES_D], [test x$HAVE_POLKIT_RULES_D != x])
  ])

dnl Backwards compat for older autoconf
AC_DEFUN([SSSD_RUNSTATEDIR],
  [
    if test x"$runstatedir" = x; then
        AC_SUBST([runstatedir],
                 ["${localstatedir}/run"])
    fi
  ])

AC_DEFUN([WITH_SECRETS],
  [ AC_ARG_WITH([secrets],
                [AC_HELP_STRING([--with-secrets],
                                [Whether to build with secrets support [yes]]
                               )
                ],
                [with_secrets=$withval],
                with_secrets=yes
               )

    if test x"$with_secrets" = xyes; then
        AC_DEFINE(BUILD_SECRETS, 1, [whether to build with SECRETS support])
    fi
    AM_CONDITIONAL([BUILD_SECRETS], [test x"$with_secrets" = xyes])
  ])

AC_DEFUN([WITH_SECRETS_DB_PATH],
  [ AC_ARG_WITH([secrets-db-path],
                [AC_HELP_STRING([--with-secrets-db-path=PATH],
                                [Path to the SSSD databases [/var/lib/sss/secrets]]
                               )
                ]
               )
    config_secdbpath="\"SSS_STATEDIR\"/secrets"
    secdbpath="${localstatedir}/lib/sss/secrets"
    if test x"$with_secrets_db_path" != x; then
        config_secdbpath=$with_secrets_db_path
        secdbpath=$with_secrets_db_path
    fi
    AC_SUBST(secdbpath)
    AC_DEFINE_UNQUOTED(SECRETS_DB_PATH, "$config_secdbpath", [Path to the SSSD Secrets databases])
  ])
