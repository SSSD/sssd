extra_distcheck_flags =
if HAVE_DEVSHM
    extra_distcheck_flags += --with-test-dir=/dev/shm
endif

if WITH_JOURNALD
    extra_distcheck_flags += --with-initscript=systemd
    extra_distcheck_flags += --with-syslog=journald
endif

if WITH_STDERR_SYSLOG
    extra_distcheck_flags += --with-syslog=stderr
endif

DISTCHECK_CONFIGURE_FLAGS = --with-ldb-lib-dir="$$dc_install_base"/lib/ldb \
                            $(extra_distcheck_flags) \
                            $(AUX_DISTCHECK_CONFIGURE_FLAGS)
CLEANFILES = $(NULL)
BUILT_SOURCES = $(NULL)

SUBDIRS = po

if HAVE_MANPAGES
SUBDIRS += src/man
endif

SUBDIRS += . src/tests/cwrap src/tests/intg src/tests/test_CA \
             src/tests/test_ECC_CA src/tools/analyzer

# Some old versions of automake don't define builddir
builddir ?= .

SETCAP = @SETCAP@
DOXYGEN = @DOXYGEN@

DISTSETUPOPTS =
if HAVE_DEBIAN
DISTSETUPOPTS += --install-layout=deb
endif

sssdlibexecdir = $(libexecdir)/sssd
sssdlibdir = $(libdir)/sssd
sssddefaultconfdir = $(sssdlibdir)/conf
ldblibdir = @ldblibdir@
if BUILD_KRB5_LOCATOR_PLUGIN
krb5plugindir = @krb5pluginpath@
endif
if BUILD_KRB5_LOCALAUTH_PLUGIN
krb5localauth_plugindir = @appmodpath@
endif
if BUILD_PAC_RESPONDER
krb5authdata_plugindir = @krb5authdatapluginpath@
endif
if BUILD_CIFS_IDMAP_PLUGIN
cifsplugindir = @cifspluginpath@
endif
if BUILD_SAMBA
winbindplugindir = @winbindpluginpath@
endif
sssdconfdir = $(sysconfdir)/sssd
sssddatadir = $(datadir)/sssd
sssdapiplugindir = $(sssddatadir)/sssd.api.d
sssdtapscriptdir = $(sssddatadir)/systemtap
krb5snippetsdir = $(sssddatadir)/krb5-snippets
dbuspolicydir = $(datadir)/dbus-1/system.d
dbusservicedir = $(datadir)/dbus-1/system-services
sss_statedir = $(localstatedir)/lib/sss
runstatedir = @runstatedir@
localedir = @localedir@
nsslibdir = @nsslibdir@
pamlibdir = @pammoddir@
autofslibdir = @appmodpath@
subidlibdir = @subidlibpath@
nfslibdir = @nfsidmaplibdir@

dbpath = @dbpath@
pluginpath = @pluginpath@
pidpath = @pidpath@
pipepath = @pipepath@
mcpath = @mcpath@
initdir = @initdir@
systemdunitdir = @systemdunitdir@
systemdconfdir = @systemdconfdir@
logpath = @logpath@
pubconfpath = @pubconfpath@
gpocachepath = @gpocachepath@
keytabdir = $(sss_statedir)/keytabs
pkgconfigdir = $(libdir)/pkgconfig
krb5rcachedir = @krb5rcachedir@
sudolibdir = @sudolibpath@
polkitdir = @polkitdir@
pamconfdir = $(sysconfdir)/pam.d
systemtap_tapdir = @tapset_dir@
sssdkcmdatadir = $(datadir)/sssd-kcm
deskprofilepath = $(sss_statedir)/deskprofile

if HAVE_SYSTEMD_UNIT

ifp_dbus_exec_comment = \# If system is configured to use systemd ifp service ("SystemdService=") then "Exec=" and "User=" options are not used
ifp_dbus_exec_cmd = $(sssdlibexecdir)/sssd_ifp --socket-activated
ifp_systemdservice = SystemdService=sssd-ifp.service
# SSSD requires a configuration file (either /etc/sssd/sssd.conf,
# or some snippet under /etc/sssd/sssd.conf.d/) to be present.
condconfigexists = ConditionPathExists=\|/etc/sssd/sssd.conf\nConditionDirectoryNotEmpty=\|/etc/sssd/conf.d/

# Bounding set needs to list capabilities required by ldap/krb5/selinux_childs and sssd_pam, otherwise they can't gain it.
# Capabilities usage by binaries:
#   - 'ldap_child': read keytab (dac_read_search)
#   - 'krb5_child':
#         - check old ccache / pre-check ccache path (dac_read_search, set*id)
#         - read keytab (dac_read_search)
#         - store TGT for a given user (set*id)
#   - 'selinux_child': use libsemanage (set*id)
#   - 'sssd_pam': read keytab in gss ops (dac_read_search)
capabilities = CapabilityBoundingSet= CAP_SETGID CAP_SETUID CAP_DAC_READ_SEARCH

if SSSD_NON_ROOT_USER
nss_service_user_group = User=$(SSSD_USER)\nGroup=$(SSSD_USER)
nss_socket_user_group = SocketUser=$(SSSD_USER)\nSocketGroup=$(SSSD_USER)
supplementary_groups = \# If service configured to be run under "root", uncomment "SupplementaryGroups"\n\#SupplementaryGroups=$(SSSD_USER)
else
supplementary_groups = \# Note: SSSD package was built without support of running as non-privileged user
endif # SSSD_NON_ROOT_USER

else
ifp_dbus_exec_comment = \# "sss_signal" is used to force SSSD monitor to trigger "sssd_ifp" reconnection to dbus
ifp_dbus_exec_cmd = $(sssdlibexecdir)/sss_signal
ifp_systemdservice =
endif # HAVE_SYSTEMD_UNIT

secdbpath = @secdbpath@

UNICODE_LIBS=@UNICODE_LIBS@

MKDIR_P = @MKDIR_P@
INSTALL = @INSTALL@

SSSD_USER = @SSSD_USER@

if SSSD_NON_ROOT_USER
ifp_non_root_owner_policy =  <policy user="$(SSSD_USER)"> <allow own="org.freedesktop.sssd.infopipe"/> </policy>
else
ifp_non_root_owner_policy =
endif


AM_CFLAGS = $(my_CFLAGS)
if WANT_AUX_INFO
    AM_CFLAGS += -aux-info $@.X
endif
if HAVE_GCC
    AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
                 -Wcast-qual -Wcast-align -Wwrite-strings -Wundef \
                 -Werror-implicit-function-declaration -Winit-self \
                 -Wmissing-include-dirs \
                 -fno-strict-aliasing \
                 -std=gnu99
endif

CMOCKA_CFLAGS = -fno-lto

pkgconfig_DATA =

ACLOCAL_AMFLAGS = -I m4 -I .

if BUILD_SSH
bin_PROGRAMS = \
    sss_ssh_authorizedkeys \
    sss_ssh_knownhosts \
    sss_ssh_knownhostsproxy
endif

sbin_PROGRAMS = \
    sssd \
    sss_cache \
    sss_override \
    sss_seed \
    sssctl \
    $(NULL)

sssdlibexec_PROGRAMS = \
    sssd_nss \
    sssd_pam \
    sssd_be \
    krb5_child \
    ldap_child \
    proxy_child \
    sss_signal \
    $(NULL)
if BUILD_SUDO
sssdlibexec_PROGRAMS += sssd_sudo
endif
if BUILD_AUTOFS
sssdlibexec_PROGRAMS += sssd_autofs
endif
if BUILD_SSH
sssdlibexec_PROGRAMS += sssd_ssh
endif
sssdlibexec_PROGRAMS += sssd_ifp
if BUILD_SAMBA
sssdlibexec_PROGRAMS += gpo_child
endif
if BUILD_SELINUX
sssdlibexec_PROGRAMS += selinux_child
endif
sssdlibexec_PROGRAMS += p11_child
if BUILD_PASSKEY
sssdlibexec_PROGRAMS += passkey_child
endif # BUILD_PASSKEY
if BUILD_OIDC_CHILD
sssdlibexec_PROGRAMS += oidc_child
endif
if SSSD_USER
if HAVE_POLKIT_RULES_D
polkit_rulesdir = $(polkitdir)
dist_polkit_rules_DATA = contrib/sssd-pcsc.rules
dist_polkit_rules_DATA += contrib/sssd-realmd.rules
endif
endif
if BUILD_KCM
sssdlibexec_PROGRAMS += sssd_kcm
dist_sssdkcmdata_DATA = contrib/kcm_default_ccache
endif


if BUILD_PAC_RESPONDER
    sssdlibexec_PROGRAMS += sssd_pac
endif
if HAVE_SYSTEMD_UNIT
sssdlibexec_PROGRAMS += sssd_check_socket_activated_responders
endif

if HAVE_CHECK
    non_interactive_check_based_tests = \
        dlopen-tests \
        sysdb-tests \
        strtonum-tests \
        resolv-tests \
        krb5-utils-tests \
        check_file-tests \
        files-tests \
        file_watch-tests \
        refcount-tests \
        fail_over-tests \
        find_uid-tests \
        auth-tests \
        ipa_ldap_opt-tests \
        ad_ldap_opt-tests \
        crypto-tests \
        util-tests \
        debug-tests \
        ipa_hbac-tests \
        sss_idmap-tests \
        responder_socket_access-tests \
        safe-format-tests

if BUILD_SSH
    non_interactive_check_based_tests += sysdb_ssh-tests
endif

endif # HAVE_CHECK

if HAVE_CMOCKA
    non_interactive_cmocka_based_tests = \
        nss-srv-tests \
        test-find-uid \
        test-io \
        test-negcache \
        test-authtok \
        test_prompt_config \
        sss_nss_idmap-tests \
        deskprofile_utils-tests \
        dyndns-tests \
        domain_resolution_order-tests \
        fqnames-tests \
        nestedgroups-tests \
        test_sss_idmap \
        test_ipa_idmap \
        test_utils \
        dp_opt_tests \
        responder-get-domains-tests \
        config_check-tests \
        test_search_bases \
        test_ldap_auth \
        test_sdap_access \
        test_sdap_certmap \
        sdap-tests \
        test_sysdb_ts_cache \
        test_sysdb_views \
        test_sysdb_subdomains \
        test_sysdb_certmap \
        test_sysdb_sudo \
        test_sysdb_utils \
        test_sysdb_domain_resolution_order \
        test_be_ptask \
        test_copy_ccache \
        test_copy_keytab \
        test_child_common \
        responder_cache_req-tests \
        test_sbus_message \
        test_sbus_opath \
        test_fo_srv \
        pam-srv-tests \
        ssh-srv-tests \
        test_ipa_subdom_util \
        test_tools_colondb \
        test_krb5_wait_queue \
        test_cert_utils \
        test_ldap_id_cleanup \
        test_data_provider_be \
        test_dp_request \
        test_dp_builtin \
        test_ipa_dn \
        simple-access-tests \
        krb5_common_test \
        test_iobuf \
        sss_certmap_test \
        test_sssd_krb5_locator_plugin \
        test_confdb \
        test_krb5_idp_plugin \
        $(NULL)


if HAVE_LIBRESOLV
non_interactive_cmocka_based_tests += test_resolv_fake
endif   # HAVE_LIBRESOLV

non_interactive_cmocka_based_tests += ifp_tests

if HAVE_INOTIFY
non_interactive_cmocka_based_tests += test_inotify
endif   # HAVE_INOTIFY

if BUILD_KCM
non_interactive_cmocka_based_tests += \
	test_kcm_marshalling \
	test_kcm_queue \
    $(NULL)
endif   # BUILD_KCM

if BUILD_KCM_RENEWAL
non_interactive_cmocka_based_tests += test_kcm_renewals
endif # BUILD_KCM_RENEWAL

if BUILD_PASSKEY
non_interactive_cmocka_based_tests += test_passkey test_krb5_passkey_plugin
endif # BUILD_PASSKEY


if BUILD_SAMBA
non_interactive_cmocka_based_tests += \
    ad_access_filter_tests \
    ad_gpo_tests \
    ad_common_tests \
    test_sdap_initgr \
    test_ad_subdom \
    test_ipa_subdom_server \
    $(NULL)
endif

if BUILD_KRB5_LOCALAUTH_PLUGIN
non_interactive_cmocka_based_tests += test_sssd_krb5_localauth_plugin
endif # BUILD_KRB5_LOCALAUTH_PLUGIN

endif   # HAVE_CMOCKA

check_PROGRAMS = \
    stress-tests \
    test_ssh_client \
    $(non_interactive_cmocka_based_tests) \
    $(non_interactive_check_based_tests)

if HAVE_CMOCKA
check_PROGRAMS += dummy-child
endif # HAVE_CMOCKA

PYTHON_TESTS =

if BUILD_PYTHON2_BINDINGS
PYTHON_TESTS += src/config/SSSDConfigTest.py2.sh \
                src/tests/pyhbac-test.py2.sh \
                src/tests/pysss-test.py2.sh \
                src/tests/pysss_murmur-test.py2.sh \
                $(NULL)
endif
if BUILD_PYTHON3_BINDINGS
PYTHON_TESTS += src/config/SSSDConfigTest.py3.sh \
                src/tests/pyhbac-test.py3.sh \
                src/tests/pysss-test.py3.sh \
                src/tests/pysss_murmur-test.py3.sh \
                $(NULL)
endif

TEST_EXTENSIONS = .sh
TESTS = \
    $(PYTHON_TESTS) \
    $(non_interactive_cmocka_based_tests) \
    $(non_interactive_check_based_tests) \
    src/tests/whitespace_test \
    src/tests/double_semicolon_test \
    $(NULL)

sssdlib_LTLIBRARIES = \
    libsss_ldap.la \
    libsss_krb5.la \
    libsss_proxy.la \
    libsss_simple.la \
    $(NULL)

if BUILD_SAMBA
sssdlib_LTLIBRARIES += \
    libsss_ipa.la \
    libsss_ad.la
endif

ldblib_LTLIBRARIES = \
    memberof.la

if BUILD_KRB5_LOCATOR_PLUGIN
krb5plugin_LTLIBRARIES = \
    sssd_krb5_locator_plugin.la
endif

if BUILD_KRB5_LOCALAUTH_PLUGIN
krb5localauth_plugin_LTLIBRARIES = \
    sssd_krb5_localauth_plugin.la
endif

if BUILD_PAC_RESPONDER
krb5authdata_plugin_LTLIBRARIES = \
    sssd_pac_plugin.la
endif

if BUILD_CIFS_IDMAP_PLUGIN
cifsplugin_LTLIBRARIES = \
    cifs_idmap_sss.la
endif

if BUILD_SAMBA
winbindplugin_LTLIBRARIES = \
    winbind_idmap_sss.la \
    $(NULL)
endif

noinst_LTLIBRARIES =

pkglib_LTLIBRARIES =

if BUILD_PYTHON2_BINDINGS
py2exec_LTLIBRARIES = \
    _py2sss.la \
    _py2hbac.la \
    _py2sss_murmur.la \
    _py2sss_nss_idmap.la \
    $(NULL)
endif

if BUILD_PYTHON3_BINDINGS
py3exec_LTLIBRARIES = \
    _py3sss.la \
    _py3hbac.la \
    _py3sss_murmur.la \
    _py3sss_nss_idmap.la \
    $(NULL)
endif

sbin_SCRIPTS = \
	src/tools/wrappers/sss_debuglevel \
	$(NULL)

dist_noinst_SCRIPTS = \
    $(EXTRA_SCRIPTS) \
    src/config/setup.py \
    src/config/SSSDConfig/ipachangeconf.py \
    src/config/SSSDConfig/sssdoptions.py \
    src/config/SSSDConfig/__init__.py \
    src/config/SSSDConfigTest.py \
    src/config/SSSDConfigTest.py2.sh \
    src/config/SSSDConfigTest.py3.sh \
    contrib/fedora/bashrc_sssd \
    contrib/fedora/make_srpm.sh \
    contrib/ci/clean \
    contrib/ci/rpm-spec-builddeps \
    contrib/ci/run \
    contrib/ci/valgrind-condense \
    src/tests/pyhbac-test.py \
    src/tests/pyhbac-test.py2.sh \
    src/tests/pyhbac-test.py3.sh \
    src/tests/pysss-test.py \
    src/tests/pysss-test.py2.sh \
    src/tests/pysss-test.py3.sh \
    src/tests/pysss_murmur-test.py \
    src/tests/pysss_murmur-test.py2.sh \
    src/tests/pysss_murmur-test.py3.sh \
    src/tests/python-test.py \
    src/tests/whitespace_test \
    src/tests/double_semicolon_test \
    src/tests/krb5_proxy_check_test_data.conf \
    $(NULL)

dist_noinst_DATA = \
    src/config/testconfigs/sssd-valid.conf \
    src/config/testconfigs/noparse.api.conf \
    src/config/testconfigs/sssd-noversion.conf \
    src/config/testconfigs/sssd-invalid.conf \
    src/config/testconfigs/sssd-invalid-badbool.conf \
    src/config/testconfigs/sssd-nonexisting-services-domains.conf \
    src/config/testconfigs/sssd-test-parse.conf \
    src/config/testconfigs/sssd-enabled-option.conf \
    src/config/etc/sssd.api.d/crash_test_dummy \
    contrib/ci/README.md \
    contrib/ci/configure.sh \
    contrib/ci/deps.sh \
    contrib/ci/distro.sh \
    contrib/ci/misc.sh \
    contrib/ci/sssd.supp \
    $(SYSTEMTAP_PROBES) \
    $(NULL)

###############################
# Global compilation settings #
###############################

AM_CPPFLAGS = \
    -Wall \
    -I.. \
    -I$(srcdir)/src/sss_client \
    -I$(srcdir)/src \
    -I. \
    $(POPT_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(TDB_CFLAGS) \
    $(TEVENT_CFLAGS) \
    $(LDB_CFLAGS) \
    $(DBUS_CFLAGS) \
    $(PCRE_CFLAGS) \
    $(INI_CONFIG_CFLAGS) \
    $(DHASH_CFLAGS) \
    $(LIBNL_CFLAGS) \
    $(OPENLDAP_CFLAGS) \
    $(GLIB2_CFLAGS) \
    $(JOURNALD_CFLAGS) \
    -DLIBDIR=\"$(libdir)\" \
    -DVARDIR=\"$(localstatedir)\" \
    -DRUNDIR=\"$(runstatedir)\" \
    -DSSS_STATEDIR=\"$(sss_statedir)\" \
    -DSYSCONFDIR=\"$(sysconfdir)\" \
    -DSHLIBEXT=\"$(SHLIBEXT)\" \
    -DSSSDDATADIR=\"$(sssddatadir)\" \
    -DSSSD_LIBEXEC_PATH=\"$(sssdlibexecdir)\" \
    -DSSSD_CONF_DIR=\"$(sssdconfdir)\" \
    -DSSS_NSS_MCACHE_DIR=\"$(mcpath)\" \
    -DSSS_NSS_SOCKET_NAME=\"$(pipepath)/nss\" \
    -DSSS_PAM_SOCKET_NAME=\"$(pipepath)/pam\" \
    -DSSS_PAC_SOCKET_NAME=\"$(pipepath)/pac\" \
    -DSSS_SUDO_SOCKET_NAME=\"$(pipepath)/sudo\" \
    -DSSS_AUTOFS_SOCKET_NAME=\"$(pipepath)/autofs\" \
    -DSSS_SSH_SOCKET_NAME=\"$(pipepath)/ssh\" \
    -DLOCALEDIR=\"$(localedir)\" \
    -DBASE_FILE_STEM=\"$(*F)\" \
    $(NULL)

EXTRA_DIST =

SSSD_CACHE_REQ_OBJ = \
	src/responder/common/cache_req/cache_req.c \
	src/responder/common/cache_req/cache_req_result.c \
	src/responder/common/cache_req/cache_req_search.c \
	src/responder/common/cache_req/cache_req_data.c \
	src/responder/common/cache_req/cache_req_domain.c \
	src/responder/common/cache_req/cache_req_sr_overlay.c \
	src/responder/common/cache_req/plugins/cache_req_common.c \
	src/responder/common/cache_req/plugins/cache_req_enum_users.c \
	src/responder/common/cache_req/plugins/cache_req_enum_groups.c \
	src/responder/common/cache_req/plugins/cache_req_enum_svc.c \
	src/responder/common/cache_req/plugins/cache_req_enum_ip_hosts.c \
	src/responder/common/cache_req/plugins/cache_req_enum_ip_networks.c \
	src/responder/common/cache_req/plugins/cache_req_user_by_name.c \
	src/responder/common/cache_req/plugins/cache_req_user_by_upn.c \
	src/responder/common/cache_req/plugins/cache_req_user_by_id.c \
	src/responder/common/cache_req/plugins/cache_req_user_by_filter.c \
	src/responder/common/cache_req/plugins/cache_req_user_by_cert.c \
	src/responder/common/cache_req/plugins/cache_req_group_by_name.c \
	src/responder/common/cache_req/plugins/cache_req_group_by_id.c \
	src/responder/common/cache_req/plugins/cache_req_group_by_filter.c \
	src/responder/common/cache_req/plugins/cache_req_initgroups_by_name.c \
	src/responder/common/cache_req/plugins/cache_req_initgroups_by_upn.c \
	src/responder/common/cache_req/plugins/cache_req_object_by_sid.c \
	src/responder/common/cache_req/plugins/cache_req_object_by_name.c \
	src/responder/common/cache_req/plugins/cache_req_object_by_id.c \
	src/responder/common/cache_req/plugins/cache_req_svc_by_name.c \
	src/responder/common/cache_req/plugins/cache_req_svc_by_port.c \
	src/responder/common/cache_req/plugins/cache_req_netgroup_by_name.c \
	src/responder/common/cache_req/plugins/cache_req_ssh_host_id_by_name.c \
	src/responder/common/cache_req/plugins/cache_req_autofs_map_entries.c \
	src/responder/common/cache_req/plugins/cache_req_autofs_map_by_name.c \
	src/responder/common/cache_req/plugins/cache_req_autofs_entry_by_name.c \
	src/responder/common/cache_req/plugins/cache_req_ip_host_by_name.c \
	src/responder/common/cache_req/plugins/cache_req_ip_host_by_addr.c \
	src/responder/common/cache_req/plugins/cache_req_ip_network_by_name.c \
	src/responder/common/cache_req/plugins/cache_req_ip_network_by_addr.c \
	$(NULL)
if BUILD_SUBID
    SSSD_CACHE_REQ_OBJ += src/responder/common/cache_req/plugins/cache_req_subid_ranges_by_name.c
endif

SSSD_RESPONDER_IFACE_OBJ = \
    src/responder/common/responder_iface.c \
    $(NULL)

SSSD_RESPONDER_OBJ = \
    src/responder/common/negcache.c \
    src/util/nss_dl_load.c \
    src/responder/common/responder_cmd.c \
    src/responder/common/responder_common.c \
    src/responder/common/responder_dp.c \
    src/responder/common/responder_packet.c \
    src/responder/common/responder_get_domains.c \
    src/responder/common/responder_utils.c \
    src/providers/data_provider_req.c \
    src/util/session_recording.c \
    $(SSSD_RESPONDER_IFACE_OBJ) \
    $(SSSD_CACHE_REQ_OBJ) \
    $(NULL)

SSSD_TOOLS_OBJ = \
    src/tools/tools_util.c \
    src/tools/common/sss_tools.c \
    src/tools/common/sss_process.c \
    src/confdb/confdb_setup.c \
    $(NULL)

SSSD_LCL_TOOLS_OBJ = \
    src/sss_client/common.c \
    src/tools/tools_mc_util.c \
    $(SSSD_TOOLS_OBJ)

SSSD_RESOLV_OBJ = \
    src/resolv/async_resolv.c \
    src/resolv/async_resolv_utils.c

SSSD_FAILOVER_OBJ = \
    src/providers/fail_over.c \
    src/providers/fail_over_srv.c \
    $(SSSD_RESOLV_OBJ)

SSSD_LIBS = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(LDB_LIBS) \
    $(DBUS_LIBS) \
    $(DHASH_LIBS) \
    $(SELINUX_LIBS) \
    $(TDB_LIBS)

if HAVE_SYSTEMD_UNIT
    SSSD_LIBS += $(SYSTEMD_DAEMON_LIBS)
endif

PYTHON_BINDINGS_LIBS = \
    $(TALLOC_LIBS) \
    $(POPT_LIBS) \
    $(LDB_LIBS) \
    $(NULL)

TOOLS_LIBS = \
    $(LTLIBINTL) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(LDB_LIBS) \
    $(DBUS_LIBS) \
    $(DHASH_LIBS) \
    $(TDB_LIBS)

if BUILD_SELINUX
    PYTHON_BINDINGS_LIBS += $(SELINUX_LIBS)
    TOOLS_LIBS += $(SELINUX_LIBS)
endif

dist_noinst_HEADERS = \
    src/sss_iface/sbus_sss_arguments.h \
    src/sss_iface/sbus_sss_client_async.h \
    src/sss_iface/sbus_sss_client_properties.h \
    src/sss_iface/sbus_sss_client_sync.h \
    src/sss_iface/sbus_sss_interface.h \
    src/sss_iface/sbus_sss_invokers.h \
    src/sss_iface/sbus_sss_keygens.h \
    src/sss_iface/sbus_sss_server.h \
    src/sss_iface/sbus_sss_symbols.h \
    src/sss_iface/sss_iface_types.h \
    src/sss_iface/sss_iface_async.h \
    src/sss_iface/sss_iface_sync.h \
    src/sss_iface/sss_iface.h \
    src/util/crypto/sss_crypto.h \
    src/util/cert.h \
    src/util/dlinklist.h \
    src/util/debug.h \
    src/util/memory_erase.h \
    src/util/util.h \
    src/util/util_errors.h \
    src/util/safe-format-string.h \
    src/util/session_recording.h \
    src/util/strtonum.h \
    src/util/sss_cli_cmd.h \
    src/util/sss_chain_id_tevent.h \
    src/util/sss_chain_id.h \
    src/util/sss_ptr_hash.h \
    src/util/sss_ptr_list.h \
    src/util/sss_endian.h \
    src/util/sss_nss.h \
    src/util/sss_ldap.h \
    src/util/sss_python.h \
    src/util/sss_regexp.h \
    src/util/sss_krb5.h \
    src/util/sss_sockets.h \
    src/util/sss_utf8.h \
    src/util/sss_ssh.h \
    src/util/sss_ini.h \
    src/util/sss_format.h \
    src/util/sss_pam_data.h \
    src/util/sss_prctl.h \
    src/util/refcount.h \
    src/util/file_watch.h \
    src/util/find_uid.h \
    src/util/user_info_msg.h \
    src/util/mmap_cache.h \
    src/util/atomic_io.h \
    src/util/auth_utils.h \
    src/util/authtok.h \
    src/util/authtok-utils.h \
    src/util/util_sss_idmap.h \
    src/util/util_creds.h \
    src/util/inotify.h \
    src/util/sss_iobuf.h \
    src/responder/kcm/secrets/secrets.h \
    src/responder/kcm/secrets/sec_pvt.h \
    src/util/nss_dl_load.h \
    src/responder/common/responder.h \
    src/responder/common/responder_packet.h \
    src/responder/common/cache_req/cache_req.h \
    src/responder/common/cache_req/cache_req_domain.h \
    src/responder/common/cache_req/cache_req_plugin.h \
    src/responder/common/cache_req/cache_req_private.h \
    src/responder/pam/pamsrv.h \
    src/responder/pam/pam_helpers.h \
    src/responder/pam/pamsrv_passkey.h \
    src/responder/nss/nss_private.h \
    src/responder/nss/nss_protocol.h \
    src/responder/nss/nss_iface.h \
    src/responder/nss/nsssrv_mmap_cache.h \
    src/responder/pac/pacsrv.h \
    src/responder/common/negcache.h \
    src/responder/sudo/sudosrv_private.h \
    src/responder/autofs/autofs_private.h \
    src/responder/ssh/ssh_private.h \
    src/responder/ifp/ifp_private.h \
    src/responder/ifp/ifp_domains.h \
    src/responder/ifp/ifp_components.h \
    src/responder/ifp/ifp_users.h \
    src/responder/ifp/ifp_groups.h \
    src/responder/ifp/ifp_cache.h \
    src/responder/ifp/ifp_iface/sbus_ifp_arguments.h \
    src/responder/ifp/ifp_iface/sbus_ifp_client_async.h \
    src/responder/ifp/ifp_iface/sbus_ifp_client_properties.h \
    src/responder/ifp/ifp_iface/sbus_ifp_client_sync.h \
    src/responder/ifp/ifp_iface/sbus_ifp_interface.h \
    src/responder/ifp/ifp_iface/sbus_ifp_invokers.h \
    src/responder/ifp/ifp_iface/sbus_ifp_keygens.h \
    src/responder/ifp/ifp_iface/sbus_ifp_server.h \
    src/responder/ifp/ifp_iface/sbus_ifp_symbols.h \
    src/responder/ifp/ifp_iface/ifp_iface.h \
    src/responder/ifp/ifp_iface/ifp_iface_types.h \
    src/responder/ifp/ifp_iface/ifp_iface_async.h \
    src/responder/ifp/ifp_iface/ifp_iface_sync.h \
    src/responder/kcm/kcm_renew.h \
    src/responder/kcm/kcmsrv_pvt.h \
    src/responder/kcm/kcmsrv_ccache.h \
    src/responder/kcm/kcmsrv_ccache_pvt.h \
    src/responder/kcm/kcmsrv_ccache_be.h \
    src/responder/kcm/kcmsrv_ops.h \
    src/sbus/sbus_annotations.h \
    src/sbus/sbus_declarations.h \
    src/sbus/sbus_errors.h \
    src/sbus/sbus.h \
    src/sbus/sbus_interface_declarations.h \
    src/sbus/sbus_interface.h \
    src/sbus/sbus_message.h \
    src/sbus/sbus_opath.h \
    src/sbus/sbus_private.h \
    src/sbus/sbus_request.h \
    src/sbus/sbus_sync.h \
    src/sbus/sbus_sync_private.h \
    src/sbus/sbus_typeof.h \
    src/sbus/connection/sbus_dbus_private.h \
    src/sbus/interface_dbus/sbus_dbus_arguments.h \
    src/sbus/interface_dbus/sbus_dbus_client_async.h \
    src/sbus/interface_dbus/sbus_dbus_client_sync.h \
    src/sbus/interface_dbus/sbus_dbus_client_properties.h \
    src/sbus/interface_dbus/sbus_dbus_interface.h \
    src/sbus/interface_dbus/sbus_dbus_invokers.h \
    src/sbus/interface_dbus/sbus_dbus_keygens.h \
    src/sbus/interface_dbus/sbus_dbus_server.h \
    src/sbus/interface_dbus/sbus_dbus_symbols.h \
    src/sbus/interface/sbus_iterator_readers.h \
    src/sbus/interface/sbus_iterator_writers.h \
    src/db/sysdb.h \
    src/db/sysdb_sudo.h \
    src/db/sysdb_autofs.h \
    src/db/sysdb_selinux.h \
    src/db/sysdb_private.h \
    src/db/sysdb_services.h \
    src/db/sysdb_ssh.h \
    src/db/sysdb_subid.h \
    src/db/sysdb_domain_resolution_order.h \
    src/db/sysdb_passkey_user_verification.h \
    src/db/sysdb_iphosts.h \
    src/db/sysdb_ipnetworks.h \
    src/confdb/confdb.h \
    src/confdb/confdb_private.h \
    src/confdb/confdb_setup.h \
    src/providers/data_provider.h \
    src/providers/data_provider_req.h \
    src/providers/data_provider/dp.h \
    src/providers/data_provider/dp_flags.h \
    src/providers/data_provider/dp_private.h \
    src/providers/data_provider/dp_request.h \
    src/providers/data_provider/dp_custom_data.h \
    src/providers/data_provider/dp_builtin.h \
    src/providers/data_provider/dp_iface.h \
    src/providers/backend.h \
    src/providers/be_dyndns.h \
    src/providers/be_netlink.h \
    src/providers/be_ptask_private.h \
    src/providers/be_ptask.h \
    src/providers/be_refresh.h \
    src/providers/fail_over.h \
    src/providers/fail_over_srv.h \
    src/util/child_common.h \
    src/providers/simple/simple_access.h \
    src/providers/simple/simple_access_pvt.h \
    src/providers/krb5/krb5_auth.h \
    src/providers/krb5/krb5_common.h \
    src/providers/krb5/krb5_utils.h \
    src/providers/krb5/krb5_init_shared.h \
    src/providers/krb5/krb5_opts.h \
    src/providers/krb5/krb5_ccache.h \
    src/providers/ldap/ldap_common.h \
    src/providers/ldap/sdap.h \
    src/providers/ldap/sdap_access.h \
    src/providers/ldap/sdap_async.h \
    src/providers/ldap/sdap_async_ad.h \
    src/providers/ldap/sdap_async_private.h \
    src/providers/ldap/sdap_sudo.h \
    src/providers/ldap/sdap_sudo_shared.h \
    src/providers/ldap/sdap_autofs.h \
    src/providers/ldap/sdap_id_op.h \
    src/providers/ldap/ldap_opts.h \
    src/providers/ldap/ldap_auth.h \
    src/providers/ldap/sdap_range.h \
    src/providers/ldap/sdap_users.h \
    src/providers/ldap/sdap_dyndns.h \
    src/providers/ldap/sdap_async_enum.h \
    src/providers/ldap/sdap_async_resolver_enum.h \
    src/providers/ldap/sdap_ops.h \
    src/providers/ldap/ldap_resolver_enum.h \
    src/providers/ipa/ipa_common.h \
    src/providers/ipa/ipa_config.h \
    src/providers/ipa/ipa_access.h \
    src/providers/ipa/ipa_selinux.h \
    src/providers/ipa/ipa_hosts.h \
    src/providers/ipa/ipa_selinux_maps.h \
    src/providers/ipa/ipa_selinux_helpers.h \
    src/providers/ipa/ipa_auth.h \
    src/providers/ipa/ipa_dyndns.h \
    src/providers/ipa/ipa_subdomains.h \
    src/providers/ipa/ipa_subdomains_passkey.h \
    src/providers/ipa/ipa_id.h \
    src/providers/ipa/ipa_opts.h \
    src/providers/ipa/ipa_srv.h \
    src/providers/ipa/ipa_dn.h \
    src/providers/ipa/ipa_sudo.h \
    src/providers/ipa/ipa_session.h \
    src/providers/ad/ad_srv.h \
    src/providers/ad/ad_common.h \
    src/providers/ad/ad_pac.h \
    src/providers/ad/ad_id.h \
    src/providers/ad/ad_access.h \
    src/providers/ad/ad_gpo.h \
    src/providers/ad/ad_opts.h \
    src/providers/ad/ad_domain_info.h \
    src/providers/ad/ad_subdomains.h \
    src/providers/ad/ad_resolver.h \
    src/providers/proxy/proxy.h \
    src/tools/tools_util.h \
    src/resolv/async_resolv.h \
    src/tests/common.h \
    src/tests/common_check.h \
    src/tests/cmocka/common_mock.h \
    src/tests/cmocka/common_mock_resp.h \
    src/tests/cmocka/common_mock_sdap.h \
    src/tests/cmocka/common_mock_sysdb_objects.h \
    src/tests/cmocka/common_mock_krb5.h \
    src/tests/cmocka/common_mock_be.h \
    src/tests/cmocka/test_expire_common.h \
    src/tests/cmocka/test_sdap_access.h \
    src/tests/cmocka/data_provider/mock_dp.h \
    src/sss_client/pam_message.h \
    src/sss_client/ssh/sss_ssh_client.h \
    src/sss_client/sudo/sss_sudo.h \
    src/sss_client/nfs/nfsidmap_internal.h \
    src/lib/idmap/sss_idmap_private.h \
    src/lib/winbind_idmap_sss/winbind_idmap_sss.h \
    src/tests/cmocka/test_utils.h \
    src/tools/common/sss_tools.h \
    src/tools/common/sss_process.h \
    src/tools/common/sss_colondb.h \
    src/tools/sssctl/sssctl.h \
    src/util/probes.h \
    src/shared/io.h \
    src/shared/cred.h \
    src/shared/murmurhash3.h \
    src/shared/safealign.h \
    src/p11_child/p11_child.h \
    src/oidc_child/oidc_child_util.h \
    src/passkey_child/passkey_child.h \
    src/krb5_plugin/common/radius_kdcpreauth.h \
    src/krb5_plugin/common/radius_clpreauth.h \
    src/krb5_plugin/common/utils.h \
    $(NULL)


SSSD_DOCS = \
    doc \
    hbac_doc \
    idmap_doc \
    nss_idmap_doc

CLIENT_LIBS = $(LTLIBINTL)

if WITH_JOURNALD
SYSLOG_LIBS = $(JOURNALD_LIBS)
endif

#####################
# Utility libraries #
#####################
pkglib_LTLIBRARIES += libsss_debug.la
libsss_debug_la_SOURCES = \
    src/util/debug.c \
    src/util/debug_backtrace.c \
    src/util/sss_log.c \
    src/util/sss_cli_cmd.c \
    $(NULL)
libsss_debug_la_LIBADD = \
    $(SYSLOG_LIBS)
libsss_debug_la_LDFLAGS = \
    -avoid-version

pkglib_LTLIBRARIES += libsss_child.la
libsss_child_la_SOURCES = src/util/child_common.c
libsss_child_la_LIBADD = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(DHASH_LIBS) \
    libsss_debug.la \
    $(NULL)
libsss_child_la_LDFLAGS = -avoid-version

pkglib_LTLIBRARIES += libsss_crypt.la

SSS_CRYPT_SOURCES = src/util/crypto/libcrypto/crypto_base64.c \
                    src/util/crypto/libcrypto/crypto_hmac_sha1.c \
                    src/util/crypto/libcrypto/crypto_sha512crypt.c \
                    src/util/crypto/libcrypto/crypto_obfuscate.c \
                    src/util/crypto/libcrypto/crypto_prng.c \
                    src/util/atomic_io.c \
                    src/util/memory.c \
                    src/util/memory_erase.c \
                    $(NULL)
SSS_CRYPT_CFLAGS = $(CRYPTO_CFLAGS)
SSS_CRYPT_LIBS = $(CRYPTO_LIBS)

SSS_CERT_SOURCES = \
    src/util/cert/cert_common.c \
    src/util/cert/libcrypto/cert.c \
    $(NULL)
SSS_CERT_CFLAGS = \
    $(CRYPTO_CFLAGS) \
    $(NULL)
SSS_CERT_LIBS = \
    $(CRYPTO_LIBS) \
    $(NULL)

libsss_crypt_la_SOURCES = \
    $(SSS_CRYPT_SOURCES)
libsss_crypt_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(SSS_CRYPT_CFLAGS) \
    $(DHASH_CFLAGS)
libsss_crypt_la_LIBADD = \
    $(SSS_CRYPT_LIBS) \
    $(DHASH_LIBS) \
    $(TALLOC_LIBS) \
    libsss_debug.la \
    $(NULL)
libsss_crypt_la_LDFLAGS = \
    -avoid-version

pkglib_LTLIBRARIES += libsss_cert.la

libsss_cert_la_SOURCES = \
    $(SSS_CERT_SOURCES) \
    $(NULL)
libsss_cert_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(SSS_CERT_CFLAGS) \
    $(NULL)
# NOTE:
# There is a dependency between libsss_cert and libsss_child which should
# always be declared explicitly and if missing might cause issue in some
# environments (e.g. Gentoo or OpenSUSE build service), even if it is
# resolved otherwise while linking the binaries.
libsss_cert_la_LIBADD = \
    $(SSS_CERT_LIBS) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    libsss_crypt.la \
    libsss_child.la \
    libsss_debug.la \
    $(NULL)
libsss_cert_la_LDFLAGS = \
    -avoid-version \
    $(NULL)

generate-sbus-code:
	$(builddir)/sbus_generate.sh $(abs_srcdir)

.PHONY: generate-sbus-code

BUILT_SOURCES += generate-sbus-code

EXTRA_DIST += \
    sbus_generate.sh.in \
    src/sbus/codegen/dbus.xml \
    src/sbus/codegen/sbus_CodeGen.py \
    src/sbus/codegen/sbus_DataType.py \
    src/sbus/codegen/sbus_Generator.py \
    src/sbus/codegen/sbus_Introspection.py \
    src/sbus/codegen/sbus_Invoker.py \
    src/sbus/codegen/sbus_Template.py \
    src/sbus/codegen/templates/arguments.c.tpl \
    src/sbus/codegen/templates/arguments.h.tpl \
    src/sbus/codegen/templates/client_async.c.tpl \
    src/sbus/codegen/templates/client_async.h.tpl \
    src/sbus/codegen/templates/client_properties.h.tpl \
    src/sbus/codegen/templates/client_sync.c.tpl \
    src/sbus/codegen/templates/client_sync.h.tpl \
    src/sbus/codegen/templates/interface.h.tpl \
    src/sbus/codegen/templates/invokers.c.tpl \
    src/sbus/codegen/templates/invokers.h.tpl \
    src/sbus/codegen/templates/keygens.c.tpl \
    src/sbus/codegen/templates/keygens.h.tpl \
    src/sbus/codegen/templates/server.h.tpl \
    src/sbus/codegen/templates/symbols.c.tpl \
    src/sbus/codegen/templates/symbols.h.tpl \
    src/sss_iface/sss_iface.xml \
    src/sss_iface/external_iface.xml \
    src/responder/ifp/ifp_iface/ifp_iface.xml \
    $(NULL)

pkglib_LTLIBRARIES += libsss_sbus.la
libsss_sbus_la_SOURCES = \
    src/util/check_file.c \
    src/util/debug.c \
    src/util/debug_backtrace.c \
    src/util/sss_chain_id.c \
    src/util/sss_ptr_hash.c \
    src/util/sss_ptr_list.c \
    src/util/sss_utf8.c \
    src/util/util.c \
    src/util/util_errors.c \
    src/util/util_ext.c \
    src/util/strtonum.c \
    src/sbus/sbus_errors.c \
    src/sbus/sbus_opath.c \
    src/sbus/connection/sbus_connection.c \
    src/sbus/connection/sbus_connection_connect.c \
    src/sbus/connection/sbus_dbus.c \
    src/sbus/connection/sbus_dispatcher.c \
    src/sbus/connection/sbus_reconnect.c \
    src/sbus/connection/sbus_send.c \
    src/sbus/connection/sbus_watch.c \
    src/sbus/interface_dbus/sbus_dbus_arguments.c \
    src/sbus/interface_dbus/sbus_dbus_client_async.c \
    src/sbus/interface_dbus/sbus_dbus_invokers.c \
    src/sbus/interface_dbus/sbus_dbus_keygens.c \
    src/sbus/interface_dbus/sbus_dbus_symbols.c \
    src/sbus/interface/sbus_interface.c \
    src/sbus/interface/sbus_introspection.c \
    src/sbus/interface/sbus_iterator_readers.c \
    src/sbus/interface/sbus_iterator_writers.c \
    src/sbus/interface/sbus_properties.c \
    src/sbus/interface/sbus_properties_parser.c \
    src/sbus/interface/sbus_std_signals.c \
    src/sbus/request/sbus_message.c \
    src/sbus/request/sbus_request.c \
    src/sbus/request/sbus_request_call.c \
    src/sbus/request/sbus_request_hash.c \
    src/sbus/request/sbus_request_sender.c \
    src/sbus/request/sbus_request_util.c \
    src/sbus/router/sbus_router.c \
    src/sbus/router/sbus_router_handler.c \
    src/sbus/router/sbus_router_hash.c \
    src/sbus/server/sbus_server_handler.c \
    src/sbus/server/sbus_server_interface.c \
    src/sbus/server/sbus_server_match.c \
    src/sbus/server/sbus_server.c \
    $(NULL)
libsss_sbus_la_LIBADD = \
    $(DHASH_LIBS) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(DBUS_LIBS) \
    $(UNICODE_LIBS) \
    $(NULL)
libsss_sbus_la_CFLAGS = \
    $(AM_CFLAGS) \
	$(DHASH_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(TEVENT_CFLAGS) \
    $(DBUS_CFLAGS) \
    $(NULL)
libsss_sbus_la_LDFLAGS = \
    -avoid-version \
    $(NULL)

pkglib_LTLIBRARIES += libsss_sbus_sync.la
libsss_sbus_sync_la_SOURCES = \
    src/util/debug.c \
    src/util/debug_backtrace.c \
    src/util/sss_utf8.c \
    src/util/util.c \
    src/util/util_errors.c \
    src/util/strtonum.c \
    src/sbus/sbus_errors.c \
    src/sbus/sbus_opath.c \
    src/sbus/connection/sbus_dbus.c \
    src/sbus/interface_dbus/sbus_dbus_arguments.c \
    src/sbus/interface_dbus/sbus_dbus_client_sync.c \
    src/sbus/interface_dbus/sbus_dbus_keygens.c \
    src/sbus/interface_dbus/sbus_dbus_symbols.c \
    src/sbus/interface/sbus_iterator_readers.c \
    src/sbus/interface/sbus_iterator_writers.c \
    src/sbus/interface/sbus_properties_parser.c \
    src/sbus/request/sbus_message.c \
    src/sbus/sync/sbus_sync.c \
    src/sbus/sync/sbus_sync_call.c \
    $(NULL)
libsss_sbus_sync_la_LIBADD = \
    $(TALLOC_LIBS) \
    $(DBUS_LIBS) \
    $(NULL)
libsss_sbus_sync_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(DBUS_CFLAGS) \
    $(UNICODE_LIBS) \
    $(NULL)
libsss_sbus_sync_la_LDFLAGS = \
    -avoid-version \
    $(NULL)

pkglib_LTLIBRARIES += libsss_iface.la
libsss_iface_la_SOURCES = \
    src/sss_iface/sbus_sss_arguments.c \
    src/sss_iface/sbus_sss_client_async.c \
    src/sss_iface/sbus_sss_invokers.c \
    src/sss_iface/sbus_sss_keygens.c \
    src/sss_iface/sbus_sss_symbols.c \
    src/sss_iface/sss_iface_types.c \
    src/sss_iface/sss_iface.c \
    src/util/domain_info_utils.c \
    src/util/sss_pam_data.c \
    $(NULL)
libsss_iface_la_LIBADD = \
    $(DHASH_LIBS) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(DBUS_LIBS) \
    libsss_sbus.la \
    $(NULL)
libsss_iface_la_CFLAGS = \
    $(AM_CFLAGS) \
	$(DHASH_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(TEVENT_CFLAGS) \
    $(DBUS_CFLAGS) \
    $(NULL)
libsss_iface_la_LDFLAGS = \
    -avoid-version \
    $(NULL)

pkglib_LTLIBRARIES += libsss_iface_sync.la
libsss_iface_sync_la_SOURCES = \
    src/sss_iface/sbus_sss_arguments.c \
    src/sss_iface/sbus_sss_client_sync.c \
    src/sss_iface/sbus_sss_keygens.c \
    src/sss_iface/sbus_sss_symbols.c \
    src/sss_iface/sss_iface_types.c \
    src/util/domain_info_utils.c \
    src/util/sss_pam_data.c \
    $(NULL)
libsss_iface_sync_la_LIBADD = \
    $(DHASH_LIBS) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(DBUS_LIBS) \
    libsss_sbus_sync.la \
    $(NULL)
libsss_iface_sync_la_CFLAGS = \
    $(AM_CFLAGS) \
	$(DHASH_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(TEVENT_CFLAGS) \
    $(DBUS_CFLAGS) \
    $(NULL)
libsss_iface_sync_la_LDFLAGS = \
    -avoid-version \
    $(NULL)

pkglib_LTLIBRARIES += libsss_util.la
libsss_util_la_SOURCES = \
    src/sbus/sbus_opath.c \
    src/confdb/confdb.c \
    src/db/sysdb.c \
    src/db/sysdb_ops.c \
    src/db/sysdb_search.c \
    src/db/sysdb_selinux.c \
    src/db/sysdb_upgrade.c \
    src/db/sysdb_init.c \
    src/db/sysdb_services.c \
    src/db/sysdb_autofs.c \
    src/db/sysdb_subdomains.c \
    src/db/sysdb_views.c \
    src/db/sysdb_ranges.c \
    src/db/sysdb_idmap.c \
    src/db/sysdb_gpo.c \
    src/db/sysdb_certmap.c \
    src/db/sysdb_domain_resolution_order.c \
    src/db/sysdb_iphosts.c \
    src/db/sysdb_ipnetworks.c \
    src/util/sss_pam_data.c \
    src/db/sysdb_subid.c \
    src/util/util.c \
    src/util/util_ext.c \
    src/util/util_preauth.c \
    src/util/memory.c \
    src/util/memory_erase.c \
    src/util/safe-format-string.c \
    src/util/server.c \
    src/util/signal.c \
    src/util/usertools.c \
    src/util/backup_file.c \
    src/util/strtonum.c \
    src/util/check_file.c \
    src/util/refcount.c \
    src/util/sss_nss.c \
    src/util/sss_utf8.c \
    src/util/sss_tc_utf8.c \
    src/util/murmurhash3.c \
    src/util/atomic_io.c \
    src/util/authtok.c \
    src/util/authtok-utils.c \
    src/util/domain_info_utils.c \
    src/util/util_lock.c \
    src/util/util_errors.c \
    src/util/inotify.c \
    src/util/file_watch.c \
    src/util/find_uid.c \
    src/util/sss_ini.c \
    src/util/io.c \
    src/util/util_sss_idmap.c \
    src/util/well_known_sids.c \
    src/util/string_utils.c \
    src/util/capabilities.c \
    src/util/util_watchdog.c \
    src/util/sss_ptr_hash.c \
    src/util/files.c \
    src/util/selinux.c \
    src/util/sss_regexp.c \
    src/util/sss_chain_id_tevent.c \
    src/util/sss_chain_id.c \
    src/util/sss_time.c \
    src/util/sss_prctl.c \
    $(NULL)
libsss_util_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
libsss_util_la_LIBADD = \
    $(LIBADD_TIMER) \
    $(SSSD_LIBS) \
    $(CAP_LIBS) \
    $(UNICODE_LIBS) \
    $(PCRE_LIBS) \
    $(INI_CONFIG_LIBS) \
    libsss_debug.la \
    libsss_child.la \
    libsss_crypt.la \
    libsss_cert.la \
    $(NULL)
if BUILD_SUDO
    libsss_util_la_SOURCES += src/db/sysdb_sudo.c
endif
if BUILD_SSH
libsss_util_la_SOURCES += \
    src/db/sysdb_ssh.c \
    src/util/sss_ssh.c
endif
if BUILD_SYSTEMTAP
libsss_util_la_LIBADD += stap_generated_probes.lo
endif
if BUILD_PASSKEY
libsss_util_la_SOURCES += src/db/sysdb_passkey_user_verification.c
endif # BUILD_PASSKEY
libsss_util_la_LDFLAGS = -avoid-version

SSSD_INTERNAL_LTLIBS = \
    libsss_util.la \
    libsss_crypt.la \
    libsss_debug.la \
    libsss_child.la \
    $(NULL)

lib_LTLIBRARIES = libipa_hbac.la \
                  libsss_idmap.la \
                  libsss_nss_idmap.la \
                  libsss_certmap.la \
                  $(NULL)

pkgconfig_DATA += src/lib/ipa_hbac/ipa_hbac.pc
libipa_hbac_la_DEPENDENCIES = src/lib/ipa_hbac/ipa_hbac.exports
libipa_hbac_la_SOURCES = \
    src/lib/ipa_hbac/hbac_evaluator.c \
    src/util/sss_utf8.c
# libipa_hbac is also used by external projects such as pam_hbac which
# support platforms that do not have a C99 compiler. We add -std=c89
# explicitly here to make sure we don't accidentally add a C99 feature
# to the libipa_hbac code
libipa_hbac_la_CFLAGS = \
    $(AM_CFLAGS) \
    -I$(top_srcdir)/src/util \
    -std=c89 \
    $(NULL)
libipa_hbac_la_LIBADD = \
    $(UNICODE_LIBS)
libipa_hbac_la_LDFLAGS = \
    -Wl,--version-script,$(srcdir)/src/lib/ipa_hbac/ipa_hbac.exports \
    -version-info 1:0:1

dist_noinst_DATA += src/lib/ipa_hbac/ipa_hbac.exports

pkgconfig_DATA += src/lib/idmap/sss_idmap.pc
libsss_idmap_la_DEPENDENCIES = src/lib/idmap/sss_idmap.exports
libsss_idmap_la_SOURCES = \
    src/lib/idmap/sss_idmap.c \
    src/lib/idmap/sss_idmap_conv.c \
    src/util/murmurhash3.c
libsss_idmap_la_CFLAGS = \
    $(UTF8PROC_CFLAGS) \
    $(NULL)
libsss_idmap_la_LIBADD = \
    $(UTF8PROC_LIBS) \
    $(NULL)
libsss_idmap_la_LDFLAGS = \
    -Wl,--version-script,$(srcdir)/src/lib/idmap/sss_idmap.exports \
    -version-info 6:0:6

dist_noinst_DATA += src/lib/idmap/sss_idmap.exports

pkgconfig_DATA += src/sss_client/idmap/sss_nss_idmap.pc
libsss_nss_idmap_la_DEPENDENCIES = src/sss_client/idmap/sss_nss_idmap.exports
libsss_nss_idmap_la_SOURCES = \
    src/sss_client/idmap/sss_nss_idmap.c \
    src/sss_client/idmap/sss_nss_ex.c \
    src/sss_client/idmap/sss_nss_idmap_private.h \
    src/sss_client/common.c \
    src/sss_client/idmap/common_ex.c \
    src/sss_client/nss_mc_passwd.c \
    src/sss_client/nss_mc_sid.c \
    src/sss_client/nss_passwd.c \
    src/sss_client/nss_mc_group.c \
    src/sss_client/nss_group.c \
    src/sss_client/nss_mc_initgr.c \
    src/sss_client/nss_mc_common.c \
    src/util/strtonum.c \
    src/util/murmurhash3.c \
    src/util/io.c \
    $(NULL)
libsss_nss_idmap_la_LIBADD = \
    $(LIBCLOCK_GETTIME) \
    $(CLIENT_LIBS) \
    -lpthread \
    $(NULL)
libsss_nss_idmap_la_LDFLAGS = \
    -Wl,--version-script,$(srcdir)/src/sss_client/idmap/sss_nss_idmap.exports \
    -version-info 6:0:6

dist_noinst_DATA += src/sss_client/idmap/sss_nss_idmap.exports

include_HEADERS = \
    src/lib/ipa_hbac/ipa_hbac.h \
    src/lib/idmap/sss_idmap.h \
    src/sss_client/idmap/sss_nss_idmap.h \
    src/lib/certmap/sss_certmap.h \
    $(NULL)

#########################
# Systemtap tracing     #
#########################

if BUILD_SYSTEMTAP
SYSTEMTAP_PROBES = \
    $(srcdir)/src/systemtap/sssd_probes.d \
    $(NULL)

systemtap_tap_DATA = $(builddir)/src/systemtap/sssd.stp

dist_systemtap_tap_DATA = \
    $(builddir)/src/systemtap/sssd_functions.stp \
    $(NULL)

dist_sssdtapscript_DATA = \
    contrib/systemtap/id_perf.stp \
    contrib/systemtap/nested_group_perf.stp \
    contrib/systemtap/dp_request.stp \
    contrib/systemtap/ldap_perf.stp \
    $(NULL)

stap_generated_probes.h: $(srcdir)/src/systemtap/sssd_probes.d
	$(AM_V_GEN)$(DTRACE) -C -h -s $< -o $@

stap_generated_probes.o: $(srcdir)/src/systemtap/sssd_probes.d stap_generated_probes.h
	$(AM_V_GEN)$(DTRACE) -C -G -s $< -o $@

stap_generated_probes.lo: stap_generated_probes.o
	$(AM_V_GEN)printf %s\\n \
	'# $@ - a libtool object file' \
	'# Generated by libtool (GNU libtool) 2.4' \
	'# Actually generated by Makefile.am, in order to shut up libtool' \
	"pic_object='$<'" \
	"non_pic_object='$<'" \
	> $@

BUILT_SOURCES += stap_generated_probes.h

CLEANFILES += stap_generated_probes.h \
	      stap_generated_probes.o \
	      stap_generated_probes.lo \
	      $(NULL)
endif

####################
# Program Binaries #
####################
sssd_SOURCES = \
    src/monitor/monitor.c \
    src/monitor/monitor_bootstrap.c \
    src/confdb/confdb_setup.c \
    $(NULL)

sssd_LDADD = \
    $(SSSD_LIBS) \
    $(INOTIFY_LIBS) \
    $(KEYUTILS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

sssd_nss_SOURCES = \
    src/responder/nss/nsssrv.c \
    src/responder/nss/nss_cmd.c \
    src/responder/nss/nss_enum.c \
    src/responder/nss/nss_get_object.c \
    src/responder/nss/nss_protocol.c \
    src/responder/nss/nss_protocol_pwent.c \
    src/responder/nss/nss_protocol_grent.c \
    src/responder/nss/nss_protocol_netgr.c \
    src/responder/nss/nss_protocol_svcent.c \
    src/responder/nss/nss_protocol_hostent.c \
    src/responder/nss/nss_protocol_netent.c \
    src/responder/nss/nss_protocol_sid.c \
    src/responder/nss/nss_utils.c \
    src/responder/nss/nss_iface.c \
    src/responder/nss/nsssrv_mmap_cache.c \
    $(SSSD_RESPONDER_OBJ)
sssd_nss_LDADD = \
    $(LIBADD_DL) \
    $(TDB_LIBS) \
    $(SSSD_LIBS) \
    libsss_idmap.la \
    libsss_cert.la \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)
if BUILD_SUBID
    sssd_nss_SOURCES += src/responder/nss/nss_protocol_subid.c
endif

sssd_pam_SOURCES = \
    src/responder/pam/pamsrv.c \
    src/responder/pam/pamsrv_cmd.c \
    src/responder/pam/pamsrv_p11.c \
    src/responder/pam/pamsrv_dp.c \
    src/responder/pam/pamsrv_gssapi.c \
    src/responder/pam/pam_prompting_config.c \
    src/sss_client/pam_sss_prompt_config.c \
    src/responder/pam/pam_helpers.c \
    $(SSSD_RESPONDER_OBJ)
if BUILD_PASSKEY
    sssd_pam_SOURCES += src/responder/pam/pamsrv_passkey.c
endif
sssd_pam_CFLAGS = \
    $(AM_CFLAGS) \
    $(GSSAPI_KRB5_CFLAGS) \
    $(NULL)
sssd_pam_LDADD = \
    $(LIBADD_DL) \
    $(TDB_LIBS) \
    $(SSSD_LIBS) \
    $(SELINUX_LIBS) \
    $(PAM_LIBS) \
    $(GSSAPI_KRB5_LIBS) \
    libsss_certmap.la \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

if BUILD_SUDO
sssd_sudo_SOURCES = \
    src/responder/sudo/sudosrv.c \
    src/responder/sudo/sudosrv_cmd.c \
    src/responder/sudo/sudosrv_get_sudorules.c \
    src/responder/sudo/sudosrv_query.c \
    src/responder/sudo/sudosrv_dp.c \
    $(SSSD_RESPONDER_OBJ)
sssd_sudo_LDADD = \
    $(LIBADD_DL) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)
endif

if BUILD_AUTOFS
sssd_autofs_SOURCES = \
    src/responder/autofs/autofssrv.c \
    src/responder/autofs/autofssrv_cmd.c \
    $(SSSD_RESPONDER_OBJ)
sssd_autofs_LDADD = \
    $(LIBADD_DL) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)
endif

if BUILD_SSH
sssd_ssh_SOURCES = \
    src/responder/ssh/sshsrv.c \
    src/responder/ssh/ssh_cmd.c \
    src/responder/ssh/ssh_protocol.c \
    src/responder/ssh/ssh_reply.c \
    src/responder/ssh/ssh_cert_to_ssh_key.c \
    $(SSSD_RESPONDER_OBJ) \
    $(NULL)

sssd_ssh_LDADD = \
    $(LIBADD_DL) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_cert.la \
    libsss_certmap.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)
endif

sssd_pac_SOURCES = \
    src/responder/pac/pacsrv.c \
    src/responder/pac/pacsrv_cmd.c \
    src/providers/ad/ad_pac_common.c \
    src/util/pac_utils.c \
    $(SSSD_RESPONDER_OBJ)
sssd_pac_CFLAGS = \
    $(AM_CFLAGS) \
    $(NDR_KRB5PAC_CFLAGS)
sssd_pac_LDADD = \
    $(LIBADD_DL) \
    $(NDR_KRB5PAC_LIBS) \
    $(TDB_LIBS) \
    $(SSSD_LIBS) \
    libsss_idmap.la \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

pkglib_LTLIBRARIES += libifp_iface.la
libifp_iface_la_SOURCES = \
    src/responder/ifp/ifp_iface/sbus_ifp_arguments.c \
    src/responder/ifp/ifp_iface/sbus_ifp_client_async.c \
    src/responder/ifp/ifp_iface/sbus_ifp_invokers.c \
    src/responder/ifp/ifp_iface/sbus_ifp_keygens.c \
    src/responder/ifp/ifp_iface/sbus_ifp_symbols.c \
    src/responder/ifp/ifp_iface/ifp_iface_types.c \
    src/responder/ifp/ifp_iface/ifp_iface.c \
    $(NULL)
libifp_iface_la_LIBADD = \
    $(DHASH_LIBS) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(DBUS_LIBS) \
    libsss_sbus.la \
    $(NULL)
libifp_iface_la_CFLAGS = \
    $(AM_CFLAGS) \
	$(DHASH_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(TEVENT_CFLAGS) \
    $(DBUS_CFLAGS) \
    $(NULL)
libifp_iface_la_LDFLAGS = \
    -avoid-version \
    $(NULL)

pkglib_LTLIBRARIES += libifp_iface_sync.la
libifp_iface_sync_la_SOURCES = \
    src/responder/ifp/ifp_iface/sbus_ifp_arguments.c \
    src/responder/ifp/ifp_iface/sbus_ifp_client_sync.c \
    src/responder/ifp/ifp_iface/sbus_ifp_keygens.c \
    src/responder/ifp/ifp_iface/sbus_ifp_symbols.c \
    src/responder/ifp/ifp_iface/ifp_iface_types.c \
    $(NULL)
libifp_iface_sync_la_LIBADD = \
    $(DHASH_LIBS) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(DBUS_LIBS) \
    libsss_sbus_sync.la \
    $(NULL)
libifp_iface_sync_la_CFLAGS = \
    $(AM_CFLAGS) \
	$(DHASH_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(TEVENT_CFLAGS) \
    $(DBUS_CFLAGS) \
    $(NULL)
libifp_iface_sync_la_LDFLAGS = \
    -avoid-version \
    $(NULL)

sssd_ifp_SOURCES = \
    src/responder/ifp/ifpsrv.c \
    src/responder/ifp/ifpsrv_cmd.c \
    src/responder/ifp/ifp_iface_nodes.c \
    src/responder/ifp/ifpsrv_util.c \
    src/responder/ifp/ifp_domains.c \
    src/responder/ifp/ifp_components.c \
    src/responder/ifp/ifp_users.c \
    src/responder/ifp/ifp_groups.c \
    src/responder/ifp/ifp_cache.c \
    $(SSSD_RESPONDER_OBJ)
sssd_ifp_CFLAGS = \
    $(AM_CFLAGS)
sssd_ifp_LDADD = \
    $(LIBADD_DL) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_cert.la \
    libifp_iface.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

dist_dbuspolicy_DATA = \
    src/responder/ifp/org.freedesktop.sssd.infopipe.conf
dist_dbusservice_DATA = \
    src/responder/ifp/org.freedesktop.sssd.infopipe.service

EXTRA_DIST += \
    src/responder/ifp/org.freedesktop.sssd.infopipe.service.in \
    src/responder/ifp/org.freedesktop.sssd.infopipe.conf.in \
    $(NULL)

ifp_edit_cmd = $(edit_cmd) \
        -e 's|@ifp_non_root_owner_policy[@]|$(ifp_non_root_owner_policy)|g' \
        -e 's|@ifp_dbus_exec_cmd[@]|$(ifp_dbus_exec_cmd)|g' \
        -e 's|@ifp_dbus_exec_comment[@]|$(ifp_dbus_exec_comment)|g' \
        -e 's|@ifp_systemdservice[@]|$(ifp_systemdservice)|g'

ifp_replace_script = \
    @rm -f $@ $@.tmp; \
    srcdir=''; \
        test -f ./$@.in || srcdir=$(srcdir)/; \
        $(ifp_edit_cmd) $${srcdir}$@.in >$@.tmp; \
    mv $@.tmp $@

src/responder/ifp/org.freedesktop.sssd.infopipe.service: src/responder/ifp/org.freedesktop.sssd.infopipe.service.in Makefile
	$(ifp_replace_script)

src/responder/ifp/org.freedesktop.sssd.infopipe.conf: src/responder/ifp/org.freedesktop.sssd.infopipe.conf.in Makefile
	$(ifp_replace_script)


if BUILD_KCM
sssd_kcm_SOURCES = \
    src/responder/kcm/kcm.c \
    src/responder/kcm/kcmsrv_cmd.c \
    src/responder/kcm/kcmsrv_ccache.c \
    src/responder/kcm/kcmsrv_ccache_binary.c \
    src/responder/kcm/kcmsrv_ccache_mem.c \
    src/responder/kcm/kcmsrv_ccache_key.c \
    src/responder/kcm/kcmsrv_ccache_secdb.c \
    src/responder/kcm/kcmsrv_ops.c \
    src/responder/kcm/kcmsrv_op_queue.c \
    src/responder/kcm/secrets/secrets.c \
    src/responder/kcm/secrets/config.c \
    src/util/sss_sockets.c \
    src/util/sss_krb5.c \
    src/util/sss_iobuf.c \
    src/confdb/confdb_setup.c \
    $(SSSD_RESPONDER_OBJ) \
    $(NULL)
sssd_kcm_CFLAGS = \
    $(AM_CFLAGS) \
    $(KRB5_CFLAGS) \
    $(UUID_CFLAGS) \
    $(CURL_CFLAGS) \
    $(NULL)
sssd_kcm_LDADD = \
    $(LIBADD_DL) \
    $(KRB5_LIBS) \
    $(SSSD_LIBS) \
    $(UUID_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

if BUILD_KCM_RENEWAL
sssd_kcm_SOURCES += \
    src/responder/kcm/kcm_renew.c \
    src/providers/krb5/krb5_opts.c \
    src/providers/krb5/krb5_child_handler.c \
    src/providers/data_provider_opts.c \
    $(NULL)
endif

endif

sssd_be_SOURCES = \
    src/providers/data_provider_be.c \
    src/providers/data_provider_req.c \
    src/providers/data_provider_fo.c \
    src/providers/data_provider_opts.c \
    src/providers/data_provider_callbacks.c \
    src/providers/be_dyndns.c \
    src/providers/be_netlink.c \
    src/providers/be_ptask.c \
    src/providers/be_refresh.c \
    src/providers/data_provider/dp.c \
    src/providers/data_provider/dp_modules.c \
    src/providers/data_provider/dp_targets.c \
    src/providers/data_provider/dp_methods.c \
    src/providers/data_provider/dp_builtin.c \
    src/providers/data_provider/dp_iface_backend.c \
    src/providers/data_provider/dp_iface_failover.c \
    src/providers/data_provider/dp_resp_client.c \
    src/providers/data_provider/dp_request.c \
    src/providers/data_provider/dp_reply_std.c \
    src/providers/data_provider/dp_target_sudo.c \
    src/providers/data_provider/dp_target_hostid.c \
    src/providers/data_provider/dp_target_autofs.c \
    src/providers/data_provider/dp_target_subdomains.c \
    src/providers/data_provider/dp_target_id.c \
    src/providers/data_provider/dp_target_auth.c \
    src/providers/data_provider/dp_target_resolver.c \
    src/util/session_recording.c \
    $(SSSD_FAILOVER_OBJ)
sssd_be_LDADD = \
    $(LIBADD_DL) \
    $(SSSD_LIBS) \
    $(CARES_LIBS) \
    $(PAM_LIBS) \
    $(LIBNL_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)
sssd_be_LDFLAGS = \
    -Wl,--version-script,$(srcdir)/src/providers/sssd_be.exports \
    -export-dynamic
if BUILD_SYSTEMTAP
sssd_be_LDADD += stap_generated_probes.lo
endif

if BUILD_PYTHON_BINDINGS
sss_obfuscate_pythondir = $(sbindir)
dist_sss_obfuscate_python_SCRIPTS = \
    src/tools/sss_obfuscate
endif



dist_noinst_DATA += \
    src/examples/sssd-example.conf \
    src/examples/sssdproxytest \
    src/examples/sudo \
    src/examples/logrotate \
    src/providers/sssd_be.exports \
    src/sss_client/COPYING \
    src/sss_client/COPYING.LESSER \
    src/m4

dist_sssddefaultconf_DATA = \
    src/examples/sssd.conf

dist_pamconf_DATA = \
    src/examples/sssd-shadowutils

######################
# Command-line Tools #
######################
sss_cache_SOURCES = \
    src/tools/sss_cache.c \
    $(SSSD_LCL_TOOLS_OBJ)
sss_cache_LDADD = \
    $(TOOLS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(CLIENT_LIBS)
sss_cache_CFLAGS = $(AM_CFLAGS)

sss_seed_SOURCES = \
    src/tools/sss_seed.c \
    $(SSSD_TOOLS_OBJ)
sss_seed_LDADD = \
    $(TOOLS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)

sss_signal_SOURCES = \
    src/tools/sss_signal.c \
    src/tools/common/sss_process.c
    $(NULL)
sss_signal_LDADD = \
    libsss_debug.la \
    $(NULL)

sss_override_SOURCES = \
    src/tools/sss_override.c \
    src/tools/common/sss_colondb.c \
    $(SSSD_TOOLS_OBJ) \
    $(NULL)
sss_override_LDADD = \
    $(TOOLS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(NULL)
sss_override_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)

sssctl_SOURCES = \
    src/tools/sssctl/sssctl.c \
    src/tools/sssctl/sssctl_systemd.c \
    src/tools/sssctl/sssctl_cache.c \
    src/tools/sssctl/sssctl_data.c \
    src/tools/sssctl/sssctl_logs.c \
    src/tools/sssctl/sssctl_domains.c \
    src/tools/sssctl/sssctl_config.c \
    src/tools/sssctl/sssctl_user_checks.c \
    src/tools/sssctl/sssctl_access_report.c \
    src/tools/sssctl/sssctl_cert.c \
    $(SSSD_TOOLS_OBJ) \
    $(NULL)
if BUILD_PASSKEY
    sssctl_SOURCES += src/tools/sssctl/sssctl_passkey.c
endif
sssctl_LDADD = \
    $(TOOLS_LIBS) \
    $(INI_CONFIG_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(PAM_LIBS) \
    $(PAM_MISC_LIBS) \
    $(LIBADD_DL) \
    libsss_certmap.la \
    libifp_iface_sync.la \
    libsss_iface.la \
    libsss_iface_sync.la \
    libsss_sbus_sync.la \
    $(NULL)
sssctl_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)

if BUILD_SUDO
sss_sudo_cli_SOURCES = \
    src/sss_client/common.c \
    src/sss_client/sudo/sss_sudo.c \
    src/sss_client/sudo/sss_sudo_response.c \
    src/sss_client/sudo_testcli/sudo_testcli.c
sss_sudo_cli_CFLAGS = $(AM_CFLAGS)
sss_sudo_cli_LDADD = $(CLIENT_LIBS)
endif

if BUILD_SSH
sss_ssh_authorizedkeys_SOURCES = \
    src/sss_client/common.c \
    src/sss_client/ssh/sss_ssh_client.c \
    src/sss_client/ssh/sss_ssh_authorizedkeys.c
sss_ssh_authorizedkeys_CFLAGS = $(AM_CFLAGS)
sss_ssh_authorizedkeys_LDADD = \
    $(SSSD_INTERNAL_LTLIBS) \
    $(CLIENT_LIBS) $(TALLOC_LIBS) $(POPT_LIBS)

sss_ssh_knownhosts_SOURCES = \
    src/sss_client/common.c \
    src/sss_client/ssh/sss_ssh_client.c \
    src/sss_client/ssh/sss_ssh_knownhosts.c
sss_ssh_knownhosts_CFLAGS = $(AM_CFLAGS)
sss_ssh_knownhosts_LDADD = \
    $(SSSD_INTERNAL_LTLIBS) \
    $(CLIENT_LIBS) $(TALLOC_LIBS) $(POPT_LIBS)

sss_ssh_knownhostsproxy_SOURCES = \
    src/sss_client/common.c \
    src/sss_client/ssh/sss_ssh_client.c \
    src/sss_client/ssh/sss_ssh_knownhostsproxy.c
sss_ssh_knownhostsproxy_CFLAGS = $(AM_CFLAGS)
sss_ssh_knownhostsproxy_LDADD = \
    $(SSSD_INTERNAL_LTLIBS) \
    $(CLIENT_LIBS) $(TALLOC_LIBS) $(POPT_LIBS)
endif

if HAVE_SYSTEMD_UNIT
sssd_check_socket_activated_responders_SOURCES = \
    src/tools/sssd_check_socket_activated_responders.c \
    src/tools/common/sss_tools.c \
    $(NULL)
sssd_check_socket_activated_responders_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
sssd_check_socket_activated_responders_LDADD = \
    $(SSSD_INTERNAL_LTLIBS) \
    $(LTLIBINTL) \
    $(TALLOC_LIBS) \
    $(POPT_LIBS) \
    $(INI_CONFIG_LIBS) \
    $(NULL)
endif

pkgconfig_DATA += src/lib/certmap/sss_certmap.pc
libsss_certmap_la_DEPENDENCIES = src/lib/certmap/sss_certmap.exports
libsss_certmap_la_SOURCES = \
    src/lib/certmap/sss_certmap.c \
    src/lib/certmap/sss_certmap_attr_names.c \
    src/lib/certmap/sss_certmap_krb5_match.c \
    src/lib/certmap/sss_certmap_ldap_mapping.c \
    src/lib/certmap/sss_cert_content_common.c \
    src/util/util_ext.c \
    src/util/strtonum.c \
    src/util/cert/cert_common.c \
    $(NULL)
libsss_certmap_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(NULL)
libsss_certmap_la_LIBADD = \
    $(TALLOC_LIBS) \
    $(NULL)
libsss_certmap_la_LDFLAGS = \
    -Wl,--version-script,$(srcdir)/src/lib/certmap/sss_certmap.exports \
    -version-info 2:0:2

libsss_certmap_la_SOURCES += \
    src/lib/certmap/sss_cert_content_crypto.c \
    src/lib/certmap/sss_cert_digest_crypto.c \
    src/util/crypto/libcrypto/crypto_base64.c \
    src/util/cert/libcrypto/cert.c \
    $(NULL)
libsss_certmap_la_CFLAGS += $(CRYPTO_CFLAGS)
libsss_certmap_la_LIBADD += $(CRYPTO_LIBS)

dist_noinst_DATA += src/lib/certmap/sss_certmap.exports
dist_noinst_HEADERS += src/lib/certmap/sss_certmap_int.h

#################
# Feature Tests #
#################
TESTS_ENVIRONMENT = LDB_MODULES_PATH=$(abs_top_builddir)/ldb_mod_test_dir \
                    SSS_TEST_DIR=$(TEST_DIR) \
                    ABS_TOP_SRCDIR=$(abs_top_srcdir) \
                    $(AUX_TESTS_ENVIRONMENT)

if VALGRIND_ENABLED
@VALGRIND_CHECK_RULES@
VALGRIND_SUPPRESSIONS_FILES = $(abs_top_srcdir)/contrib/ci/sssd.supp
endif

ldb_mod_test_dir: memberof.la
	$(MKDIR_P) $(builddir)/ldb_mod_test_dir
	cp $(builddir)/.libs/memberof.so $(builddir)/ldb_mod_test_dir

check_LTLIBRARIES = \
    libsss_test_common.la

libsss_test_common_la_SOURCES = \
    src/tests/common_tev.c \
    src/tests/common_dom.c \
    src/tests/leak_check.c \
    src/tests/common.c
libsss_test_common_la_LIBADD = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(LDB_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(NULL)
if BUILD_SYSTEMTAP
libsss_test_common_la_LIBADD += stap_generated_probes.lo
endif

if HAVE_CHECK
libsss_test_common_la_SOURCES += \
    src/tests/common_check.c

check_LTLIBRARIES += \
    libdlopen_test_providers.la \
    $(NULL)

if BUILD_SAMBA
check_LTLIBRARIES += \
    libsss_ad_tests.la \
    libdlopen_test_winbind_idmap.la \
    $(NULL)
endif

# libdlopen_test_providers is a helper library to provide missing symbols for
# dlopen_tests.
libdlopen_test_providers_la_SOURCES = \
    $(sssd_be_SOURCES) \
    $(NULL)
libdlopen_test_providers_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS) \
    -DUNIT_TESTING
libdlopen_test_providers_la_LIBADD = \
    $(LIBADD_DL) \
    $(PAM_LIBS) \
    $(SSSD_LIBS) \
    $(CARES_LIBS) \
    $(LIBNL_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)
if BUILD_SYSTEMTAP
libdlopen_test_providers_la_LIBADD += stap_generated_probes.lo
endif
libdlopen_test_providers_la_LDFLAGS = \
    -shared \
    -avoid-version \
    -Wl,--version-script,$(srcdir)/src/providers/sssd_be.exports \
    -rpath $(abs_top_builddir) \
    -export-dynamic

libsss_ad_tests_la_SOURCES = $(libsss_ad_la_SOURCES)
libsss_ad_tests_la_CFLAGS = $(libsss_ad_la_CFLAGS)
libsss_ad_tests_la_LIBADD = \
    $(libsss_ad_la_LIBADD) \
    libdlopen_test_providers.la \
    $(NULL)
libsss_ad_tests_la_LDFLAGS = \
    -shared \
    -rpath $(abs_top_builddir) \
    $(NULL)

dlopen_tests_SOURCES = \
    src/tests/dlopen-tests.c
dlopen_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
dlopen_tests_LDADD = \
    $(LIBADD_DL) \
    $(CHECK_LIBS)

EXTRA_sysdb_tests_DEPENDENCIES = \
    $(ldblib_LTLIBRARIES)
sysdb_tests_SOURCES = \
    src/tests/sysdb-tests.c
sysdb_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
sysdb_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

EXTRA_sysdb_ssh_tests_DEPENDENCIES = \
    $(ldblib_LTLIBRARIES)
sysdb_ssh_tests_SOURCES = \
    src/tests/sysdb_ssh-tests.c
sysdb_ssh_tests_CFLAGS = \
    $(AM_CFLAGS)\
    $(CHECK_CFLAGS)
sysdb_ssh_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

strtonum_tests_SOURCES = \
    src/tests/strtonum-tests.c \
    src/util/strtonum.c
strtonum_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
strtonum_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    libsss_debug.la \
    libsss_test_common.la

krb5_utils_tests_SOURCES = \
    src/tests/krb5_utils-tests.c \
    src/providers/krb5/krb5_utils.c \
    src/providers/krb5/krb5_ccache.c \
    src/providers/krb5/krb5_common.c \
    src/providers/krb5/krb5_opts.c \
    src/util/sss_krb5.c \
    src/util/sss_iobuf.c \
    src/providers/data_provider_fo.c \
    src/providers/data_provider_opts.c \
    src/providers/data_provider_callbacks.c \
    $(SSSD_FAILOVER_OBJ) \
    $(NULL)
krb5_utils_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(KRB5_CFLAGS) \
    $(CHECK_CFLAGS)
krb5_utils_tests_LDADD = \
    $(SSSD_LIBS)\
    $(CARES_LIBS) \
    $(KRB5_LIBS) \
    $(CHECK_LIBS) \
    $(PCRE_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la


check_file_tests_SOURCES = \
    src/tests/check_file-tests.c \
    src/util/check_file.c
check_file_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
check_file_tests_LDADD = \
    libsss_debug.la \
    $(CHECK_LIBS) \
    libsss_test_common.la

FILES_TESTS_LIBS = \
    $(CHECK_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    libsss_test_common.la
if BUILD_SELINUX
    FILES_TESTS_LIBS += $(SELINUX_LIBS)
endif
if BUILD_SELINUX
    FILES_TESTS_LIBS += $(SEMANAGE_LIBS)
endif

if HAVE_INOTIFY
files_tests_SOURCES = \
    src/tests/files-tests.c \
    src/util/check_file.c \
    src/util/atomic_io.c \
    src/util/selinux.c \
    src/util/files.c
files_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
files_tests_LDADD = \
    $(FILES_TESTS_LIBS) \
    libsss_test_common.la \
    $(SSSD_INTERNAL_LTLIBS)
endif   # HAVE_INOTIFY

SSSD_RESOLV_TESTS_OBJ = \
    $(SSSD_RESOLV_OBJ)

resolv_tests_SOURCES = \
    src/tests/resolv-tests.c \
    src/tests/common.c \
    $(SSSD_RESOLV_TESTS_OBJ)
resolv_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS) \
    -DBUILD_TXT
resolv_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(CARES_LIBS) \
    libsss_debug.la \
    libsss_test_common.la

file_watch_tests_SOURCES = \
    src/tests/file_watch-tests.c \
    $(NULL)
file_watch_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
file_watch_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(INOTIFY_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

refcount_tests_SOURCES = \
    src/tests/refcount-tests.c \
    $(NULL)
refcount_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
refcount_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

fail_over_tests_SOURCES = \
    src/tests/fail_over-tests.c \
    $(SSSD_FAILOVER_OBJ) \
    $(NULL)
fail_over_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
fail_over_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(CARES_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

find_uid_tests_SOURCES = \
    src/tests/find_uid-tests.c \
    src/util/find_uid.c \
    src/util/atomic_io.c \
    src/util/strtonum.c
find_uid_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(DHASH_CFLAGS) \
    $(CHECK_CFLAGS)
if HAVE_SYSTEMD_UNIT
    find_uid_tests_CFLAGS += $(SYSTEMD_LOGIN_CFLAGS)
endif

find_uid_tests_LDADD = \
    libsss_debug.la \
    $(TALLOC_LIBS) \
    $(DHASH_LIBS) \
    $(CHECK_LIBS) \
    libsss_test_common.la
if HAVE_SYSTEMD_UNIT
    find_uid_tests_LDADD += $(SYSTEMD_LOGIN_LIBS)
endif

auth_tests_SOURCES = \
    src/tests/auth-tests.c
auth_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
auth_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

ipa_ldap_opt_tests_SOURCES = \
    src/providers/data_provider_opts.c \
    src/providers/ldap/sdap.c \
    src/providers/ldap/sdap_range.c \
    src/providers/ldap/sdap_domain.c \
    src/providers/ldap/ldap_opts.c \
    src/providers/ad/ad_opts.c \
    src/providers/ipa/ipa_opts.c \
    src/providers/krb5/krb5_opts.c \
    src/util/sss_sockets.c \
    src/util/sss_ldap.c \
    src/tests/ipa_ldap_opt-tests.c
ipa_ldap_opt_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
ipa_ldap_opt_tests_LDADD = \
    $(CHECK_LIBS) \
    $(TALLOC_LIBS) \
    $(LDB_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(OPENLDAP_LIBS) \
    libsss_test_common.la \
    libsss_ldap_common.la \
    libdlopen_test_providers.la \
    $(NULL)

ad_ldap_opt_tests_SOURCES = \
    src/providers/ldap/ldap_opts.c \
    src/providers/ad/ad_opts.c \
    src/providers/krb5/krb5_opts.c \
    src/tests/ad_ldap_opt-tests.c
ad_ldap_opt_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
ad_ldap_opt_tests_LDADD = \
    $(CHECK_LIBS) \
    $(TALLOC_LIBS) \
    libsss_test_common.la

util_tests_SOURCES = \
    src/tests/util-tests.c \
    $(NULL)
util_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS) \
    $(NULL)
util_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

safe_format_tests_SOURCES = \
    src/tests/safe-format-tests.c
safe_format_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
safe_format_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

debug_tests_SOURCES = \
    src/tests/debug-tests.c \
    src/tests/common.c
debug_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
debug_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    libsss_debug.la

crypto_tests_SOURCES = \
    src/tests/crypto-tests.c
crypto_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
crypto_tests_LDADD = \
    $(CHECK_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    libsss_crypt.la \
    libsss_debug.la \
    libsss_test_common.la

ipa_hbac_tests_SOURCES = \
    src/tests/ipa_hbac-tests.c
ipa_hbac_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
ipa_hbac_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    libsss_test_common.la \
    libipa_hbac.la

sss_idmap_tests_SOURCES = \
    src/tests/sss_idmap-tests.c
sss_idmap_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
sss_idmap_tests_LDADD = \
    $(CHECK_LIBS) \
    $(TALLOC_LIBS) \
    libsss_test_common.la \
    libsss_idmap.la

responder_socket_access_tests_SOURCES = \
    src/tests/responder_socket_access-tests.c \
    src/responder/common/negcache.c \
    src/util/nss_dl_load.c \
    src/responder/common/responder_common.c \
    src/responder/common/responder_packet.c \
    src/responder/common/responder_cmd.c \
    src/responder/common/cache_req/cache_req_domain.c \
    src/util/session_recording.c \
    $(SSSD_RESPONDER_IFACE_OBJ) \
    $(NULL)
responder_socket_access_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
responder_socket_access_tests_LDADD = \
    $(LIBADD_DL) \
    $(CHECK_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)
endif

stress_tests_SOURCES = \
    src/tests/stress-tests.c
stress_tests_LDADD = \
    $(SSSD_LIBS) \
    libsss_test_common.la

test_ssh_client_SOURCES = \
    src/tests/test_ssh_client.c \
    $(NULL)
test_ssh_client_CFLAGS = \
    $(AM_CFLAGS) \
    -DSSH_CLIENT_DIR=\"$(abs_top_builddir)\" \
    $(NULL)
test_ssh_client_LDADD = \
    $(SSSD_INTERNAL_LTLIBS) \
    $(SSSD_LIBS) \
    $(NULL)

test_sbus_message_SOURCES = \
    src/tests/cmocka/sbus/test_sbus_message.c \
    $(NULL)
test_sbus_message_CFLAGS = \
    $(AM_CFLAGS)
test_sbus_message_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    libsss_debug.la \
    libsss_test_common.la \
    libsss_sbus.la \
    $(SSSD_INTERNAL_LTLIBS) \
    $(NULL)

test_sbus_opath_SOURCES = \
    src/tests/cmocka/sbus/test_sbus_opath.c \
    $(NULL)
test_sbus_opath_CFLAGS = \
    $(AM_CFLAGS)
test_sbus_opath_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    libsss_debug.la \
    libsss_test_common.la \
    libsss_sbus.la \
    $(SSSD_INTERNAL_LTLIBS) \
    $(NULL)

if HAVE_CMOCKA

TEST_MOCK_RESP_OBJ = \
     src/tests/cmocka/common_mock_resp.c \
     src/tests/cmocka/common_mock_resp_dp.c \
     src/responder/common/responder_packet.c \
     src/responder/common/responder_cmd.c \
     src/responder/common/negcache.c \
     src/util/nss_dl_load.c \
     src/responder/common/responder_common.c \
     src/responder/common/responder_utils.c \
     src/util/session_recording.c \
     $(SSSD_CACHE_REQ_OBJ) \
     $(SSSD_RESPONDER_IFACE_OBJ) \
     $(NULL)

TEST_MOCK_PROVIDER_OBJ = \
     src/util/sss_sockets.c \
     src/util/sss_ldap.c \
     src/providers/data_provider_opts.c \
     src/providers/ldap/ldap_opts.c \
     src/providers/ldap/ldap_options.c \
     src/providers/ldap/sdap_domain.c \
     src/providers/ldap/sdap.c \
     src/providers/ldap/sdap_utils.c \
     src/providers/ldap/sdap_range.c \
     src/tests/cmocka/common_mock_sdap.c \
     src/tests/cmocka/common_mock_sysdb_objects.c

EXTRA_nss_srv_tests_DEPENDENCIES = \
     $(ldblib_LTLIBRARIES)
nss_srv_tests_SOURCES = \
     $(TEST_MOCK_RESP_OBJ) \
     src/tests/cmocka/test_nss_srv.c \
     src/responder/nss/nss_cmd.c \
     src/responder/nss/nss_enum.c \
     src/responder/nss/nss_get_object.c \
     src/responder/nss/nss_protocol.c \
     src/responder/nss/nss_protocol_pwent.c \
     src/responder/nss/nss_protocol_grent.c \
     src/responder/nss/nss_protocol_netgr.c \
     src/responder/nss/nss_protocol_svcent.c \
     src/responder/nss/nss_protocol_hostent.c \
     src/responder/nss/nss_protocol_netent.c \
     src/responder/nss/nss_protocol_sid.c \
     src/responder/nss/nss_utils.c \
     src/responder/nss/nsssrv_mmap_cache.c
nss_srv_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS)
nss_srv_tests_LDFLAGS = \
    -Wl,-wrap,sss_ncache_check_user \
    -Wl,-wrap,sss_ncache_check_upn \
    -Wl,-wrap,sss_ncache_check_uid \
    -Wl,-wrap,sss_ncache_check_sid \
    -Wl,-wrap,sss_ncache_check_cert \
    -Wl,-wrap,sss_packet_get_body \
    -Wl,-wrap,sss_packet_get_cmd \
    -Wl,-wrap,sss_cmd_send_empty \
    -Wl,-wrap,sss_cmd_done
nss_srv_tests_LDADD = \
    $(LIBADD_DL) \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    libsss_cert.la \
    libsss_idmap.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)
if BUILD_SUBID
     nss_srv_tests_SOURCES += src/responder/nss/nss_protocol_subid.c
endif

EXTRA_pam_srv_tests_DEPENDENCIES = \
    $(ldblib_LTLIBRARIES) \
    $(NULL)
EXTRA_pam_srv_tests_DEPENDENCIES += p11_child
pam_srv_tests_SOURCES = \
    $(TEST_MOCK_RESP_OBJ) \
    src/tests/cmocka/test_pam_srv.c \
    src/tests/cmocka/common_utils.c \
    src/sss_client/pam_message.c \
    src/responder/pam/pamsrv_cmd.c \
    src/responder/pam/pamsrv_p11.c \
    src/responder/pam/pamsrv_gssapi.c \
    src/responder/pam/pam_helpers.c \
    src/responder/pam/pamsrv_dp.c \
    src/responder/pam/pam_prompting_config.c \
    src/sss_client/pam_sss_prompt_config.c \
    $(NULL)
pam_srv_tests_CFLAGS = \
    -U SSSD_LIBEXEC_PATH -DSSSD_LIBEXEC_PATH=\"$(abs_builddir)\" \
    -I$(abs_builddir)/src \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS) \
    $(GSSAPI_KRB5_CFLAGS) \
    $(NULL)
pam_srv_tests_LDFLAGS = \
    -Wl,-wrap,sss_packet_get_body \
    -Wl,-wrap,sss_packet_get_cmd \
    -Wl,-wrap,sss_cmd_send_empty \
    -Wl,-wrap,sss_cmd_done \
    -Wl,-wrap,pam_dp_send_req \
    $(NULL)
pam_srv_tests_LDADD = \
    $(LIBADD_DL) \
    $(CMOCKA_LIBS) \
    $(PAM_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(GSSAPI_KRB5_LIBS) \
    libsss_test_common.la \
    libsss_idmap.la \
    libsss_certmap.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)
if BUILD_PASSKEY
     pam_srv_tests_SOURCES += src/responder/pam/pamsrv_passkey.c
endif # BUILD_PASSKEY

EXTRA_ssh_srv_tests_DEPENDENCIES = \
    $(ldblib_LTLIBRARIES) \
    $(NULL)
EXTRA_ssh_srv_tests_DEPENDENCIES += p11_child
ssh_srv_tests_SOURCES = \
    $(TEST_MOCK_RESP_OBJ) \
    src/tests/cmocka/test_ssh_srv.c \
    src/responder/ssh/ssh_cmd.c \
    src/responder/ssh/ssh_protocol.c \
    src/responder/ssh/ssh_reply.c \
    src/responder/ssh/ssh_cert_to_ssh_key.c \
    $(NULL)

ssh_srv_tests_CFLAGS = \
    -U SSSD_LIBEXEC_PATH -DSSSD_LIBEXEC_PATH=\"$(abs_builddir)\" \
    -I$(abs_builddir)/src \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS) \
    $(NULL)
ssh_srv_tests_LDFLAGS = \
    -Wl,-wrap,sss_packet_get_body \
    -Wl,-wrap,sss_packet_get_cmd \
    -Wl,-wrap,sss_cmd_send_empty \
    -Wl,-wrap,sss_cmd_done \
    -Wl,-wrap,ssh_dp_send_req \
    $(NULL)
ssh_srv_tests_LDADD = \
    $(LIBADD_DL) \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    libsss_iface.la \
    libsss_sbus.la \
    libsss_certmap.la \
    $(NULL)

EXTRA_responder_get_domains_tests_DEPENDENCIES = \
     $(ldblib_LTLIBRARIES)
responder_get_domains_tests_SOURCES = \
     $(SSSD_RESPONDER_OBJ) \
     src/tests/cmocka/test_responder_common.c \
     src/tests/cmocka/common_mock_resp.c
responder_get_domains_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS)
responder_get_domains_tests_LDFLAGS = \
    -Wl,-wrap,sss_parse_name_for_domains \
    -Wl,-wrap,sss_ncache_reset_repopulate_permanent
responder_get_domains_tests_LDADD = \
    $(LIBADD_DL) \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

config_check_tests_SOURCES = \
    src/tests/cmocka/test_config_check.c \
    $(NULL)
config_check_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
config_check_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(INI_CONFIG_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_find_uid_SOURCES = \
    src/tests/cmocka/test_find_uid.c \
    src/util/find_uid.c \
    src/util/atomic_io.c \
    src/util/strtonum.c
test_find_uid_CFLAGS = \
    $(AM_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(DHASH_CFLAGS)
if HAVE_SYSTEMD_UNIT
    test_find_uid_CFLAGS += $(SYSTEMD_LOGIN_CFLAGS)
endif

test_find_uid_LDADD = \
    $(TALLOC_LIBS) \
    $(DHASH_LIBS) \
    $(CMOCKA_LIBS) \
    libsss_debug.la
if HAVE_SYSTEMD_UNIT
    test_find_uid_CFLAGS += $(SYSTEMD_LOGIN_LIBS)
endif

test_io_SOURCES = \
    src/tests/cmocka/test_io.c \
    src/util/io.c \
    src/tests/common.c
test_io_CFLAGS = \
    $(AM_CFLAGS)
test_io_LDADD = \
    $(CMOCKA_LIBS)

EXTRA_test_negcache_DEPENDENCIES = \
    $(ldblib_LTLIBRARIES)
test_negcache_SOURCES = \
    $(SSSD_RESPONDER_OBJ) \
    src/tests/cmocka/common_mock_resp.c \
    src/tests/cmocka/test_negcache.c \
    src/tests/cmocka/test_negcache_2.c
test_negcache_CFLAGS = \
    $(AM_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(DHASH_CFLAGS)
test_negcache_LDADD = \
    $(LIBADD_DL) \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    libsss_idmap.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

test_authtok_SOURCES = \
    src/tests/cmocka/test_authtok.c \
    src/util/authtok.c \
    src/util/authtok-utils.c \
    src/util/util.c \
    src/util/util_ext.c \
    $(NULL)
test_authtok_CFLAGS = \
    $(AM_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(POPT_CFLAGS) \
    $(DHASH_CFLAGS) \
    $(NULL)
test_authtok_LDADD = \
    $(TALLOC_LIBS) \
    $(CMOCKA_LIBS) \
    $(DHASH_LIBS) \
    $(POPT_LIBS) \
    libsss_test_common.la \
    libsss_debug.la \
    $(NULL)

test_prompt_config_SOURCES = \
    src/tests/cmocka/test_prompt_config.c \
    src/sss_client/pam_sss_prompt_config.c \
    $(NULL)
test_prompt_config_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS) \
    $(NULL)
test_prompt_config_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    libsss_debug.la \
    $(TALLOC_LIBS) \
    $(NULL)

sss_nss_idmap_tests_SOURCES = \
    $(libsss_nss_idmap_la_SOURCES) \
    src/tests/cmocka/sss_nss_idmap-tests.c
sss_nss_idmap_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS)
sss_nss_idmap_tests_LDFLAGS = \
    -Wl,-wrap,sss_nss_make_request_timeout
sss_nss_idmap_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(libsss_nss_idmap_la_LIBADD) \
    $(NULL)

deskprofile_utils_tests_SOURCES = \
    src/tests/cmocka/test_deskprofile_utils.c \
    src/providers/ipa/ipa_deskprofile_rules_util.c \
    src/providers/ipa/ipa_rules_common.c
deskprofile_utils_tests_CFLAGS = \
    $(AM_CFLAGS)
deskprofile_utils_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

EXTRA_dyndns_tests_DEPENDENCIES = \
     $(ldblib_LTLIBRARIES)
dyndns_tests_SOURCES = \
     $(SSSD_RESOLV_OBJ) \
     src/tests/cmocka/common_mock_be.c \
     src/tests/cmocka/test_dyndns.c \
     src/providers/data_provider_opts.c \
     src/util/child_common.c
dyndns_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS) \
    -DDYNDNS_TIMEOUT=2
dyndns_tests_LDFLAGS = \
    -Wl,-wrap,execv \
    -Wl,-wrap,getifaddrs \
    -Wl,-wrap,freeifaddrs
dyndns_tests_LDADD = \
    $(CARES_LIBS) \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

domain_resolution_order_tests_SOURCES = \
	src/tests/cmocka/test_domain_resolution_order.c \
	src/responder/common/cache_req/cache_req_domain.c
domain_resolution_order_tests_CFLAGS = \
	$(AM_CFLAGS)
domain_resolution_order_tests_LDADD = \
	$(CMOCKA_LIBS) \
	$(SSSD_INTERNAL_LTLIBS) \
	libsss_test_common.la

fqnames_tests_SOURCES = \
    src/tests/cmocka/test_fqnames.c
fqnames_tests_CFLAGS = \
    $(AM_CFLAGS)
fqnames_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

nestedgroups_tests_SOURCES = \
    $(TEST_MOCK_PROVIDER_OBJ) \
    src/providers/ldap/sdap_idmap.c \
    src/tests/cmocka/test_nested_groups.c \
    src/tests/cmocka/common_mock_be.c \
    src/providers/ldap/sdap_async_nested_groups.c \
    src/providers/ldap/sdap_ad_groups.c \
    src/providers/ipa/ipa_dn.c \
    $(NULL)
nestedgroups_tests_CFLAGS = \
    $(AM_CFLAGS) \
    -DEXTERNAL_MEMBERS_CHUNK=1 \
    $(NULL)
nestedgroups_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(OPENLDAP_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_idmap.la \
    libsss_test_common.la \
    libsss_ldap_common.la \
    libdlopen_test_providers.la \
    $(NULL)
if BUILD_SYSTEMTAP
nestedgroups_tests_LDADD += stap_generated_probes.lo
endif

test_sss_idmap_SOURCES = \
    src/tests/cmocka/test_sss_idmap.c
test_sss_idmap_CFLAGS = \
    $(AM_CFLAGS)
test_sss_idmap_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    libsss_idmap.la \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

test_ipa_idmap_SOURCES = \
    src/tests/cmocka/test_ipa_idmap.c \
    src/providers/ipa/ipa_idmap.c
test_ipa_idmap_CFLAGS = \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS)
test_ipa_idmap_LDFLAGS = \
    -Wl,-wrap,sysdb_get_ranges
test_ipa_idmap_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    libsss_idmap.la \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

test_utils_SOURCES = \
    src/tests/cmocka/test_utils.c \
    src/tests/cmocka/test_string_utils.c \
    src/tests/cmocka/test_sss_ptr_hash.c \
    src/p11_child/p11_child_common_utils.c \
    $(NULL)
if BUILD_SSH
test_utils_SOURCES += src/tests/cmocka/test_sss_ssh.c
endif
test_utils_CFLAGS = \
    $(AM_CFLAGS)
test_utils_CFLAGS += \
    $(P11_KIT_CFLAGS) \
    $(NULL)
test_utils_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

test_search_bases_SOURCES = \
    src/tests/cmocka/test_search_bases.c
test_search_bases_LDADD = \
    $(CMOCKA_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_ldap_common.la \
    libsss_test_common.la \
    libdlopen_test_providers.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

test_ldap_auth_SOURCES = \
    src/tests/cmocka/test_ldap_auth.c \
    src/tests/cmocka/test_expire_common.c \
    $(NULL)
test_ldap_auth_LDADD = \
    $(CMOCKA_LIBS) \
    $(TALLOC_LIBS) \
    libsss_ldap_common.la \
    libsss_test_common.la \
    libdlopen_test_providers.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

test_ldap_id_cleanup_SOURCES = \
    src/tests/cmocka/test_ldap_id_cleanup.c \
    $(NULL)
test_ldap_id_cleanup_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_ldap_common.la \
    libsss_test_common.la \
    libdlopen_test_providers.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

test_sdap_access_SOURCES = \
    src/tests/cmocka/test_sdap_access.c \
    src/tests/cmocka/test_expire_common.c \
    $(NULL)
test_sdap_access_LDADD = \
    $(CMOCKA_LIBS) \
    $(TALLOC_LIBS) \
    libsss_ldap_common.la \
    libsss_test_common.la \
    libdlopen_test_providers.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

test_sdap_certmap_SOURCES = \
    src/tests/cmocka/test_sdap_certmap.c \
    src/providers/ldap/sdap_certmap.c \
    $(NULL)
test_sdap_certmap_CFLAGS = \
    $(AM_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(POPT_CFLAGS) \
    $(NULL)
test_sdap_certmap_LDADD = \
    $(CMOCKA_LIBS) \
    $(TALLOC_LIBS) \
    $(POPT_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    libsss_certmap.la \
    $(NULL)

ad_access_filter_tests_SOURCES = \
    src/tests/cmocka/test_ad_access_filter.c
ad_access_filter_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_ldap_common.la \
    libsss_ad_tests.la \
    libsss_test_common.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

ad_gpo_tests_SOURCES = \
    src/tests/cmocka/test_ad_gpo.c \
    src/providers/ad/ad_gpo_child_utils.c
ad_gpo_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(NDR_NBT_CFLAGS) \
    $(NULL)
ad_gpo_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(OPENLDAP_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(NDR_NBT_LIBS) \
    libsss_ldap_common.la \
    libsss_idmap.la \
    libsss_krb5_common.la \
    libsss_ad_tests.la \
    libsss_test_common.la \
    libdlopen_test_providers.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

dist_noinst_DATA += src/tests/cmocka/GPT.INI

ad_common_tests_SOURCES = \
    $(libsss_krb5_common_la_SOURCES) \
    src/tests/cmocka/common_mock_krb5.c \
    src/tests/cmocka/test_ad_common.c \
    src/providers/ad/ad_opts.c \
    src/providers/ad/ad_pac.c \
    src/providers/ad/ad_pac_common.c \
    src/providers/ad/ad_domain_info.c \
    src/providers/ldap/ldap_common.c \
    src/providers/ldap/sdap_async_initgroups_ad.c \
    $(NULL)
ad_common_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(OPENLDAP_LIBS) \
    $(NDR_NBT_CFLAGS) \
    $(NDR_KRB5PAC_CFLAGS) \
    $(CMOCKA_CFLAGS) \
    $(NULL)
ad_common_tests_LDFLAGS = \
    -Wl,-wrap,sdap_set_sasl_options \
    -Wl,-wrap,sdap_select_principal_from_keytab_sync \
    -Wl,-wrap,krb5_kt_default \
    $(NULL)
ad_common_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(KEYUTILS_LIBS) \
    $(NDR_NBT_LIBS) \
    $(NDR_KRB5PAC_LIBS) \
    $(KRB5_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_idmap.la \
    libsss_ldap_common.la \
    libsss_test_common.la \
    libdlopen_test_providers.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

dp_opt_tests_SOURCES = \
    src/providers/data_provider_opts.c \
    src/tests/cmocka/test_dp_opts.c
dp_opt_tests_CFLAGS = \
    $(AM_CFLAGS)
dp_opt_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(TALLOC_LIBS) \
    $(POPT_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

sdap_tests_SOURCES = \
    src/providers/data_provider_opts.c \
    src/providers/ldap/sdap_domain.c \
    src/providers/ldap/sdap.c \
    src/providers/ldap/sdap_range.c \
    src/providers/ldap/ldap_opts.c \
    src/providers/ipa/ipa_opts.c \
    src/util/sss_sockets.c \
    src/util/sss_ldap.c \
    src/tests/cmocka/test_sdap.c \
    $(NULL)
sdap_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS) \
    $(NULL)
sdap_tests_LDFLAGS = \
    -Wl,-wrap,ldap_set_option \
    -Wl,-wrap,ldap_get_dn \
    -Wl,-wrap,ldap_memfree \
    -Wl,-wrap,ldap_get_values_len \
    -Wl,-wrap,ldap_value_free_len \
    -Wl,-wrap,ldap_first_attribute \
    -Wl,-wrap,ldap_next_attribute \
    $(NULL)
sdap_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(TALLOC_LIBS) \
    $(LDB_LIBS) \
    $(POPT_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(OPENLDAP_LIBS) \
    libsss_test_common.la \
    libsss_ldap_common.la \
    libdlopen_test_providers.la \
    $(NULL)

ifp_tests_SOURCES = \
    $(TEST_MOCK_RESP_OBJ) \
    src/tests/cmocka/test_ifp.c \
    src/responder/ifp/ifpsrv_cmd.c \
    src/responder/ifp/ifpsrv_util.c \
    $(NULL)
ifp_tests_CFLAGS = \
    $(AM_CFLAGS)
ifp_tests_LDADD = \
    $(LIBADD_DL) \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

test_sysdb_views_SOURCES = \
    src/tests/cmocka/test_sysdb_views.c \
    src/providers/ipa/ipa_utils.c \
    $(NULL)
test_sysdb_views_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_sysdb_views_LDADD = \
    $(CMOCKA_LIBS) \
    $(LDB_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_sysdb_ts_cache_SOURCES = \
    src/tests/cmocka/test_sysdb_ts_cache.c \
    src/providers/ipa/ipa_utils.c \
    $(NULL)
test_sysdb_ts_cache_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_sysdb_ts_cache_LDADD = \
    $(CMOCKA_LIBS) \
    $(LDB_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_sysdb_subdomains_SOURCES = \
    src/tests/cmocka/test_sysdb_subdomains.c \
    $(NULL)
test_sysdb_subdomains_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_sysdb_subdomains_LDADD = \
    $(CMOCKA_LIBS) \
    $(LDB_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_sysdb_certmap_SOURCES = \
    src/tests/cmocka/test_sysdb_certmap.c \
    $(NULL)
test_sysdb_certmap_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_sysdb_certmap_LDADD = \
    $(CMOCKA_LIBS) \
    $(LDB_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_sysdb_sudo_SOURCES = \
    src/tests/cmocka/test_sysdb_sudo.c \
    $(NULL)
test_sysdb_sudo_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_sysdb_sudo_LDADD = \
    $(CMOCKA_LIBS) \
    $(LDB_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_sysdb_utils_SOURCES = \
    src/tests/cmocka/test_sysdb_utils.c \
    $(NULL)
test_sysdb_utils_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_sysdb_utils_LDADD = \
    $(CMOCKA_LIBS) \
    $(LDB_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_sysdb_domain_resolution_order_SOURCES = \
    src/tests/cmocka/test_sysdb_domain_resolution_order.c \
    $(NULL)
test_sysdb_domain_resolution_order_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_sysdb_domain_resolution_order_LDADD = \
    $(CMOCKA_LIBS) \
    $(LDB_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_be_ptask_SOURCES = \
    src/tests/cmocka/common_mock_be.c \
    src/tests/cmocka/test_be_ptask.c \
    src/providers/be_ptask.c \
    $(NULL)
test_be_ptask_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_be_ptask_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_copy_ccache_SOURCES = \
    src/tests/cmocka/test_copy_ccache.c \
    src/providers/krb5/krb5_ccache.c \
    src/util/sss_krb5.c \
    src/util/sss_iobuf.c \
    $(NULL)
test_copy_ccache_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_copy_ccache_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(KRB5_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_copy_keytab_SOURCES = \
    src/tests/cmocka/common_mock_krb5.c \
    src/tests/cmocka/test_copy_keytab.c \
    src/providers/krb5/krb5_keytab.c \
    src/util/sss_krb5.c \
    src/util/sss_iobuf.c \
    $(NULL)
test_copy_keytab_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_copy_keytab_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(KRB5_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

dummy_child_SOURCES = \
    src/tests/cmocka/dummy_child.c \
    $(NULL)
dummy_child_LDADD = \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(NULL)

test_child_common_SOURCES = \
    src/tests/cmocka/test_child_common.c \
    src/util/child_common.c \
    src/util/signal.c \
    src/util/atomic_io.c \
    src/util/util_errors.c \
    src/util/util.c \
    src/util/util_ext.c \
    $(NULL)
test_child_common_CFLAGS = \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS) \
    -DCHILD_DIR=\"$(builddir)\" \
    $(NULL)
test_child_common_LDFLAGS = \
    -Wl,-wrap,child_io_destructor \
    $(NULL)
test_child_common_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(DHASH_LIBS) \
    libsss_debug.la \
    libsss_test_common.la \
    $(NULL)

responder_cache_req_tests_SOURCES = \
    $(TEST_MOCK_RESP_OBJ) \
    src/tests/cmocka/test_responder_cache_req.c \
    $(NULL)
responder_cache_req_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS) \
    $(NULL)
responder_cache_req_tests_LDFLAGS = \
    -Wl,-wrap,sss_dp_get_account_send \
    $(NULL)
responder_cache_req_tests_LDADD = \
    $(LIBADD_DL) \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

if HAVE_LIBRESOLV
test_resolv_fake_SOURCES = \
    src/tests/cmocka/test_resolv_fake.c \
    src/resolv/async_resolv.c \
    $(NULL)
test_resolv_fake_CFLAGS = \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS) \
    $(NULL)
test_resolv_fake_LDFLAGS = \
    -Wl,-wrap,ares_query \
    $(NULL)
test_resolv_fake_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(CARES_LIBS) \
    $(DHASH_LIBS) \
    $(RESOLV_LIBS) \
    libsss_debug.la \
    libsss_test_common.la \
    $(NULL)
endif # HAVE_LIBRESOLV

test_fo_srv_SOURCES = \
    src/tests/cmocka/test_fo_srv.c \
    src/providers/fail_over.c \
    src/providers/fail_over_srv.c \
    $(NULL)
test_fo_srv_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_fo_srv_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(CARES_LIBS) \
    $(DHASH_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_sdap_initgr_SOURCES = \
    src/tests/cmocka/common_mock_sdap.c \
    src/tests/cmocka/common_mock_sysdb_objects.c \
    src/tests/cmocka/test_sdap_initgr.c \
    $(NULL)
test_sdap_initgr_CFLAGS = \
    $(AM_CFLAGS) \
    $(NDR_NBT_CFLAGS) \
    $(NULL)
test_sdap_initgr_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(DHASH_LIBS) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(LDB_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_ldap_common.la \
    libsss_test_common.la \
    libdlopen_test_providers.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

test_ad_subdom_SOURCES = \
    src/tests/cmocka/test_ad_subdomains.c \
    $(NULL)
test_ad_subdom_CFLAGS = \
    $(AM_CFLAGS) \
    $(NDR_NBT_CFLAGS) \
    $(NULL)
test_ad_subdom_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_ldap_common.la \
    libsss_ad_tests.la \
    libsss_idmap.la \
    libsss_test_common.la \
    libdlopen_test_providers.la \
    libsss_iface.la \
    libsss_sbus.la \
    libsss_krb5_common.la \
    $(NULL)

test_ipa_subdom_util_SOURCES = \
    src/tests/cmocka/test_ipa_subdomains_utils.c \
    src/providers/ipa/ipa_subdomains_utils.c \
    $(NULL)
test_ipa_subdom_util_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_ipa_subdom_util_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(LDB_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_ipa_subdom_server_SOURCES = \
    $(libsss_krb5_common_la_SOURCES) \
    src/tests/cmocka/common_mock_sdap.c \
    src/tests/cmocka/common_mock_be.c \
    src/tests/cmocka/common_mock_krb5.c \
    src/tests/cmocka/data_provider/mock_dp.c \
    src/tests/cmocka/test_ipa_subdomains_server.c \
    src/providers/ipa/ipa_subdomains_server.c \
    src/providers/ipa/ipa_subdomains_utils.c \
    src/providers/ipa/ipa_common.c \
    src/providers/ipa/ipa_opts.c \
    src/providers/ipa/ipa_srv.c \
    src/providers/ldap/ldap_common.c \
    $(NULL)
test_ipa_subdom_server_CFLAGS = \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS) \
    -DIPA_TRUST_KEYTAB_DIR=TEST_DIR\"/tp_test_ipa_subdom_server-test_ipa_subdomains_server\" \
    $(NULL)
test_ipa_subdom_server_LDFLAGS = \
    -Wl,-wrap,krb5_kt_default \
    -Wl,-wrap,execle \
    -Wl,-wrap,execve \
    -Wl,-wrap,rename \
    -Wl,-wrap,sss_unique_filename \
    -Wl,-wrap,sdap_select_principal_from_keytab_sync \
    $(NULL)
test_ipa_subdom_server_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(KEYUTILS_LIBS) \
    $(KRB5_LIBS) \
    $(OPENLDAP_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_idmap.la \
    libsss_ldap_common.la \
    libsss_ad_tests.la \
    libsss_test_common.la \
    libdlopen_test_providers.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

test_tools_colondb_SOURCES = \
    src/tests/cmocka/test_tools_colondb.c \
    src/tools/common/sss_colondb.c \
    $(NULL)
test_tools_colondb_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_tools_colondb_LDFLAGS = \
    $(NULL)
test_tools_colondb_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(POPT_LIBS) \
    libsss_test_common.la \
    $(NULL)

test_krb5_wait_queue_SOURCES = \
    src/tests/cmocka/common_mock_be.c \
    src/tests/cmocka/test_krb5_wait_queue.c \
    src/providers/krb5/krb5_wait_queue.c \
    $(NULL)
test_krb5_wait_queue_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_krb5_wait_queue_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(DHASH_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_cert_utils_SOURCES = \
    src/tests/cmocka/test_cert_utils.c \
    src/responder/ssh/ssh_cert_to_ssh_key.c \
    src/util/cert_derb64_to_ldap_filter.c \
    $(NULL)
test_cert_utils_CFLAGS = \
    $(AM_CFLAGS) \
    -U SSSD_LIBEXEC_PATH -DSSSD_LIBEXEC_PATH=\"$(abs_builddir)\" \
    -I$(abs_builddir)/src \
    $(CRYPTO_CFLAGS) \
    $(CMOCKA_CFLAGS) \
    $(NULL)
test_cert_utils_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(CRYPTO_LIBS) \
    libsss_debug.la \
    libsss_test_common.la \
    libsss_cert.la \
    libsss_crypt.la \
    libsss_certmap.la \
    $(NULL)

test_data_provider_be_SOURCES = \
    src/providers/data_provider_be.c \
    src/tests/cmocka/test_data_provider_be.c \
    src/tests/cmocka/common_mock_be.c \
    $(NULL)
test_data_provider_be_CFLAGS = \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS) \
    -DUNIT_TESTING \
    $(NULL)
test_data_provider_be_LDFLAGS = \
    -Wl,-wrap,_tevent_add_timer \
    $(NULL)
test_data_provider_be_LDADD = \
    $(CMOCKA_LIBS) \
    $(PAM_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(LIBADD_DL) \
    libsss_test_common.la \
    libdlopen_test_providers.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

test_dp_request_SOURCES = \
    src/providers/data_provider/dp_request.c \
    src/providers/data_provider/dp_modules.c \
    src/providers/data_provider/dp_targets.c \
    src/providers/data_provider/dp_methods.c \
    src/providers/data_provider/dp_builtin.c \
    src/tests/cmocka/data_provider/mock_dp.c \
    src/tests/cmocka/data_provider/test_dp_request.c \
    src/tests/cmocka/common_mock_be.c \
    $(NULL)
test_dp_request_CFLAGS = \
    $(AM_CFLAGS) \
    $(CMOCKA_CFLAGS) \
    -DUNIT_TESTING \
    $(NULL)
test_dp_request_LDFLAGS = \
    -Wl,-wrap,be_is_offline \
    $(NULL)
test_dp_request_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(LIBADD_DL) \
    libsss_test_common.la \
    $(NULL)
if BUILD_SYSTEMTAP
test_dp_request_LDADD += stap_generated_probes.lo
endif

test_dp_builtin_SOURCES = \
    src/providers/data_provider/dp_modules.c \
    src/providers/data_provider/dp_targets.c \
    src/providers/data_provider/dp_methods.c \
    src/providers/data_provider/dp_builtin.c \
    src/tests/cmocka/data_provider/mock_dp.c \
    src/tests/cmocka/data_provider/test_dp_builtin.c \
    src/tests/cmocka/common_mock_be.c \
    $(NULL)
test_dp_builtin_CFLAGS = \
    $(AM_CFLAGS) \
    -DUNIT_TESTING \
    $(NULL)
test_dp_builtin_LDFLAGS = \
    $(NULL)
test_dp_builtin_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(LIBADD_DL) \
    libsss_test_common.la \
    $(NULL)

test_ipa_dn_SOURCES = \
    src/providers/ipa/ipa_dn.c \
    src/tests/cmocka/test_ipa_dn.c \
    $(NULL)
test_ipa_dn_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(LDB_LIBS) \
    $(TEVENT_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_iobuf_SOURCES = \
    src/util/sss_iobuf.c \
    src/tests/cmocka/test_iobuf.c \
    $(NULL)
test_iobuf_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_iobuf_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(NULL)

test_confdb_SOURCES = \
    src/tests/cmocka/confdb/test_confdb.c \
    $(NULL)
test_confdb_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_confdb_LDADD = \
    $(CMOCKA_LIBS) \
    $(LDB_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

EXTRA_simple_access_tests_DEPENDENCIES = \
    $(ldblib_LTLIBRARIES)
simple_access_tests_SOURCES = \
    src/tests/cmocka/test_simple_access.c \
    src/tests/cmocka/common_mock_be.c \
    src/providers/simple/simple_access.c \
    src/providers/simple/simple_access_check.c \
    $(NULL)
simple_access_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
simple_access_tests_LDFLAGS = \
    $(NULL)
simple_access_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    libdlopen_test_providers.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

krb5_common_test_SOURCES = \
    src/tests/cmocka/test_krb5_common.c \
    $(NULL)
krb5_common_test_CFLAGS = \
    $(KRB5_CFLAGS) \
    $(AM_CFLAGS) \
    $(NULL)
krb5_common_test_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    libsss_krb5_common.la \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    libdlopen_test_providers.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

test_inotify_SOURCES = \
    src/util/inotify.c \
    src/tests/cmocka/test_inotify.c \
    $(NULL)
test_inotify_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_inotify_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(LIBADD_DL) \
    libsss_test_common.la \
    $(NULL)

sss_certmap_test_SOURCES = \
    src/tests/cmocka/test_certmap.c \
    src/lib/certmap/sss_certmap_attr_names.c \
    $(NULL)
sss_certmap_test_CFLAGS = \
    $(AM_CFLAGS) \
    $(SSS_CERT_CFLAGS) \
    -I$(abs_builddir)/src \
    $(NULL)
sss_certmap_test_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(SSS_CERT_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    libsss_certmap.la \
    $(NULL)

test_sssd_krb5_locator_plugin_SOURCES = \
    src/tests/cmocka/test_sssd_krb5_locator_plugin.c \
    src/krb5_plugin/sssd_krb5_locator_plugin.c \
    $(NULL)
test_sssd_krb5_locator_plugin_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(KRB5_CFLAGS) \
    -DTEST_PUBCONF_PATH=\"$(abs_builddir)/src/tests/cmocka/pubconf\" \
    $(NULL)
test_sssd_krb5_locator_plugin_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(KRB5_LIBS) \
    libsss_test_common.la \
    $(NULL)

if BUILD_PASSKEY
test_passkey_SOURCES = \
    src/passkey_child/passkey_child_common.c \
    src/passkey_child/passkey_child_credentials.c \
    src/passkey_child/passkey_child_devices.c \
    src/passkey_child/passkey_child_assert.c \
    src/tests/cmocka/test_passkey_child.c \
    $(NULL)
test_passkey_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_passkey_LDFLAGS = \
    -Wl,-wrap,sleep \
    -Wl,-wrap,tcgetattr \
    -Wl,-wrap,tcsetattr \
    -Wl,-wrap,getline \
    -Wl,-wrap,fido_dev_info_manifest \
    -Wl,-wrap,fido_dev_info_path \
    -Wl,-wrap,fido_dev_open \
    -Wl,-wrap,fido_dev_has_uv \
    -Wl,-wrap,fido_dev_has_pin \
    -Wl,-wrap,fido_dev_supports_uv \
    -Wl,-wrap,fido_dev_make_cred \
    -Wl,-wrap,fido_cred_x5c_ptr \
    -Wl,-wrap,fido_cred_verify \
    -Wl,-wrap,fido_cred_verify_self \
    -Wl,-wrap,fido_cred_id_ptr \
    -Wl,-wrap,fido_cred_id_len \
    -Wl,-wrap,fido_cred_pubkey_ptr \
    -Wl,-wrap,fido_cred_pubkey_len \
    -Wl,-wrap,fido_assert_set_rp \
    -Wl,-wrap,fido_assert_allow_cred \
    -Wl,-wrap,fido_assert_set_uv \
    -Wl,-wrap,fido_assert_user_id_len \
    -Wl,-wrap,fido_assert_set_clientdata_hash \
    -Wl,-wrap,fido_dev_get_assert \
    -Wl,-wrap,fido_dev_is_fido2 \
    -Wl,-wrap,fido_assert_verify \
    -Wl,-wrap,fido_assert_authdata_ptr \
    -Wl,-wrap,fido_assert_authdata_len \
    -Wl,-wrap,fido_assert_sig_ptr \
    -Wl,-wrap,fido_assert_sig_len \
    -Wl,-wrap,fido_assert_set_count \
    -Wl,-wrap,fido_assert_set_authdata \
    -Wl,-wrap,fido_assert_set_sig \
    -Wl,-wrap,fido_dev_get_retry_count
test_passkey_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(LIBADD_DL) \
    $(PASSKEY_LIBS) \
    libsss_test_common.la \
    $(JANSSON_LIBS) \
    $(NULL)
endif # BUILD_PASSKEY

if BUILD_KCM
test_kcm_marshalling_SOURCES = \
    src/tests/cmocka/test_kcm_marshalling.c \
    src/responder/kcm/kcmsrv_ccache_binary.c \
    src/responder/kcm/kcmsrv_ccache_key.c \
    src/responder/kcm/kcmsrv_ccache.c \
    src/util/sss_krb5.c \
    src/util/sss_iobuf.c \
    $(NULL)
test_kcm_marshalling_CFLAGS = \
    $(AM_CFLAGS) \
    $(UUID_CFLAGS) \
    $(NULL)
test_kcm_marshalling_LDADD = \
    $(UUID_LIBS) \
    $(KRB5_LIBS) \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    $(NULL)

test_kcm_queue_SOURCES = \
    $(TEST_MOCK_RESP_OBJ) \
    src/tests/cmocka/test_kcm_queue.c \
    src/responder/kcm/kcmsrv_op_queue.c \
    $(NULL)
test_kcm_queue_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_kcm_queue_LDADD = \
    $(LIBADD_DL) \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

test_krb5_idp_plugin_SOURCES = \
    src/tests/cmocka/test_krb5_idp_plugin.c \
    src/krb5_plugin/common/utils.c \
    src/krb5_plugin/idp/idp_utils.c \
    $(NULL)
test_krb5_idp_plugin_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_krb5_idp_plugin_LDADD = \
    $(CMOCKA_LIBS) \
    $(JANSSON_LIBS) \
    $(NULL)

if BUILD_PASSKEY
test_krb5_passkey_plugin_SOURCES = \
    src/tests/cmocka/test_krb5_passkey_plugin.c \
    src/krb5_plugin/common/utils.c \
    src/krb5_plugin/passkey/passkey_utils.c \
    $(NULL)
test_krb5_passkey_plugin_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_krb5_passkey_plugin_LDADD = \
    $(CMOCKA_LIBS) \
    $(JANSSON_LIBS) \
    $(NULL)
endif # BUILD_PASSKEY

if BUILD_KCM_RENEWAL
test_kcm_renewals_SOURCES = \
	$(TEST_MOCK_RESP_OBJ) \
	src/tests/cmocka/test_kcm_renewals.c \
	src/responder/kcm/kcm_renew.c \
	src/responder/kcm/kcmsrv_ccache.c \
	src/responder/kcm/kcmsrv_ccache_key.c \
	src/responder/kcm/kcmsrv_ccache_binary.c \
	src/util/sss_krb5.c \
	src/util/sss_iobuf.c \
	src/responder/kcm/secrets/secrets.c \
	src/responder/kcm/secrets/config.c \
	src/providers/krb5/krb5_child_handler.c \
	src/providers/krb5/krb5_opts.c \
	src/providers/data_provider_opts.c \
	$(NULL)
test_kcm_renewals_CFLAGS = \
	$(AM_CFLAGS) \
	$(NULL)
test_kcm_renewals_LDFLAGS = \
	-Wl,-wrap,fstat
test_kcm_renewals_LDADD = \
	$(LIBADD_DL) \
	$(UUID_LIBS) \
	$(KRB5_LIBS) \
	$(CARES_LIBS) \
	$(CMOCKA_LIBS) \
	$(SSSD_LIBS) \
	$(SSSD_INTERNAL_LTLIBS) \
	libsss_test_common.la \
	libsss_iface.la \
	libsss_sbus.la \
	$(NULL)
endif # BUILD_KCM_RENEWAL

endif # BUILD_KCM

endif # HAVE_CMOCKA

noinst_PROGRAMS =
if BUILD_SUDO
noinst_PROGRAMS += sss_sudo_cli
endif
if BUILD_AUTOFS
noinst_PROGRAMS += autofs_test_client
endif
if BUILD_PAC_RESPONDER
    noinst_PROGRAMS += sssd_pac_test_client
endif

if BUILD_AUTOFS
autofs_test_client_SOURCES = \
    src/sss_client/autofs/autofs_test_client.c \
    src/sss_client/autofs/sss_autofs.c \
    src/sss_client/common.c
autofs_test_client_CFLAGS = $(AM_CFLAGS)
autofs_test_client_LDADD = -lpopt $(CLIENT_LIBS)
endif

if BUILD_KRB5_LOCALAUTH_PLUGIN
test_sssd_krb5_localauth_plugin_SOURCES = \
    src/tests/cmocka/test_sssd_krb5_localauth_plugin.c \
    src/krb5_plugin/sssd_krb5_localauth_plugin.c \
    $(NULL)
test_sssd_krb5_localauth_plugin_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
test_sssd_krb5_localauth_plugin_LDADD = \
    $(CMOCKA_LIBS) \
    $(KRB5_LIBS) \
    $(NULL)
endif

#####################
# Integration tests #
#####################

intgcheck-prepare:
	set -e; \
	rm -Rf intg; \
	$(MKDIR_P) intg/bld; \
	: Use /hopefully/ short prefix to keep D-Bus socket path short; \
	prefix=`mktemp --tmpdir --directory sssd-intg.XXXXXXXX`; \
	$(LN_S) "$$prefix" intg/pfx; \
	cd intg/bld; \
	$(abs_top_srcdir)/configure \
	    --prefix="$$prefix" \
	    --with-ldb-lib-dir="$$prefix"/lib/ldb \
	    --with-pid-path="$$prefix"/run/sssd \
	    --enable-intgcheck-reqs \
	    --without-selinux \
	    --with-session-recording-shell=/bin/false \
	    $(INTGCHECK_CONFIGURE_FLAGS) \
	    CFLAGS="-O2 -g $$CFLAGS -DINTGCHECK_BUILD"; \
	$(MAKE) $(AM_MAKEFLAGS) ; \
	$(MAKE) $(AM_MAKEFLAGS) test_ssh_client; \
	: Force single-thread install to workaround concurrency issues; \
	$(MAKE) $(AM_MAKEFLAGS) -j1 install; \
	: Remove .la files from LDB module directory to avoid loader warnings; \
	rm "$$prefix"/lib/ldb/*.la; \
	cd ../..

intgcheck-run:
	set -e; \
	if [ ! -d intg/pfx ]; then $(MAKE) intgcheck-prepare; fi; \
	cd intg/bld; \
	$(MAKE) $(AM_MAKEFLAGS) -C src/tests/intg intgcheck-installed; \
	cd ../..

intgcheck-clean:
	set -e; \
	prefix=`readlink -e intg/pfx`; \
	rm -Rf "$$prefix" intg

intgcheck:
	$(MAKE) intgcheck-prepare
	$(MAKE) intgcheck-run
	$(MAKE) intgcheck-clean

####################
# Client Libraries #
####################

nsslib_LTLIBRARIES = libnss_sss.la
libnss_sss_la_SOURCES = \
    src/sss_client/common.c \
    src/sss_client/nss_passwd.c \
    src/sss_client/nss_group.c \
    src/sss_client/nss_netgroup.c \
    src/sss_client/nss_services.c \
    src/sss_client/nss_hosts.c \
    src/sss_client/nss_ipnetworks.c \
    src/sss_client/sss_cli.h \
    src/sss_client/nss_compat.h \
    src/sss_client/nss_common.h \
    src/sss_client/common_private.h \
    src/sss_client/nss_mc_common.c \
    src/util/io.c \
    src/util/murmurhash3.c \
    src/sss_client/nss_mc_passwd.c \
    src/sss_client/nss_mc_group.c \
    src/sss_client/nss_mc_initgr.c \
    src/sss_client/nss_mc.h
libnss_sss_la_LIBADD = \
    $(CLIENT_LIBS)
libnss_sss_la_LDFLAGS = \
    -module \
    -version-info 2:0:0 \
    -Wl,--version-script,$(srcdir)/src/sss_client/sss_nss.exports

if BUILD_NFS_IDMAP
nfslib_LTLIBRARIES = sss.la
sss_la_SOURCES = \
    src/sss_client/common.c \
    src/sss_client/nss_mc_common.c \
    src/util/io.c \
    src/util/murmurhash3.c \
    src/sss_client/nss_mc_passwd.c \
    src/sss_client/nss_mc_group.c \
    src/sss_client/nfs/sss_nfs_client.c \
    $(NULL)
sss_la_CFLAGS = $(AM_CFLAGS)
sss_la_LIBADD = \
    $(CLIENT_LIBS) \
    $(NFSIDMAP_LIBS) \
    $(NULL)
sss_la_LDFLAGS = \
    -module \
    -avoid-version \
    $(NULL)
endif

pamlib_LTLIBRARIES = pam_sss.la
pam_sss_la_SOURCES = \
    src/sss_client/pam_sss.c \
    src/sss_client/pam_sss_prompt_config.c \
    src/sss_client/pam_message.c \
    src/sss_client/common.c \
    src/sss_client/sss_cli.h \
    src/util/atomic_io.c \
    src/util/authtok-utils.c \
    src/util/memory_erase.c \
    src/sss_client/sss_pam_macros.h \
    src/sss_client/sss_pam_compat.h

pam_sss_la_LIBADD = \
    $(CLIENT_LIBS) \
    $(PAM_LIBS)
pam_sss_la_LDFLAGS = \
    -module \
    -avoid-version \
    -Wl,--version-script,$(srcdir)/src/sss_client/sss_pam.exports

pamlib_LTLIBRARIES += pam_sss_gss.la
pam_sss_gss_la_SOURCES = \
    src/sss_client/pam_sss_gss.c \
    src/sss_client/common.c \
    $(NULL)

pam_sss_gss_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(GSSAPI_KRB5_CFLAGS) \
    $(NULL)

pam_sss_gss_la_LIBADD = \
    $(CLIENT_LIBS) \
    $(PAM_LIBS) \
    $(GSSAPI_KRB5_LIBS) \
    $(NULL)

pam_sss_gss_la_LDFLAGS = \
    -module \
    -avoid-version \
    -Wl,--version-script,$(srcdir)/src/sss_client/pam_sss_gss.exports

if BUILD_SUDO

libsss_sudo_la_SOURCES = \
    src/sss_client/common.c \
    src/sss_client/sss_cli.h \
    src/sss_client/sudo/sss_sudo_response.c \
    src/sss_client/sudo/sss_sudo.c \
    src/sss_client/sudo/sss_sudo.h \
    src/sss_client/sudo/sss_sudo_private.h
libsss_sudo_la_LIBADD = \
    $(CLIENT_LIBS)
libsss_sudo_la_LDFLAGS = \
    -Wl,--version-script,$(srcdir)/src/sss_client/sss_sudo.exports \
    -module \
    -avoid-version

sudolib_LTLIBRARIES = libsss_sudo.la

endif

if BUILD_AUTOFS
autofslib_LTLIBRARIES = libsss_autofs.la
libsss_autofs_la_SOURCES = \
    src/sss_client/common.c \
    src/sss_client/sss_cli.h \
    src/sss_client/autofs/sss_autofs.c \
    src/sss_client/autofs/sss_autofs_private.h

libsss_autofs_la_LIBADD = \
    $(CLIENT_LIBS)
libsss_autofs_la_LDFLAGS = \
    -module \
    -avoid-version \
    -Wl,--version-script,$(srcdir)/src/sss_client/autofs/sss_autofs.exports
endif

if BUILD_SUBID
subidlib_LTLIBRARIES = libsubid_sss.la
libsubid_sss_la_SOURCES = \
    src/sss_client/common.c \
    src/sss_client/sss_cli.h \
    src/sss_client/subid/sss_subid.c

libsubid_sss_la_LIBADD = \
    $(CLIENT_LIBS)
libsubid_sss_la_LDFLAGS = \
    -module \
    -avoid-version \
    -Wl,--version-script,$(srcdir)/src/sss_client/subid/sss_subid.exports
endif

dist_noinst_DATA += \
    src/sss_client/sss_nss.exports \
    src/sss_client/sss_pam.exports \
    src/sss_client/pam_sss_gss.exports \
    $(NULL)

if BUILD_SUDO
dist_noinst_DATA += src/sss_client/sss_sudo.exports
endif

if BUILD_AUTOFS
dist_noinst_DATA += src/sss_client/autofs/sss_autofs.exports
endif

if BUILD_SUBID
dist_noinst_DATA += src/sss_client/subid/sss_subid.exports
endif

####################
# Plugin Libraries #
####################

# libsss_krb5_common must be installed before libsss_ldap_common
# because libtool tries to relink libsss_ldap_common when installing
# libsss_ldap_common and therefore make distcheck fails
pkglib_LTLIBRARIES += libsss_krb5_common.la
pkglib_LTLIBRARIES += libsss_ldap_common.la
libsss_ldap_common_la_SOURCES = \
    src/providers/ldap/ldap_id.c \
    src/providers/ldap/ldap_id_enum.c \
    src/providers/ldap/ldap_resolver_enum.c \
    src/providers/ldap/ldap_resolver_cleanup.c \
    src/providers/ldap/sdap_async_enum.c \
    src/providers/ldap/sdap_async_resolver_enum.c \
    src/providers/ldap/ldap_id_cleanup.c \
    src/providers/ldap/ldap_id_netgroup.c \
    src/providers/ldap/ldap_id_services.c \
    src/providers/ldap/ldap_auth.c \
    src/providers/ldap/ldap_common.c \
    src/providers/ldap/ldap_options.c \
    src/providers/ldap/ldap_opts.c \
    src/providers/ldap/sdap_access.c \
    src/providers/ldap/sdap_iphost.c \
    src/providers/ldap/sdap_ipnetwork.c \
    src/providers/ldap/sdap_async.c \
    src/providers/ldap/sdap_async_users.c \
    src/providers/ldap/sdap_async_groups.c \
    src/providers/ldap/sdap_async_nested_groups.c \
    src/providers/ldap/sdap_async_initgroups.c \
    src/providers/ldap/sdap_async_initgroups_ad.c \
    src/providers/ldap/sdap_async_connection.c \
    src/providers/ldap/sdap_async_netgroups.c \
    src/providers/ldap/sdap_async_hosts.c \
    src/providers/ldap/sdap_async_services.c \
    src/providers/ldap/sdap_async_iphost.c \
    src/providers/ldap/sdap_async_ipnetwork.c \
    src/providers/ldap/sdap_online_check.c \
    src/providers/ldap/sdap_ad_groups.c \
    src/providers/ldap/sdap_child_helpers.c \
    src/providers/ldap/sdap_fd_events.c \
    src/providers/ldap/sdap_hostid.h \
    src/providers/ldap/sdap_id_op.c \
    src/providers/ldap/sdap_certmap.c \
    src/providers/ldap/sdap_idmap.c \
    src/providers/ldap/sdap_idmap.h \
    src/providers/ldap/sdap_range.c \
    src/providers/ldap/sdap_reinit.c \
    src/providers/ldap/sdap_dyndns.c \
    src/providers/ldap/sdap_refresh.c \
    src/providers/ldap/sdap_utils.c \
    src/providers/ldap/sdap_domain.c \
    src/providers/ldap/sdap_ops.c \
    src/providers/ldap/sdap.c \
    src/providers/ipa/ipa_dn.c \
    src/util/user_info_msg.c \
    src/util/sss_sockets.c \
    src/util/sss_ldap.c \
    src/util/cert_derb64_to_ldap_filter.c \
    $(NULL)
libsss_ldap_common_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(KRB5_CFLAGS) \
    $(NULL)
libsss_ldap_common_la_LIBADD = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(LDB_LIBS) \
    $(OPENLDAP_LIBS) \
    $(DHASH_LIBS) \
    $(KRB5_LIBS) \
    libsss_krb5_common.la \
    libsss_idmap.la \
    libsss_certmap.la \
    $(SSSD_INTERNAL_LTLIBS) \
    $(NULL)
libsss_ldap_common_la_LDFLAGS = \
    -avoid-version \
    $(NULL)
if BUILD_SYSTEMTAP
libsss_ldap_common_la_LIBADD += stap_generated_probes.lo
endif
if BUILD_SUBID
libsss_ldap_common_la_SOURCES += src/providers/ldap/ldap_id_subid.c
endif

if BUILD_SSH
libsss_ldap_common_la_SOURCES += src/providers/ldap/sdap_hostid.c
endif

if BUILD_SUDO
libsss_ldap_common_la_SOURCES += \
    src/providers/ldap/sdap_async_sudo.c \
    src/providers/ldap/sdap_async_sudo_hostinfo.c \
    src/providers/ldap/sdap_sudo_refresh.c \
    src/providers/ldap/sdap_sudo_shared.c \
    src/providers/ldap/sdap_sudo.c
endif

if BUILD_AUTOFS
libsss_ldap_common_la_SOURCES += \
    src/providers/ldap/sdap_autofs.c \
    src/providers/ldap/sdap_async_autofs.c
endif

libsss_krb5_common_la_SOURCES = \
    src/providers/krb5/krb5_utils.c \
    src/providers/krb5/krb5_delayed_online_authentication.c \
    src/providers/krb5/krb5_renew_tgt.c \
    src/providers/krb5/krb5_wait_queue.c \
    src/providers/krb5/krb5_common.c \
    src/providers/krb5/krb5_opts.c \
    src/providers/krb5/krb5_auth.c \
    src/providers/krb5/krb5_access.c \
    src/providers/krb5/krb5_child_handler.c \
    src/providers/krb5/krb5_init_shared.c \
    src/providers/krb5/krb5_ccache.c \
    src/util/sss_krb5.c \
    src/util/sss_iobuf.c \
    src/util/pac_utils.c \
    $(NULL)
libsss_krb5_common_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(KRB5_CFLAGS)
libsss_krb5_common_la_LIBADD = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(LDB_LIBS) \
    $(KEYUTILS_LIBS) \
    $(DHASH_LIBS) \
    $(KRB5_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(NULL)
libsss_krb5_common_la_LDFLAGS = \
    -avoid-version

libsss_ldap_la_SOURCES = \
    src/providers/ldap/ldap_init.c \
    src/providers/ldap/ldap_access.c
libsss_ldap_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(OPENLDAP_CFLAGS)
libsss_ldap_la_LIBADD = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(OPENLDAP_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_ldap_common.la \
    libsss_krb5_common.la
libsss_ldap_la_LDFLAGS = \
    -avoid-version \
    -module


libsss_proxy_la_SOURCES = \
    src/providers/proxy/proxy_init.c \
    src/providers/proxy/proxy_client.c \
    src/providers/proxy/proxy_id.c \
    src/providers/proxy/proxy_netgroup.c \
    src/providers/proxy/proxy_services.c \
    src/providers/proxy/proxy_hosts.c \
    src/providers/proxy/proxy_ipnetworks.c \
    src/providers/proxy/proxy_auth.c \
    src/providers/proxy/proxy_certmap.c \
    src/util/cert_derb64_to_ldap_filter.c \
    src//util/nss_dl_load.c \
    $(NULL)
libsss_proxy_la_CFLAGS = \
    $(AM_CFLAGS)
libsss_proxy_la_LIBADD = \
    $(LIBADD_DL) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(LDB_LIBS) \
    $(PAM_LIBS) \
    $(DHASH_LIBS) \
    $(DBUS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_iface.la \
    libsss_sbus.la \
    libsss_certmap.la \
    $(NULL)
libsss_proxy_la_LDFLAGS = \
    -avoid-version \
    -module

libsss_simple_la_SOURCES = \
    src/providers/simple/simple_access_check.c \
    src/providers/simple/simple_access.c
libsss_simple_la_CFLAGS = \
    $(AM_CFLAGS)
libsss_simple_la_LIBADD = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(LDB_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(NULL)
libsss_simple_la_LDFLAGS = \
    -avoid-version \
    -module

libsss_krb5_la_SOURCES = \
    src/providers/krb5/krb5_init.c
libsss_krb5_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(DHASH_CFLAGS) \
    $(KRB5_CFLAGS)
libsss_krb5_la_LIBADD = \
    $(TALLOC_LIBS) \
    $(DHASH_LIBS) \
    $(KRB5_LIBS) \
    $(PCRE_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_krb5_common.la
libsss_krb5_la_LDFLAGS = \
    -avoid-version \
    -module

libsss_ipa_la_SOURCES = \
    src/providers/ipa/ipa_init.c \
    src/providers/ipa/ipa_opts.c \
    src/providers/ipa/ipa_common.c \
    src/providers/ipa/ipa_config.c \
    src/providers/ipa/ipa_id.c \
    src/providers/ipa/ipa_netgroups.c \
    src/providers/ipa/ipa_auth.c \
    src/providers/ipa/ipa_access.c \
    src/providers/ipa/ipa_dyndns.c \
    src/providers/ipa/ipa_hosts.c \
    src/providers/ipa/ipa_subdomains.c \
    src/providers/ipa/ipa_subdomains_id.c \
    src/providers/ipa/ipa_subdomains_server.c \
    src/providers/ipa/ipa_subdomains_utils.c \
    src/providers/ipa/ipa_subdomains_ext_groups.c \
    src/providers/ipa/ipa_views.c \
    src/providers/ipa/ipa_utils.c \
    src/providers/ipa/ipa_s2n_exop.c \
    src/providers/ipa/ipa_hbac_hosts.c \
    src/providers/ipa/ipa_hbac_private.h \
    src/providers/ipa/ipa_hbac_rules.c \
    src/providers/ipa/ipa_hbac_rules.h \
    src/providers/ipa/ipa_hbac_services.c \
    src/providers/ipa/ipa_hbac_users.c \
    src/providers/ipa/ipa_hbac_common.c \
    src/providers/ipa/ipa_rules_common.c \
    src/providers/ipa/ipa_rules_common.h \
    src/providers/ipa/ipa_session.c \
    src/providers/ipa/ipa_deskprofile_private.h \
    src/providers/ipa/ipa_deskprofile_config.c \
    src/providers/ipa/ipa_deskprofile_config.h \
    src/providers/ipa/ipa_deskprofile_rules.c \
    src/providers/ipa/ipa_deskprofile_rules.h \
    src/providers/ipa/ipa_deskprofile_rules_util.c \
    src/providers/ipa/ipa_deskprofile_rules_util.h \
    src/providers/ipa/ipa_srv.c \
    src/providers/ipa/ipa_idmap.c \
    src/providers/ipa/ipa_dn.c \
    src/providers/ipa/ipa_refresh.c \
    src/providers/ad/ad_opts.c \
    src/providers/ad/ad_common.c \
    src/providers/ad/ad_dyndns.c \
    src/providers/ad/ad_id.c \
    src/providers/ad/ad_pac.c \
    src/providers/ad/ad_pac_common.c \
    src/providers/ad/ad_srv.c \
    src/providers/ad/ad_domain_info.c \
    src/providers/ad/ad_cldap_ping.c \
    $(NULL)
libsss_ipa_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(OPENLDAP_CFLAGS) \
    $(DHASH_CFLAGS) \
    $(NDR_NBT_CFLAGS) \
    $(NDR_KRB5PAC_CFLAGS) \
    $(KRB5_CFLAGS)
libsss_ipa_la_LIBADD = \
    $(LDB_LIBS) \
    $(DBUS_LIBS) \
    $(OPENLDAP_LIBS) \
    $(DHASH_LIBS) \
    $(NDR_NBT_LIBS) \
    $(NDR_KRB5PAC_LIBS) \
    $(KRB5_LIBS) \
    $(SELINUX_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_ldap_common.la \
    libsss_krb5_common.la \
    libipa_hbac.la \
    libsss_idmap.la \
    $(NULL)
libsss_ipa_la_LDFLAGS = \
    -avoid-version \
    -module
if BUILD_AUTOFS
libsss_ipa_la_SOURCES += \
    src/providers/ipa/ipa_autofs.c
endif

if BUILD_SUDO
libsss_ipa_la_SOURCES += \
    src/providers/ipa/ipa_sudo.c \
    src/providers/ipa/ipa_sudo_refresh.c \
    src/providers/ipa/ipa_sudo_conversion.c \
    src/providers/ipa/ipa_sudo_async.c
endif

if BUILD_SELINUX
libsss_ipa_la_SOURCES += \
    src/providers/ipa/ipa_selinux.c \
    src/providers/ipa/ipa_selinux_helpers.c \
    src/providers/ipa/ipa_selinux_maps.c
endif

if BUILD_SSH
libsss_ipa_la_SOURCES += src/providers/ipa/ipa_hostid.c
endif

if BUILD_PASSKEY
libsss_ipa_la_SOURCES += \
    src/providers/ipa/ipa_subdomains_passkey.c
endif # BUILD_PASSKEY

libsss_ad_la_SOURCES = \
    src/providers/ad/ad_opts.c \
    src/providers/ad/ad_common.c \
    src/providers/ad/ad_init.c \
    src/providers/ad/ad_dyndns.c \
    src/providers/ad/ad_machine_pw_renewal.c \
    src/providers/ad/ad_id.c \
    src/providers/ad/ad_pac.c \
    src/providers/ad/ad_pac_common.c \
    src/providers/ad/ad_access.c \
    src/providers/ad/ad_gpo.c \
    src/providers/ad/ad_gpo_ndr.c \
    src/providers/ad/ad_srv.c \
    src/providers/ad/ad_subdomains.c \
    src/providers/ad/ad_domain_info.c \
    src/providers/ad/ad_refresh.c \
    src/providers/ad/ad_resolver.c \
    src/providers/ad/ad_cldap_ping.c \
    $(NULL)


if BUILD_SUDO
libsss_ad_la_SOURCES += \
    src/providers/ad/ad_sudo.c
endif

if BUILD_AUTOFS
libsss_ad_la_SOURCES += \
    src/providers/ad/ad_autofs.c
endif

libsss_ad_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(OPENLDAP_CFLAGS) \
    $(SASL_CFLAGS) \
    $(DHASH_CFLAGS) \
    $(KRB5_CFLAGS) \
    $(NDR_NBT_CFLAGS) \
    $(NDR_KRB5PAC_CFLAGS) \
    $(NULL)
libsss_ad_la_LIBADD = \
    $(LDB_LIBS) \
    $(OPENLDAP_LIBS) \
    $(SASL_LIBS) \
    $(DHASH_LIBS) \
    $(INI_CONFIG_LIBS) \
    $(KRB5_LIBS) \
    $(NDR_NBT_LIBS) \
    $(NDR_KRB5PAC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_ldap_common.la \
    libsss_krb5_common.la \
    libsss_idmap.la \
    $(NULL)
libsss_ad_la_LDFLAGS = \
    -avoid-version \
    -module

krb5_child_SOURCES = \
    src/providers/krb5/krb5_child.c \
    src/providers/krb5/krb5_ccache.c \
    src/providers/krb5/krb5_keytab.c \
    src/util/sss_pam_data.c \
    src/util/user_info_msg.c \
    src/util/sss_krb5.c \
    src/util/sss_iobuf.c \
    src/util/find_uid.c \
    src/util/atomic_io.c \
    src/util/memory.c \
    src/util/memory_erase.c \
    src/util/authtok.c \
    src/util/authtok-utils.c \
    src/util/util.c \
    src/util/capabilities.c \
    src/util/util_ext.c \
    src/util/signal.c \
    src/util/sss_chain_id.c \
    src/util/strtonum.c \
    src/util/util_errors.c \
    src/sss_client/common.c \
    src/krb5_plugin/common/utils.c \
    src/krb5_plugin/idp/idp_utils.c \
    $(NULL)
if BUILD_PASSKEY
    krb5_child_SOURCES += src/krb5_plugin/passkey/passkey_utils.c
endif # BUILD_PASSKEY
krb5_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS) \
    $(KRB5_CFLAGS) \
    $(NULL)
krb5_child_LDADD = \
    libsss_debug.la \
    $(TALLOC_LIBS) \
    $(POPT_LIBS) \
    $(DHASH_LIBS) \
    $(KRB5_LIBS) \
    $(CLIENT_LIBS) \
    $(JANSSON_LIBS) \
    $(CAP_LIBS) \
    $(NULL)

if HAVE_SYSTEMD_UNIT
    krb5_child_LDADD += $(SYSTEMD_DAEMON_LIBS)
endif

ldap_child_SOURCES = \
    src/providers/ldap/ldap_child.c \
    src/providers/krb5/krb5_keytab.c \
    src/util/sss_krb5.c \
    src/util/sss_iobuf.c \
    src/util/atomic_io.c \
    src/util/memory.c \
    src/util/memory_erase.c \
    src/util/authtok.c \
    src/util/authtok-utils.c \
    src/util/util.c \
    src/util/util_ext.c \
    src/util/capabilities.c \
    src/util/signal.c \
    src/util/util_errors.c \
    $(NULL)
ldap_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS) \
    $(KRB5_CFLAGS)
ldap_child_LDADD = \
    libsss_debug.la \
    $(TALLOC_LIBS) \
    $(POPT_LIBS) \
    $(CAP_LIBS) \
    $(DHASH_LIBS) \
    $(KRB5_LIBS)

if BUILD_SELINUX
selinux_child_SOURCES = \
    src/providers/ipa/selinux_child.c \
    src/providers/ipa/selinux_child_semanage.c \
    src/util/sss_chain_id.c \
    src/util/sss_prctl.c \
    src/util/atomic_io.c \
    src/util/util.c \
    src/util/util_ext.c \
    src/util/util_errors.c \
    src/util/capabilities.c \
    $(NULL)
selinux_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS) \
    $(NULL)
selinux_child_LDADD = \
    libsss_debug.la \
    $(TALLOC_LIBS) \
    $(POPT_LIBS) \
    $(DHASH_LIBS) \
    $(CAP_LIBS) \
    $(SEMANAGE_LIBS) \
    $(SELINUX_LIBS) \
    $(NULL)
endif

gpo_child_SOURCES = \
    src/providers/ad/ad_gpo_child.c \
    src/providers/ad/ad_gpo_child_utils.c \
    src/util/atomic_io.c \
    src/util/util.c \
    src/util/util_ext.c \
    src/util/util_errors.c \
    src/util/signal.c \
    src/util/sss_chain_id.c \
    src/util/sss_prctl.c
gpo_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS) \
    $(KRB5_CFLAGS) \
    $(INI_CONFIG_CFLAGS) \
    $(SMBCLIENT_CFLAGS)
gpo_child_LDADD = \
    libsss_debug.la \
    $(TALLOC_LIBS) \
    $(POPT_LIBS) \
    $(DHASH_LIBS) \
    $(INI_CONFIG_LIBS) \
    $(SMBCLIENT_LIBS) \
    $(SAMBA_UTIL_LIBS)

proxy_child_SOURCES = \
    src/providers/proxy/proxy_child.c \
    $(NULL)
proxy_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS)
proxy_child_LDADD = \
    $(PAM_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_iface.la \
    libsss_sbus.la \
    $(NULL)

p11_child_SOURCES = \
    src/p11_child/p11_child_common.c \
    src/p11_child/p11_child_common_utils.c \
    src/util/atomic_io.c \
    src/util/util.c \
    src/util/util_ext.c \
    src/util/sss_chain_id.c \
    src/util/sss_prctl.c \
    $(NULL)
p11_child_SOURCES += src/p11_child/p11_child_openssl.c

p11_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS) \
    $(NULL)
p11_child_CFLAGS += \
    $(P11_KIT_CFLAGS) \
    $(CRYPTO_CFLAGS) \
    $(SSL_CFLAGS) \
    $(NULL)

p11_child_LDADD = \
    libsss_debug.la \
    $(TALLOC_LIBS) \
    $(DHASH_LIBS) \
    $(POPT_LIBS) \
    libsss_crypt.la \
    $(NULL)
p11_child_LDADD += \
    $(P11_KIT_LIBS) \
    $(CRYPTO_LIBS) \
    $(SSL_LIBS) \
    $(NULL)

if BUILD_PASSKEY
passkey_child_SOURCES = \
    src/passkey_child/passkey_child.c \
    src/passkey_child/passkey_child_common.c \
    src/passkey_child/passkey_child_credentials.c \
    src/passkey_child/passkey_child_devices.c \
    src/passkey_child/passkey_child_assert.c \
    $(NULL)

passkey_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS)

passkey_child_LDADD = \
    libsss_crypt.la \
    libsss_debug.la \
    $(TALLOC_LIBS) \
    $(DHASH_LIBS) \
    $(POPT_LIBS) \
    $(PASSKEY_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(CRYPTO_LIBS) \
    $(JANSSON_LIBS) \
    $(NULL)
endif # BUILD_PASSKEY

if BUILD_OIDC_CHILD
oidc_child_SOURCES = \
    src/oidc_child/oidc_child.c \
    src/oidc_child/oidc_child_curl.c \
    src/oidc_child/oidc_child_json.c \
    src/util/atomic_io.c \
    src/util/memory.c \
    src/util/memory_erase.c \
    src/util/strtonum.c \
    $(NULL)
oidc_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS) \
    $(JANSSON_CFLAGS) \
    $(JOSE_CFLAGS) \
    $(CURL_CFLAGS) \
    $(NULL)
oidc_child_LDADD = \
    libsss_debug.la \
    $(TALLOC_LIBS) \
    $(POPT_LIBS) \
    $(JANSSON_LIBS) \
    $(JOSE_LIBS) \
    $(CURL_LIBS) \
    $(NULL)
endif

memberof_la_SOURCES = \
    src/ldb_modules/memberof.c \
    src/util/util.c \
    src/util/util_ext.c \
    $(NULL)
memberof_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
memberof_la_LIBADD = \
    libsss_debug.la \
    $(TALLOC_LIBS) \
    $(LDB_LIBS) \
    $(DHASH_LIBS) \
    $(NULL)
memberof_la_LDFLAGS = \
    -avoid-version \
    -module \
    $(NULL)

if BUILD_KRB5_LOCATOR_PLUGIN
sssd_krb5_locator_plugin_la_SOURCES = \
    src/krb5_plugin/sssd_krb5_locator_plugin.c \
    src/util/atomic_io.c
sssd_krb5_locator_plugin_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(KRB5_CFLAGS)
sssd_krb5_locator_plugin_la_LDFLAGS = \
    -avoid-version \
    -module
endif

if BUILD_KRB5_LOCALAUTH_PLUGIN
sssd_krb5_localauth_plugin_la_SOURCES = \
    src/krb5_plugin/sssd_krb5_localauth_plugin.c \
    src/util/murmurhash3.c \
    src/util/io.c \
    src/sss_client/common.c \
    src/sss_client/nss_mc_common.c \
    src/sss_client/nss_mc_passwd.c \
    src/sss_client/nss_passwd.c
sssd_krb5_localauth_plugin_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(KRB5_CFLAGS)
sssd_krb5_localauth_plugin_la_LIBADD = \
    $(KRB5_LIBS)
sssd_krb5_localauth_plugin_la_LDFLAGS = \
    -avoid-version \
    -module
endif

krb5_plugindir = @appmodpath@
dist_krb5snippets_DATA = contrib/enable_sssd_conf_dir

krb5_plugin_LTLIBRARIES = \
    sssd_krb5_idp_plugin.la \
    $(NULL)

sssd_krb5_idp_plugin_la_SOURCES = \
    src/krb5_plugin/common/utils.c \
    src/krb5_plugin/common/radius_clpreauth.c \
    src/krb5_plugin/common/radius_kdcpreauth.c \
    src/krb5_plugin/idp/idp_clpreauth.c \
    src/krb5_plugin/idp/idp_kdcpreauth.c \
    src/krb5_plugin/idp/idp_utils.c \
    $(NULL)
sssd_krb5_idp_plugin_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(KRB5_CFLAGS) \
    $(NULL)
sssd_krb5_idp_plugin_la_LIBADD = \
    $(KRB5_LIBS) \
    $(KRAD_LIBS) \
    $(JANSSON_LIBS) \
    $(NULL)
sssd_krb5_idp_plugin_la_LDFLAGS = \
    -avoid-version \
    -module \
    $(NULL)

dist_noinst_HEADERS += src/krb5_plugin/idp/idp.h
dist_krb5snippets_DATA += src/krb5_plugin/idp/sssd_enable_idp

if BUILD_PASSKEY
krb5_plugin_LTLIBRARIES += sssd_krb5_passkey_plugin.la

sssd_krb5_passkey_plugin_la_SOURCES = \
    src/krb5_plugin/common/utils.c \
    src/krb5_plugin/common/radius_kdcpreauth.c \
    src/krb5_plugin/common/radius_clpreauth.c \
    src/krb5_plugin/passkey/passkey_clpreauth.c \
    src/krb5_plugin/passkey/passkey_kdcpreauth.c \
    src/krb5_plugin/passkey/passkey_utils.c \
    $(NULL)
sssd_krb5_passkey_plugin_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(KRB5_CFLAGS) \
    $(NULL)
sssd_krb5_passkey_plugin_la_LIBADD = \
    $(KRB5_LIBS) \
    $(KRAD_LIBS) \
    $(JANSSON_LIBS) \
    $(NULL)
sssd_krb5_passkey_plugin_la_LDFLAGS = \
    -avoid-version \
    -module \
    $(NULL)

dist_noinst_HEADERS += src/krb5_plugin/passkey/passkey.h
dist_krb5snippets_DATA += src/krb5_plugin/passkey/sssd_enable_passkey
endif # BUILD_PASSKEY

sssd_pac_plugin_la_SOURCES = \
    src/sss_client/sssd_pac.c \
    src/sss_client/common.c \
    src/sss_client/sss_cli.h \
    src/sss_client/krb5_authdata_int.h
sssd_pac_plugin_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(KRB5_CFLAGS)
sssd_pac_plugin_la_LIBADD = \
    $(CLIENT_LIBS) \
    $(KRB5_LIBS)
sssd_pac_plugin_la_LDFLAGS = \
    -avoid-version \
    -module

sssd_pac_test_client_SOURCES = \
    src/sss_client/sss_pac_responder_client.c \
    src/sss_client/common.c \
    src/util/strtonum.c \
    $(NULL)
sssd_pac_test_client_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
sssd_pac_test_client_LDADD = \
    $(CLIENT_LIBS) \
    -lpthread \
    $(NULL)

# python[23] bindings
pysss_la_SOURCES = \
    $(SSSD_TOOLS_OBJ) \
    src/python/pysss.c
pysss_la_LDFLAGS = \
    -avoid-version \
    -module

_py2sss_la_SOURCES = $(pysss_la_SOURCES)
_py2sss_la_CFLAGS = \
    $(AM_CFLAGS)  \
    $(PYTHON2_CFLAGS)
_py2sss_la_LIBADD = \
    $(SSSD_INTERNAL_LTLIBS) \
    $(PYTHON_BINDINGS_LIBS) \
    $(PYTHON2_LIBS)
_py2sss_la_LDFLAGS = $(pysss_la_LDFLAGS)

_py3sss_la_SOURCES = $(pysss_la_SOURCES)
_py3sss_la_CFLAGS = \
    $(AM_CFLAGS)  \
    $(PYTHON3_CFLAGS)
_py3sss_la_LIBADD = \
    $(SSSD_INTERNAL_LTLIBS) \
    $(PYTHON_BINDINGS_LIBS) \
    $(PYTHON3_LIBS)
_py3sss_la_LDFLAGS = $(pysss_la_LDFLAGS)


pyhbac_la_SOURCES = \
    src/python/pyhbac.c \
    src/util/sss_python.c
pyhbac_la_LDFLAGS = \
    -avoid-version \
    -module

_py2hbac_la_SOURCES = $(pyhbac_la_SOURCES)
_py2hbac_la_CFLAGS = \
    $(AM_CFLAGS)  \
    $(PYTHON2_CFLAGS)
_py2hbac_la_LIBADD = \
    $(PYTHON2_LIBS) \
    libipa_hbac.la
_py2hbac_la_LDFLAGS = $(pyhbac_la_LDFLAGS)

_py3hbac_la_SOURCES = $(pyhbac_la_SOURCES)
_py3hbac_la_CFLAGS = \
    $(AM_CFLAGS)  \
    $(PYTHON3_CFLAGS)
_py3hbac_la_LIBADD = \
    $(PYTHON3_LIBS) \
    libipa_hbac.la
_py3hbac_la_LDFLAGS = $(pyhbac_la_LDFLAGS)


pysss_murmur_la_SOURCES = \
    src/python/pysss_murmur.c \
    src/util/murmurhash3.c
pysss_murmur_la_LDFLAGS = \
    -avoid-version \
    -module

_py2sss_murmur_la_SOURCES = $(pysss_murmur_la_SOURCES)
_py2sss_murmur_la_CFLAGS = \
    $(AM_CFLAGS)  \
    $(PYTHON2_CFLAGS)
_py2sss_murmur_la_LIBADD = \
    $(PYTHON2_LIBS)
_py2sss_murmur_la_LDFLAGS = $(pysss_murmur_la_LDFLAGS)

_py3sss_murmur_la_SOURCES = $(pysss_murmur_la_SOURCES)
_py3sss_murmur_la_CFLAGS = \
    $(AM_CFLAGS)  \
    $(PYTHON3_CFLAGS)
_py3sss_murmur_la_LIBADD = \
    $(PYTHON3_LIBS)
_py3sss_murmur_la_LDFLAGS = $(pysss_murmur_la_LDFLAGS)


pysss_nss_idmap_la_SOURCES = \
    src/python/pysss_nss_idmap.c
pysss_nss_idmap_la_LDFLAGS = \
    -avoid-version \
    -module

_py2sss_nss_idmap_la_SOURCES = $(pysss_nss_idmap_la_SOURCES)
_py2sss_nss_idmap_la_CFLAGS = \
    $(AM_CFLAGS)  \
    $(PYTHON2_CFLAGS)
_py2sss_nss_idmap_la_LIBADD = \
    $(PYTHON2_LIBS) \
    libsss_nss_idmap.la
_py2sss_nss_idmap_la_LDFLAGS = $(pysss_nss_idmap_la_LDFLAGS)

_py3sss_nss_idmap_la_SOURCES = $(pysss_nss_idmap_la_SOURCES)
_py3sss_nss_idmap_la_CFLAGS = \
    $(AM_CFLAGS)  \
    $(PYTHON3_CFLAGS)
_py3sss_nss_idmap_la_LIBADD = \
    $(PYTHON3_LIBS) \
    libsss_nss_idmap.la
_py3sss_nss_idmap_la_LDFLAGS = $(pysss_nss_idmap_la_LDFLAGS)
# end of python[23] bindings

if BUILD_CIFS_IDMAP_PLUGIN
cifs_idmap_sss_la_SOURCES = \
    src/lib/cifs_idmap_sss/cifs_idmap_sss.c
cifs_idmap_sss_la_LIBADD = \
    libsss_idmap.la \
    libsss_nss_idmap.la
cifs_idmap_sss_la_CFLAGS = \
    $(AM_CFLAGS)
cifs_idmap_sss_la_LDFLAGS = \
    -avoid-version \
    -module
endif

if BUILD_SAMBA
winbind_idmap_sss_la_SOURCES = \
    src/lib/winbind_idmap_sss/winbind_idmap_sss.c \
    src/util/util_sss_idmap.c \
    $(NULL)
winbind_idmap_sss_la_LIBADD = \
    libsss_idmap.la \
    libsss_nss_idmap.la \
    $(TALLOC_LIBS) \
    $(NULL)
winbind_idmap_sss_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(NDR_KRB5PAC_CFLAGS) \
    $(NULL)
winbind_idmap_sss_la_LDFLAGS = \
    -avoid-version \
    -module \
    $(NULL)

libdlopen_test_winbind_idmap_la_SOURCES = \
    src/lib/winbind_idmap_sss/libdlopen-test-winbind-idmap.c \
    $(NULL)
libdlopen_test_winbind_idmap_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(NDR_KRB5PAC_CFLAGS) \
    $(NULL)
libdlopen_test_winbind_idmap_la_LDFLAGS = \
    -shared \
    -avoid-version \
    -rpath $(abs_top_builddir) \
    -export-dynamic
    $(NULL)
endif

################
# TRANSLATIONS #
################
update-po:
if HAVE_MANPAGES
	$(MAKE) -C src/man update-po
endif
	$(MAKE) -C po update-po

#######################
# Installation Extras #
#######################

init_SCRIPTS =
systemdunit_DATA =
systemdconf_DATA =
if HAVE_SYSTEMD_UNIT
    systemdunit_DATA += \
        src/sysv/systemd/sssd.service \
        src/sysv/systemd/sssd-nss.socket \
        src/sysv/systemd/sssd-nss.service \
        src/sysv/systemd/sssd-pam.socket \
        src/sysv/systemd/sssd-pam.service \
        $(NULL)
if BUILD_AUTOFS
    systemdunit_DATA += \
        src/sysv/systemd/sssd-autofs.socket \
        src/sysv/systemd/sssd-autofs.service \
        $(NULL)
endif
    systemdunit_DATA += \
        src/sysv/systemd/sssd-ifp.service \
        $(NULL)
if BUILD_PAC_RESPONDER
    systemdunit_DATA += \
        src/sysv/systemd/sssd-pac.socket \
        src/sysv/systemd/sssd-pac.service \
        $(NULL)
endif
if BUILD_SSH
    systemdunit_DATA += \
        src/sysv/systemd/sssd-ssh.socket \
        src/sysv/systemd/sssd-ssh.service \
        $(NULL)
endif
if BUILD_SUDO
    systemdunit_DATA += \
        src/sysv/systemd/sssd-sudo.socket \
        src/sysv/systemd/sssd-sudo.service \
        $(NULL)
endif
if BUILD_KCM
    systemdunit_DATA += \
        src/sysv/systemd/sssd-kcm.socket \
        src/sysv/systemd/sssd-kcm.service \
        $(NULL)
endif
else
if HAVE_GENTOO
    init_SCRIPTS += \
        src/sysv/gentoo/sssd \
        src/sysv/gentoo/sssd-kcm
else
    init_SCRIPTS += \
        src/sysv/sssd
endif
endif


dist_sssddata_DATA = \
    src/config/etc/sssd.api.conf \
    src/config/cfg_rules.ini \
    $(NULL)
dist_sssdapiplugin_DATA = \
    src/config/etc/sssd.api.d/sssd-ipa.conf \
    src/config/etc/sssd.api.d/sssd-ad.conf \
    src/config/etc/sssd.api.d/sssd-krb5.conf \
    src/config/etc/sssd.api.d/sssd-ldap.conf \
    src/config/etc/sssd.api.d/sssd-proxy.conf \
    src/config/etc/sssd.api.d/sssd-simple.conf

edit_cmd = $(SED) \
        -e 's|@sbindir[@]|$(sbindir)|g' \
        -e 's|@environment_file[@]|$(environment_file)|g' \
        -e 's|@localstatedir[@]|$(localstatedir)|g' \
        -e 's|@runstatedir[@]|$(runstatedir)|g' \
        -e 's|@logpath[@]|$(logpath)|g' \
        -e 's|@pidpath[@]|$(pidpath)|g' \
        -e 's|@libexecdir[@]|$(libexecdir)|g' \
        -e 's|@pipepath[@]|$(pipepath)|g' \
        -e 's|@prefix[@]|$(prefix)|g' \
        -e 's|@SSSD_USER[@]|$(SSSD_USER)|g' \
        -e 's|@condconfigexists[@]|$(condconfigexists)|g' \
        -e 's|@capabilities[@]|$(capabilities)|g' \
        -e 's|@nss_service_user_group[@]|$(nss_service_user_group)|g' \
        -e 's|@nss_socket_user_group[@]|$(nss_socket_user_group)|g' \
        -e 's|@supplementary_groups[@]|$(supplementary_groups)|g' \
        -e 's|@sssdconfdir[@]|$(sssdconfdir)|g' \
        -e 's|@secdbpath[@]|$(secdbpath)|g' \
        -e 's|@dbpath[@]|$(dbpath)|g' \
        -e 's|@gpocachepath[@]|$(gpocachepath)|g'

replace_script = \
    @rm -f $@ $@.tmp; \
    srcdir=''; \
        test -f ./$@.in || srcdir=$(srcdir)/; \
        $(edit_cmd) $${srcdir}$@.in >$@.tmp; \
    mv $@.tmp $@

EXTRA_DIST += \
    src/sysv/systemd/sssd.service.in \
    src/sysv/systemd/sssd-nss.socket.in \
    src/sysv/systemd/sssd-nss.service.in \
    src/sysv/systemd/sssd-pam.socket.in \
    src/sysv/systemd/sssd-pam.service.in \
    src/sysv/systemd/sssd-autofs.socket.in \
    src/sysv/systemd/sssd-autofs.service.in \
    src/sysv/systemd/sssd-ifp.service.in \
    src/sysv/systemd/sssd-pac.socket.in \
    src/sysv/systemd/sssd-pac.service.in \
    src/sysv/systemd/sssd-ssh.socket.in \
    src/sysv/systemd/sssd-ssh.service.in \
    src/sysv/systemd/sssd-sudo.socket.in \
    src/sysv/systemd/sssd-sudo.service.in \
    src/sysv/systemd/sssd-kcm.socket.in \
    src/sysv/systemd/sssd-kcm.service.in \
    $(NULL)

src/examples/logrotate: src/examples/logrotate.in Makefile
	@$(MKDIR_P) src/examples/
	$(replace_script)

src/sysv/systemd/sssd.service: src/sysv/systemd/sssd.service.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)

src/sysv/systemd/sssd-nss.socket: src/sysv/systemd/sssd-nss.socket.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)

src/sysv/systemd/sssd-nss.service: src/sysv/systemd/sssd-nss.service.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)

src/sysv/systemd/sssd-pam.socket: src/sysv/systemd/sssd-pam.socket.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)

src/sysv/systemd/sssd-pam.service: src/sysv/systemd/sssd-pam.service.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)

if BUILD_AUTOFS
src/sysv/systemd/sssd-autofs.socket: src/sysv/systemd/sssd-autofs.socket.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)

src/sysv/systemd/sssd-autofs.service: src/sysv/systemd/sssd-autofs.service.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)
endif

src/sysv/systemd/sssd-ifp.service: src/sysv/systemd/sssd-ifp.service.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(ifp_replace_script)

if BUILD_PAC_RESPONDER
src/sysv/systemd/sssd-pac.socket: src/sysv/systemd/sssd-pac.socket.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)

src/sysv/systemd/sssd-pac.service: src/sysv/systemd/sssd-pac.service.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)
endif

if BUILD_SSH
src/sysv/systemd/sssd-ssh.socket: src/sysv/systemd/sssd-ssh.socket.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)

src/sysv/systemd/sssd-ssh.service: src/sysv/systemd/sssd-ssh.service.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)
endif

if BUILD_SUDO
src/sysv/systemd/sssd-sudo.socket: src/sysv/systemd/sssd-sudo.socket.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)

src/sysv/systemd/sssd-sudo.service: src/sysv/systemd/sssd-sudo.service.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)
endif

if BUILD_KCM
src/sysv/systemd/sssd-kcm.socket: src/sysv/systemd/sssd-kcm.socket.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)

src/sysv/systemd/sssd-kcm.service: src/sysv/systemd/sssd-kcm.service.in Makefile
	@$(MKDIR_P) src/sysv/systemd/
	$(replace_script)
endif

EXTRA_DIST += \
    src/tools/wrappers/sss_debuglevel.in \
    $(NULL)

src/tools/wrappers/sss_debuglevel: src/tools/wrappers/sss_debuglevel.in Makefile
	@$(MKDIR_P) src/tools/wrappers/
	$(replace_script)

SSSD_USER_DIRS = \
    $(DESTDIR)$(sss_statedir) \
    $(DESTDIR)$(dbpath) \
    $(DESTDIR)$(keytabdir) \
    $(DESTDIR)$(mcpath) \
    $(DESTDIR)$(pipepath) \
    $(DESTDIR)$(pipepath)/private \
    $(DESTDIR)$(pubconfpath) \
    $(DESTDIR)$(pubconfpath)/krb5.include.d \
    $(DESTDIR)$(gpocachepath) \
    $(DESTDIR)$(sssdconfdir) \
    $(DESTDIR)$(sssdconfdir)/conf.d \
    $(DESTDIR)$(sssdconfdir)/pki \
    $(DESTDIR)$(sssddefaultconfdir) \
    $(DESTDIR)$(logpath) \
    $(DESTDIR)$(deskprofilepath) \
    $(DESTDIR)$(runstatedir)/sssd \
    $(NULL)

installsssddirs::
	$(MKDIR_P) \
    $(DESTDIR)$(includedir) \
    $(DESTDIR)$(libdir) \
    $(DESTDIR)$(bindir) \
    $(DESTDIR)$(sbindir) \
    $(DESTDIR)$(mandir) \
    $(DESTDIR)$(pidpath) \
    $(DESTDIR)$(pluginpath) \
    $(DESTDIR)$(libdir)/ldb \
    $(DESTDIR)$(dbuspolicydir) \
    $(DESTDIR)$(dbusservicedir) \
    $(DESTDIR)$(sssdlibdir) \
    $(DESTDIR)$(pkglibdir) \
    $(DESTDIR)$(sssddatadir) \
    $(DESTDIR)$(sudolibdir) \
    $(DESTDIR)$(autofslibdir) \
    $(DESTDIR)$(pipepath)/private \
    $(DESTDIR)$(krb5snippetsdir) \
    $(SSSD_USER_DIRS) \
    $(NULL);
if SSSD_USER
	-chown $(SSSD_USER):$(SSSD_USER) $(SSSD_USER_DIRS)
	-chown -f $(SSSD_USER):$(SSSD_USER) $(DESTDIR)$(dbpath)/* || true
	-chown -f $(SSSD_USER):$(SSSD_USER) $(DESTDIR)$(sssdconfdir)/sssd.conf || true
	-chown -f -R $(SSSD_USER):$(SSSD_USER) $(DESTDIR)$(sssdconfdir)/conf.d || true
	-chown -f $(SSSD_USER):$(SSSD_USER) $(DESTDIR)$(logpath)/*.log || true
endif
	$(INSTALL) -d -m 0770 $(DESTDIR)$(dbpath) $(DESTDIR)$(logpath) \
	    $(DESTDIR)$(keytabdir) $(DESTDIR)$(gpocachepath) \
	    $(NULL)
	$(INSTALL) -d -m 0770 $(DESTDIR)$(pipepath)/private
	$(INSTALL) -d -m 0771 $(DESTDIR)$(deskprofilepath)
	$(INSTALL) -d -m 0775 $(DESTDIR)$(sss_statedir) \
            $(DESTDIR)$(mcpath) $(DESTDIR)$(pipepath) \
            $(DESTDIR)$(pubconfpath) \
            $(DESTDIR)$(pubconfpath)/krb5.include.d \
            $(DESTDIR)$(runstatedir)/sssd \
	    $(NULL)
	$(INSTALL) -d -m 0750 $(DESTDIR)$(sssdconfdir) \
                          $(DESTDIR)$(sssdconfdir)/conf.d \
                          $(DESTDIR)$(sssdconfdir)/pki

if HAVE_DOXYGEN
docs:
	$(DOXYGEN) src/doxy.config
	$(DOXYGEN) src/lib/ipa_hbac/ipa_hbac.doxy
	$(DOXYGEN) src/lib/idmap/sss_idmap.doxy
	$(DOXYGEN) src/sss_client/idmap/sss_nss_idmap.doxy
	$(DOXYGEN) src/lib/certmap/sss_certmap.doxy
else !HAVE_DOXYGEN
docs:
	@echo "Doxygen not installed, cannot generate documentation"
	@exit 1
endif !HAVE_DOXYGEN

if BUILD_PYTHON_BINDINGS
$(abs_builddir)/src/config/SSSDConfig/ipachangeconf.py:
	-cp $(srcdir)/src/config/SSSDConfig/ipachangeconf.py $(builddir)/src/config/SSSDConfig/

$(abs_builddir)/src/config/SSSDConfig/sssdoptions.py:
	-cp $(srcdir)/src/config/SSSDConfig/sssdoptions.py $(builddir)/src/config/SSSDConfig/

SSSDCONFIG_MODULES = \
    $(abs_builddir)/src/config/SSSDConfig/ipachangeconf.py \
    $(abs_builddir)/src/config/SSSDConfig/sssdoptions.py
else
SSSSCONFIG_MODULES =
endif

all-local: ldb_mod_test_dir $(SSSDCONFIG_MODULES)
if BUILD_PYTHON2_BINDINGS
	cd $(builddir)/src/config; \
	$(PYTHON2) setup.py build --build-base $(abs_builddir)/src/config
endif
if BUILD_PYTHON3_BINDINGS
	cd $(builddir)/src/config; \
	$(PYTHON3) setup.py build --build-base $(abs_builddir)/src/config
endif

install-exec-hook: installsssddirs
if BUILD_PYTHON2_BINDINGS
	if [ "$(DESTDIR)" = "" ]; then \
		cd $(builddir)/src/config; \
		$(MKDIR_P) "$(python2dir)"; \
		PYTHONPATH="$(PYTHONPATH):$(python2dir)" $(PYTHON2) setup.py build \
			--build-base $(abs_builddir)/src/config install $(DISTSETUPOPTS) --prefix=$(PYTHON2_PREFIX) \
			--record=$(abs_builddir)/src/config/.files2; \
	else \
		cd $(builddir)/src/config; \
		$(MKDIR_P) "$(python2dir)"; \
		PYTHONPATH="$(PYTHONPATH):$(python2dir)" $(PYTHON2) setup.py build \
			--build-base $(abs_builddir)/src/config install $(DISTSETUPOPTS) --prefix=$(PYTHON2_PREFIX) \
			--record=$(abs_builddir)/src/config/.files2 --root=$(DESTDIR); \
	fi
	cd $(DESTDIR)$(py2execdir) && \
		mv -f _py2sss.so pysss.so ; \
		mv -f _py2hbac.so pyhbac.so ; \
		mv -f _py2sss_murmur.so pysss_murmur.so ; \
		mv -f _py2sss_nss_idmap.so pysss_nss_idmap.so
endif
if BUILD_PYTHON3_BINDINGS
	if [ "$(DESTDIR)" = "" ]; then \
		cd $(builddir)/src/config; \
		$(MKDIR_P) "$(python3dir)"; \
		PYTHONPATH="$(PYTHONPATH):$(python3dir)" $(PYTHON3) setup.py build \
			--build-base $(abs_builddir)/src/config install $(DISTSETUPOPTS) --prefix=$(PYTHON3_PREFIX) \
			--record=$(abs_builddir)/src/config/.files3; \
	else \
		cd $(builddir)/src/config; \
		$(MKDIR_P) "$(python3dir)"; \
		PYTHONPATH="$(PYTHONPATH):$(python3dir)" $(PYTHON3) setup.py build \
			--build-base $(abs_builddir)/src/config install $(DISTSETUPOPTS) --prefix=$(PYTHON3_PREFIX) \
			--record=$(abs_builddir)/src/config/.files3 --root=$(DESTDIR); \
	fi
	cd $(DESTDIR)$(py3execdir) && \
		mv -f _py3sss.so pysss.so ; \
		mv -f _py3hbac.so pyhbac.so ; \
		mv -f _py3sss_murmur.so pysss_murmur.so ; \
		mv -f _py3sss_nss_idmap.so pysss_nss_idmap.so
endif
	for doc in $(SSSD_DOCS); do \
		$(MKDIR_P) $$doc $(DESTDIR)/$(docdir); \
		cp -a $$doc $(DESTDIR)/$(docdir)/; \
	done;

if HAVE_SYSTEMD_UNIT
	$(MKDIR_P) $(DESTDIR)$(systemdunitdir)
	$(MKDIR_P) $(DESTDIR)$(systemdconfdir)
else
	$(MKDIR_P) $(DESTDIR)$(initdir)
endif

if SSSD_USER
	-chgrp $(SSSD_USER) $(DESTDIR)$(sssdlibexecdir)/ldap_child
	chmod 750 $(DESTDIR)$(sssdlibexecdir)/ldap_child
	-$(SETCAP) cap_dac_read_search=p $(DESTDIR)$(sssdlibexecdir)/ldap_child
	-chgrp $(SSSD_USER) $(DESTDIR)$(sssdlibexecdir)/krb5_child
	chmod 750 $(DESTDIR)$(sssdlibexecdir)/krb5_child
	-$(SETCAP) cap_dac_read_search,cap_setuid,cap_setgid=p $(DESTDIR)$(sssdlibexecdir)/krb5_child
	-chgrp $(SSSD_USER) $(DESTDIR)$(sssdlibexecdir)/proxy_child
	chmod 750 $(DESTDIR)$(sssdlibexecdir)/proxy_child
	-chgrp $(SSSD_USER) $(DESTDIR)$(sssdlibexecdir)/sssd_pam
	chmod 750 $(DESTDIR)$(sssdlibexecdir)/sssd_pam
	-$(SETCAP) cap_dac_read_search=p $(DESTDIR)$(sssdlibexecdir)/sssd_pam
if BUILD_SELINUX
	-chgrp $(SSSD_USER) $(DESTDIR)$(sssdlibexecdir)/selinux_child
	chmod 750 $(DESTDIR)$(sssdlibexecdir)/selinux_child
	-$(SETCAP) cap_setuid,cap_setgid=p $(DESTDIR)$(sssdlibexecdir)/selinux_child
endif
endif


install-data-hook:
	rm $(DESTDIR)/$(nsslibdir)/libnss_sss.so.2 \
       $(DESTDIR)/$(nsslibdir)/libnss_sss.so
	mv $(DESTDIR)/$(nsslibdir)/libnss_sss.so.2.0.0 $(DESTDIR)/$(nsslibdir)/libnss_sss.so.2
	if [ ! $(krb5rcachedir) = "__LIBKRB5_DEFAULTS__" ]; then \
        $(MKDIR_P) $(DESTDIR)/$(krb5rcachedir) ; \
	fi
if BUILD_SAMBA
	mv $(DESTDIR)/$(winbindplugindir)/winbind_idmap_sss.so $(DESTDIR)/$(winbindplugindir)/sss.so
endif
if BUILD_KCM
	$(MKDIR_P) $(DESTDIR)/$(sssdkcmdatadir)
	$(MKDIR_P) $(DESTDIR)$(secdbpath)
if SSSD_USER
	-chown $(SSSD_USER):$(SSSD_USER) $(DESTDIR)$(secdbpath)
	-chown -f $(SSSD_USER):$(SSSD_USER) $(DESTDIR)$(secdbpath)/*.ldb || true
endif
	$(INSTALL) -d -m 0770 $(DESTDIR)$(secdbpath)
endif

uninstall-hook:
	if [ -f $(abs_builddir)/src/config/.files2 ]; then \
	    cat $(abs_builddir)/src/config/.files2 | xargs -iq rm -f $(DESTDIR)/q; \
	    rm $(abs_builddir)/src/config/.files2 ; \
	fi
	if [ -f $(abs_builddir)/src/config/.files3 ]; then \
	    cat $(abs_builddir)/src/config/.files3 | xargs -iq rm -f $(DESTDIR)/q; \
	    rm $(abs_builddir)/src/config/.files3 ; \
	fi
	for doc in $(SSSD_DOCS); do \
		rm -Rf $(DESTDIR)/$(docdir)/$$doc; \
	done;
if BUILD_PYTHON2_BINDINGS
	cd $(DESTDIR)$(py2execdir) && \
		rm -f pysss.so pyhbac.so pysss_murmur.so pysss_nss_idmap.so
	rm -fr "$(DESTDIR)$(python2dir)/easy-install.pth"
	rm -fr "$(DESTDIR)$(python2dir)/__pycache__"
	rm -fr "$(DESTDIR)$(python2dir)/site.py"
endif
if BUILD_PYTHON3_BINDINGS
	cd $(DESTDIR)$(py3execdir) && \
		rm -f pysss.so pyhbac.so pysss_murmur.so pysss_nss_idmap.so
	rm -fr "$(DESTDIR)$(python3dir)/easy-install.pth"
	rm -fr "$(DESTDIR)$(python3dir)/__pycache__"
	rm -fr "$(DESTDIR)$(python3dir)/site.py"
endif
if BUILD_SAMBA
	rm $(DESTDIR)/$(winbindplugindir)/sss.so
endif

clean-local:
if BUILD_PYTHON2_BINDINGS
	if [ ! $(srcdir)/src/config/SSSDConfig/ipachangeconf.py -ef $(builddir)/src/config/SSSDConfig/ipachangeconf.py ]; then \
		rm -f $(builddir)/src/config/SSSDConfig/ipachangeconf.py ; \
	fi

	if [ ! $(srcdir)/src/config/SSSDConfig/sssdoptions.py -ef $(builddir)/src/config/SSSDConfig/sssdoptions.py ]; then \
		rm -f $(builddir)/src/config/SSSDConfig/sssdoptions.py ; \
	fi

	cd $(builddir)/src/config; $(PYTHON2) setup.py build --build-base $(abs_builddir)/src/config clean --all

	rm -fr "$(builddir)/src/config/dist"
	rm -fr "$(builddir)/src/config/SSSDConfig.egg-info"
	rm -fr "$(builddir)/src/config/SSSDConfig/__pycache__"
	find "$(builddir)/src/config/SSSDConfig" -name "*.py[co]" -delete
endif
if BUILD_PYTHON3_BINDINGS
	if [ ! $(srcdir)/src/config/SSSDConfig/ipachangeconf.py -ef $(builddir)/src/config/SSSDConfig/ipachangeconf.py ]; then \
		rm -f $(builddir)/src/config/SSSDConfig/ipachangeconf.py ; \
	fi

	if [ ! $(srcdir)/src/config/SSSDConfig/sssdoptions.py -ef $(builddir)/src/config/SSSDConfig/sssdoptions.py ]; then \
		rm -f $(builddir)/src/config/SSSDConfig/sssdoptions.py ; \
	fi

	cd $(builddir)/src/config; $(PYTHON3) setup.py build --build-base $(abs_builddir)/src/config clean --all

	rm -fr "$(builddir)/src/config/dist"
	rm -fr "$(builddir)/src/config/SSSDConfig.egg-info"
	rm -fr "$(builddir)/src/config/SSSDConfig/__pycache__"
	find "$(builddir)/src/config/SSSDConfig" -name "*.py[co]" -delete
endif
	for doc in $(SSSD_DOCS); do \
		rm -Rf $$doc; \
	done;
	rm -Rf ldb_mod_test_dir
	rm -f $(builddir)/src/responder/ifp/org.freedesktop.sssd.infopipe.service
	rm -f $(builddir)/src/responder/ifp/org.freedesktop.sssd.infopipe.conf
	rm -f $(builddir)/src/sysv/systemd/sssd.service
	rm -f $(builddir)/src/sysv/systemd/sssd-autofs.socket
	rm -f $(builddir)/src/sysv/systemd/sssd-autofs.service
	rm -f $(builddir)/src/sysv/systemd/sssd-ifp.service
	rm -f $(builddir)/src/sysv/systemd/sssd-nss.socket
	rm -f $(builddir)/src/sysv/systemd/sssd-nss.service
	rm -f $(builddir)/src/sysv/systemd/sssd-pac.socket
	rm -f $(builddir)/src/sysv/systemd/sssd-pac.service
	rm -f $(builddir)/src/sysv/systemd/sssd-pam.socket
	rm -f $(builddir)/src/sysv/systemd/sssd-pam.service
	rm -f $(builddir)/src/sysv/systemd/sssd-ssh.socket
	rm -f $(builddir)/src/sysv/systemd/sssd-ssh.service
	rm -f $(builddir)/src/sysv/systemd/sssd-sudo.socket
	rm -f $(builddir)/src/sysv/systemd/sssd-sudo.service
	rm -f $(builddir)/src/sysv/systemd/sssd-kcm.socket
	rm -f $(builddir)/src/sysv/systemd/sssd-kcm.service
	rm -f $(builddir)/src/tools/wrappers/sss_debuglevel
	rm -Rf $(builddir)/src/examples
	rm -Rf $(builddir)/contrib

CLEANFILES += *.X */*.X */*/*.X

test_CA: test_CA.stamp

test_CA.stamp: $(srcdir)/src/tests/test_CA/* $(srcdir)/src/tests/test_ECC_CA/*
	$(MAKE) -C src/tests/test_CA ca_all
	$(MAKE) -C src/tests/test_CA/intermediate_CA ca_all
	$(MAKE) -C src/tests/test_ECC_CA ca_all
	touch $@

if BUILD_TEST_CA
BUILT_SOURCES += test_CA
endif
CLEANFILES += test_CA.stamp

tests: all $(check_PROGRAMS)
	(cd src/tests/cwrap && $(MAKE) $(AM_MAKEFLAGS) $@) || exit 1;


# RPM-related tasks

RPMBUILD ?= $(PWD)/rpmbuild

dist_noinst_DATA += \
    m4 \
    contrib/sssd.spec.in \
    BUILD.txt \
    COPYING \
    src/tests/ \
    $(NULL)


if BUILD_TMPFILES
        tmpfiles_DATA = contrib/sssd-tmpfiles.conf
        CLEANFILES += contrib/sssd-tmpfiles.conf
else
	dist_noinst_DATA += contrib/sssd-tmpfiles.conf
endif

if BUILD_UDEV_RULES
        udevrules_DATA = contrib/90-sssd-token-access.rules
        CLEANFILES += contrib/90-sssd-token-access.rules
else
	dist_noinst_DATA += contrib/90-sssd-token-access.rules
endif

if BUILD_SYSTEMD_SYSUSERS
        systemd_sysusers_DATA = contrib/sssd.sysusers
        CLEANFILES += contrib/sssd.sysusers
else
        dist_noinst_DATA += contrib/sssd.sysusers
endif

rpmroot:
	$(MKDIR_P) $(RPMBUILD)/BUILD
	$(MKDIR_P) $(RPMBUILD)/RPMS
	$(MKDIR_P) $(RPMBUILD)/SOURCES
	$(MKDIR_P) $(RPMBUILD)/SPECS
	$(MKDIR_P) $(RPMBUILD)/SRPMS

# pre-release related vars

PR_VERSION_DATE := $(shell date +%Y%m%d.%H%M)
PR_VERSION_COMMIT_HASH := $(shell git log -1 --pretty=format:%h)
PR_VERSION_NUMBER = $(PR_VERSION_DATE).git$(PR_VERSION_COMMIT_HASH)
PR_VERSION_REGEX = m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.*\])
PR_VERSION_REPL = m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.$(PR_VERSION_NUMBER)\])

rpmbrprep: dist-gzip rpmroot
if GIT_CHECKOUT
# When we're building RPMs from a git checkout,
# we don't want to be bothered with translation
# updates
	git checkout $(srcdir)/po $(srcdir)/src/man/po
endif
	cp $(builddir)/contrib/sssd.spec $(RPMBUILD)/SPECS
	cp $(distdir).tar.gz $(RPMBUILD)/SOURCES
	cp $(srcdir)/contrib/sssd.sysusers $(RPMBUILD)/SOURCES

rpms: rpmbrprep
	cd $(RPMBUILD); \
	rpmbuild --define "_topdir $(RPMBUILD)" -ba SPECS/sssd.spec

if GIT_CHECKOUT
prerelease-rpms:
	cp $(srcdir)/version.m4 $(srcdir)/version.m4.orig
	sed -e "s/$(PR_VERSION_REGEX)/$(PR_VERSION_REPL)/" \
		< $(srcdir)/version.m4.orig > $(srcdir)/version.m4
	$(MAKE) rpms
	mv $(srcdir)/version.m4.orig $(srcdir)/version.m4
endif

# make srpms will use the old digest algorithm to be compatible
# with RHEL5
srpm: rpmbrprep
	cd $(RPMBUILD); \
	rpmbuild --define "_topdir $(RPMBUILD)" \
	         -bs SPECS/sssd.spec

if GIT_CHECKOUT
prerelease-srpm:
	cp $(srcdir)/version.m4 $(srcdir)/version.m4.orig
	sed -e "s/$(PR_VERSION_REGEX)/$(PR_VERSION_REPL)/" \
		< $(srcdir)/version.m4.orig > $(srcdir)/version.m4
	$(MAKE) srpm
	mv $(srcdir)/version.m4.orig $(srcdir)/version.m4
endif
