extra_distcheck_flags =
if HAVE_DEVSHM
    extra_distcheck_flags += --with-test-dir=/dev/shm
endif

DISTCHECK_CONFIGURE_FLAGS = --with-ldb-lib-dir="$$dc_install_base"/lib/ldb \
                            --enable-all-experimental-features \
                            $(extra_distcheck_flags)

SUBDIRS = po

if HAVE_MANPAGES
SUBDIRS += src/man
endif

# Some old versions of automake don't define builddir
builddir ?= .

DOXYGEN = @DOXYGEN@

DISTSETUPOPTS =
if HAVE_DEBIAN
DISTSETUPOPTS += --install-layout=deb
endif

sssdlibexecdir = $(libexecdir)/sssd
sssdlibdir = $(libdir)/sssd
ldblibdir = @ldblibdir@
if BUILD_KRB5_LOCATOR_PLUGIN
krb5plugindir = @krb5pluginpath@
endif
if BUILD_PAC_RESPONDER
krb5authdata_plugindir = @krb5authdatapluginpath@
endif
if BUILD_CIFS_IDMAP_PLUGIN
cifsplugindir = @cifspluginpath@
endif
sssdconfdir = $(sysconfdir)/sssd
sssddatadir = $(datadir)/sssd
sssdapiplugindir = $(sssddatadir)/sssd.api.d
dbusintrospectdir = $(datarootdir)/sssd/introspect
localedir = @localedir@
nsslibdir = @nsslibdir@
pamlibdir = @pammoddir@
autofslibdir = @appmodpath@

dbpath = @dbpath@
pluginpath = @pluginpath@
pidpath = @pidpath@
pipepath = @pipepath@
mcpath = @mcpath@
initdir = @initdir@
systemdunitdir = @systemdunitdir@
logpath = @logpath@
pubconfpath = @pubconfpath@
pkgconfigdir = $(libdir)/pkgconfig
krb5rcachedir = @krb5rcachedir@
sudolibdir = @sudolibpath@

UNICODE_LIBS=@UNICODE_LIBS@

AM_CFLAGS =
if WANT_AUX_INFO
    AM_CFLAGS += -aux-info $@.X
endif
if HAVE_GCC
    AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
                 -Wcast-qual -Wcast-align -Wwrite-strings \
                 -Werror-implicit-function-declaration \
                 -fno-strict-aliasing \
                 -std=gnu99
endif

dist_pkgconfig_DATA =

ACLOCAL_AMFLAGS = -I m4 -I .

if BUILD_SSH
bin_PROGRAMS = \
    sss_ssh_authorizedkeys \
    sss_ssh_knownhostsproxy
endif

sbin_PROGRAMS = \
    sssd \
    sss_useradd \
    sss_userdel \
    sss_groupadd \
    sss_groupdel \
    sss_usermod \
    sss_groupmod \
    sss_groupshow \
    sss_cache \
    sss_debuglevel \
    sss_seed

sssdlibexec_PROGRAMS = \
    sssd_nss \
    sssd_pam \
    sssd_be \
    krb5_child \
    ldap_child \
    proxy_child
if BUILD_SUDO
sssdlibexec_PROGRAMS += sssd_sudo
endif
if BUILD_AUTOFS
sssdlibexec_PROGRAMS += sssd_autofs
endif
if BUILD_SSH
sssdlibexec_PROGRAMS += sssd_ssh
endif

if BUILD_PAC_RESPONDER
    sssdlibexec_PROGRAMS += sssd_pac
endif

if HAVE_CHECK
    non_interactive_check_based_tests = \
        dlopen-tests \
        sysdb-tests \
        strtonum-tests \
        resolv-tests \
        krb5-utils-tests \
        check_and_open-tests \
        files-tests \
        refcount-tests \
        fail_over-tests \
        find_uid-tests \
        auth-tests \
        ipa_ldap_opt-tests \
        ad_ldap_opt-tests \
        simple_access-tests \
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

endif

if HAVE_CMOCKA
    non_interactive_cmocka_based_tests = \
        nss-srv-tests \
        test-find-uid \
        test-io \
        test-authtok \
        sss_nss_idmap-tests \
        dyndns-tests \
        fqnames-tests \
        test_sss_idmap \
        test_utils \
        ad_access_filter_tests \
        ad_common_tests \
        test_search_bases
endif

check_PROGRAMS = \
    stress-tests \
    krb5-child-test \
    $(non_interactive_cmocka_based_tests) \
    $(non_interactive_check_based_tests)

PYTHON_TESTS =

if BUILD_PYTHON_BINDINGS
PYTHON_TESTS += src/config/SSSDConfigTest.py \
                src/tests/pyhbac-test.py \
                src/tests/pysss_murmur-test.py
endif

TESTS = \
    $(PYTHON_TESTS) \
    $(non_interactive_cmocka_based_tests) \
    $(non_interactive_check_based_tests)

sssdlib_LTLIBRARIES = \
    libsss_ldap.la \
    libsss_krb5.la \
    libsss_proxy.la \
    libsss_ipa.la \
    libsss_ad.la \
    libsss_simple.la

ldblib_LTLIBRARIES = \
    memberof.la

if BUILD_KRB5_LOCATOR_PLUGIN
krb5plugin_LTLIBRARIES = \
    sssd_krb5_locator_plugin.la
endif

if BUILD_PAC_RESPONDER
krb5authdata_plugin_LTLIBRARIES = \
    sssd_pac_plugin.la
endif

if BUILD_CIFS_IDMAP_PLUGIN
cifsplugin_LTLIBRARIES = \
    cifs_idmap_sss.la
endif

noinst_LTLIBRARIES =

pkglib_LTLIBRARIES = \
    libsss_crypt.la

if HAVE_NSS
    SSS_CRYPT_SOURCES = src/util/crypto/nss/nss_base64.c \
                        src/util/crypto/nss/nss_hmac_sha1.c \
                        src/util/crypto/nss/nss_sha512crypt.c \
                        src/util/crypto/nss/nss_obfuscate.c \
                        src/util/crypto/nss/nss_util.c
    SSS_CRYPT_CFLAGS = $(NSS_CFLAGS)
    SSS_CRYPT_LIBS = $(NSS_LIBS)
else
    SSS_CRYPT_SOURCES = src/util/crypto/libcrypto/crypto_base64.c \
                        src/util/crypto/libcrypto/crypto_hmac_sha1.c \
                        src/util/crypto/libcrypto/crypto_sha512crypt.c \
                        src/util/crypto/libcrypto/crypto_obfuscate.c
    SSS_CRYPT_CFLAGS = $(CRYPTO_CFLAGS)
    SSS_CRYPT_LIBS = $(CRYPTO_LIBS)
endif

libsss_crypt_la_SOURCES = \
    $(SSS_CRYPT_SOURCES)
libsss_crypt_la_CFLAGS = \
    $(SSS_CRYPT_CFLAGS) \
    $(DHASH_CFLAGS)
libsss_crypt_la_LIBADD = \
    $(SSS_CRYPT_LIBS)
libsss_crypt_la_LDFLAGS = \
    -avoid-version

if BUILD_PYTHON_BINDINGS
pyexec_LTLIBRARIES = \
    pysss.la \
    pyhbac.la \
    pysss_murmur.la \
    pysss_nss_idmap.la
endif

dist_noinst_SCRIPTS = \
    $(EXTRA_SCRIPTS) \
    src/config/setup.py \
    src/config/SSSDConfig/ipachangeconf.py \
    src/config/SSSDConfig/__init__.py \
    src/config/SSSDConfigTest.py \
    src/config/SSSDConfig/sssd_upgrade_config.py \
    contrib/rhel/update_debug_levels.py \
    contrib/fedora/bashrc_sssd \
    contrib/fedora/make_srpm.sh \
    src/tests/pyhbac-test.py \
    src/tests/pysss_murmur-test.py

dist_noinst_DATA = \
    src/config/testconfigs/sssd-valid.conf \
    src/config/testconfigs/noparse.api.conf \
    src/config/testconfigs/sssd-noversion.conf \
    src/config/testconfigs/sssd-badversion.conf \
    src/config/testconfigs/sssd-invalid.conf \
    src/config/testconfigs/sssd-invalid-badbool.conf

###############################
# Global compilation settings #
###############################

AM_CPPFLAGS = \
    -Wall \
    -Iinclude \
    -I.. \
    -I$(srcdir)/include \
    -I$(srcdir)/src/sss_client \
    -I$(srcdir)/src \
    -Iinclude \
    -I. \
    $(POPT_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(TDB_CFLAGS) \
    $(TEVENT_CFLAGS) \
    $(LDB_CFLAGS) \
    $(DBUS_CFLAGS) \
    $(PCRE_CFLAGS) \
    $(COLLECTION_CFLAGS) \
    $(INI_CONFIG_CFLAGS) \
    $(DHASH_CFLAGS) \
    $(LIBNL_CFLAGS) \
    $(OPENLDAP_CFLAGS) \
    $(GLIB2_CFLAGS) \
    $(JOURNALD_CFLAGS) \
    -DLIBDIR=\"$(libdir)\" \
    -DVARDIR=\"$(localstatedir)\" \
    -DSHLIBEXT=\"$(SHLIBEXT)\" \
    -DSSSD_LIBEXEC_PATH=\"$(sssdlibexecdir)\" \
    -DSSSD_INTROSPECT_PATH=\"$(dbusinstropectdir)\" \
    -DSSSD_CONF_DIR=\"$(sssdconfdir)\" \
    -DSSS_NSS_MCACHE_DIR=\"$(mcpath)\" \
    -DSSS_NSS_SOCKET_NAME=\"$(pipepath)/nss\" \
    -DSSS_PAM_SOCKET_NAME=\"$(pipepath)/pam\" \
    -DSSS_PAC_SOCKET_NAME=\"$(pipepath)/pac\" \
    -DSSS_PAM_PRIV_SOCKET_NAME=\"$(pipepath)/private/pam\" \
    -DSSS_SUDO_SOCKET_NAME=\"$(pipepath)/sudo\" \
    -DSSS_AUTOFS_SOCKET_NAME=\"$(pipepath)/autofs\" \
    -DSSS_SSH_SOCKET_NAME=\"$(pipepath)/ssh\" \
    -DLOCALEDIR=\"$(localedir)\"

EXTRA_DIST = build/config.rpath

SSSD_RESPONDER_OBJ = \
    src/responder/common/negcache.c \
    src/responder/common/responder_cmd.c \
    src/responder/common/responder_common.c \
    src/responder/common/responder_dp.c \
    src/responder/common/responder_packet.c \
    src/responder/common/responder_get_domains.c

SSSD_TOOLS_OBJ = \
    src/tools/sss_sync_ops.c \
    src/tools/tools_util.c \
    src/tools/files.c \
    src/tools/selinux.c \
    src/util/nscd.c

SSSD_LCL_TOOLS_OBJ = \
    src/sss_client/common.c \
    src/tools/tools_mc_util.c \
    $(SSSD_TOOLS_OBJ)

SSSD_RESOLV_OBJ = \
    src/resolv/async_resolv.c \
    src/resolv/async_resolv_utils.c
if BUILD_ARES_DATA
    SSSD_RESOLV_OBJ += \
    src/resolv/ares/ares_parse_srv_reply.c \
    src/resolv/ares/ares_data.c
endif

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
    $(PCRE_LIBS) \
    $(INI_CONFIG_LIBS) \
    $(COLLECTION_LIBS) \
    $(DHASH_LIBS) \
    $(SSS_CRYPT_LIBS) \
    $(OPENLDAP_LIBS) \
    $(TDB_LIBS)

PYTHON_BINDINGS_LIBS = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(LDB_LIBS) \
    $(DBUS_LIBS) \
    $(PCRE_LIBS) \
    $(DHASH_LIBS) \
    $(SSS_CRYPT_LIBS) \
    $(OPENLDAP_LIBS) \
    $(TDB_LIBS)

TOOLS_LIBS = \
    $(LTLIBINTL) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(LDB_LIBS) \
    $(DBUS_LIBS) \
    $(PCRE_LIBS) \
    $(INI_CONFIG_LIBS) \
    $(COLLECTION_LIBS) \
    $(DHASH_LIBS) \
    $(OPENLDAP_LIBS) \
    $(TDB_LIBS)

if BUILD_SELINUX
    PYTHON_BINDINGS_LIBS += $(SELINUX_LIBS)
    TOOLS_LIBS += $(SELINUX_LIBS)
endif
if BUILD_SEMANAGE
    PYTHON_BINDINGS_LIBS += $(SEMANAGE_LIBS)
    TOOLS_LIBS += $(SEMANAGE_LIBS)
endif

dist_noinst_HEADERS = \
    src/monitor/monitor.h \
    src/util/crypto/sss_crypto.h \
    src/util/dlinklist.h \
    src/util/util.h \
    src/util/io.h \
    src/util/util_errors.h \
    src/util/safe-format-string.h \
    src/util/strtonum.h \
    src/util/sss_endian.h \
    src/util/sss_nss.h \
    src/util/sss_ldap.h \
    src/util/sss_python.h \
    src/util/sss_krb5.h \
    src/util/sss_selinux.h \
    src/util/sss_utf8.h \
    src/util/sss_ssh.h \
    src/util/sss_ini.h \
    src/util/sss_format.h \
    src/util/refcount.h \
    src/util/find_uid.h \
    src/util/user_info_msg.h \
    src/util/murmurhash3.h \
    src/util/mmap_cache.h \
    src/util/atomic_io.h \
    src/util/auth_utils.h \
    src/util/authtok.h \
    src/util/util_safealign.h \
    src/util/util_sss_idmap.h \
    src/monitor/monitor.h \
    src/monitor/monitor_interfaces.h \
    src/responder/common/responder.h \
    src/responder/common/responder_packet.h \
    src/responder/common/responder_sbus.h \
    src/responder/pam/pamsrv.h \
    src/responder/pam/pam_helpers.h \
    src/responder/nss/nsssrv.h \
    src/responder/nss/nsssrv_private.h \
    src/responder/nss/nsssrv_netgroup.h \
    src/responder/nss/nsssrv_services.h \
    src/responder/nss/nsssrv_mmap_cache.h \
    src/responder/pac/pacsrv.h \
    src/responder/common/negcache.h \
    src/responder/sudo/sudosrv_private.h \
    src/responder/autofs/autofs_private.h \
    src/responder/ssh/sshsrv_private.h \
    src/sbus/sbus_client.h \
    src/sbus/sssd_dbus.h \
    src/sbus/sssd_dbus_private.h \
    src/db/sysdb.h \
    src/db/sysdb_sudo.h \
    src/db/sysdb_autofs.h \
    src/db/sysdb_selinux.h \
    src/db/sysdb_private.h \
    src/db/sysdb_services.h \
    src/db/sysdb_ssh.h \
    src/confdb/confdb.h \
    src/confdb/confdb_private.h \
    src/confdb/confdb_setup.h \
    src/providers/data_provider.h \
    src/providers/dp_backend.h \
    src/providers/dp_dyndns.h \
    src/providers/dp_ptask.h \
    src/providers/dp_refresh.h \
    src/providers/fail_over.h \
    src/providers/fail_over_srv.h \
    src/util/child_common.h \
    src/providers/simple/simple_access.h \
    src/providers/krb5/krb5_auth.h \
    src/providers/krb5/krb5_common.h \
    src/providers/krb5/krb5_utils.h \
    src/providers/krb5/krb5_init_shared.h \
    src/providers/krb5/krb5_opts.h \
    src/providers/ldap/ldap_common.h \
    src/providers/ldap/sdap.h \
    src/providers/ldap/sdap_access.h \
    src/providers/ldap/sdap_async.h \
    src/providers/ldap/sdap_async_private.h \
    src/providers/ldap/sdap_sudo_cache.h \
    src/providers/ldap/sdap_sudo.h \
    src/providers/ldap/sdap_autofs.h \
    src/providers/ldap/sdap_id_op.h \
    src/providers/ldap/ldap_opts.h \
    src/providers/ldap/sdap_range.h \
    src/providers/ldap/sdap_users.h \
    src/providers/ldap/sdap_dyndns.h \
    src/providers/ldap/sdap_async_enum.h \
    src/providers/ipa/ipa_common.h \
    src/providers/ipa/ipa_config.h \
    src/providers/ipa/ipa_access.h \
    src/providers/ipa/ipa_selinux.h \
    src/providers/ipa/ipa_hosts.h \
    src/providers/ipa/ipa_selinux_maps.h \
    src/providers/ipa/ipa_auth.h \
    src/providers/ipa/ipa_dyndns.h \
    src/providers/ipa/ipa_subdomains.h \
    src/providers/ipa/ipa_id.h \
    src/providers/ipa/ipa_hostid.h \
    src/providers/ipa/ipa_opts.h \
    src/providers/ipa/ipa_srv.h \
    src/providers/ad/ad_srv.h \
    src/providers/proxy/proxy.h \
    src/tools/tools_util.h \
    src/tools/sss_sync_ops.h \
    src/resolv/async_resolv.h \
    src/resolv/ares/ares_parse_srv_reply.h \
    src/resolv/ares/ares_parse_txt_reply.h \
    src/resolv/ares/ares_data.h \
    src/tests/common.h \
    src/tests/common_check.h \
    src/tests/cmocka/common_mock.h \
    src/tests/cmocka/common_mock_resp.h \
    src/sss_client/ssh/sss_ssh_client.h \
    src/sss_client/sudo/sss_sudo.h \
    src/lib/idmap/sss_idmap_private.h


if HAVE_NSS
    dist_noinst_HEADERS += src/util/crypto/nss/nss_util.h
endif

SSSD_DOCS = \
    doc \
    hbac_doc \
    idmap_doc \
    nss_idmap_doc

if BUILD_SUDO
    SSSD_DOCS += libsss_sudo_doc
endif

CLIENT_LIBS = $(LTLIBINTL)

if HAVE_PTHREAD
CLIENT_LIBS += -lpthread
endif

if WITH_JOURNALD
SYSLOG_LIBS = $(JOURNALD_LIBS)
endif

#####################
# Utility libraries #
#####################
pkglib_LTLIBRARIES += libsss_debug.la
libsss_debug_la_SOURCES = \
    src/util/debug.c \
    src/util/sss_log.c
libsss_debug_la_LIBADD = \
    $(SYSLOG_LIBS)
libsss_debug_la_LDFLAGS = \
    -avoid-version

pkglib_LTLIBRARIES += libsss_child.la
libsss_child_la_SOURCES = src/util/child_common.c
libsss_child_la_LDFLAGS = -avoid-version

pkglib_LTLIBRARIES += libsss_util.la
libsss_util_la_SOURCES = \
    src/confdb/confdb.c \
    src/db/sysdb.c \
    src/db/sysdb_ops.c \
    src/db/sysdb_search.c \
    src/db/sysdb_selinux.c \
    src/db/sysdb_upgrade.c \
    src/db/sysdb_services.c \
    src/db/sysdb_autofs.c \
    src/db/sysdb_subdomains.c \
    src/db/sysdb_ranges.c \
    src/db/sysdb_idmap.c \
    src/monitor/monitor_sbus.c \
    src/providers/dp_auth_util.c \
    src/providers/dp_pam_data_util.c \
    src/providers/dp_sbus.c \
    src/sbus/sbus_client.c \
    src/sbus/sssd_dbus_common.c \
    src/sbus/sssd_dbus_connection.c \
    src/sbus/sssd_dbus_server.c \
    src/util/util.c \
    src/util/memory.c \
    src/util/safe-format-string.c \
    src/util/server.c \
    src/util/signal.c \
    src/util/usertools.c \
    src/util/backup_file.c \
    src/util/strtonum.c \
    src/util/check_and_open.c \
    src/util/refcount.c \
    src/util/sss_nss.c \
    src/util/sss_utf8.c \
    src/util/sss_tc_utf8.c \
    src/util/murmurhash3.c \
    src/util/atomic_io.c \
    src/util/authtok.c \
    src/util/sss_selinux.c \
    src/util/domain_info_utils.c \
    src/util/util_lock.c \
    src/util/util_errors.c \
    src/util/sss_ini.c \
    src/util/io.c \
    src/util/util_sss_idmap.c \
    src/util/well_known_sids.c
libsss_util_la_LIBADD = \
    $(SSSD_LIBS) \
    $(UNICODE_LIBS)
if BUILD_SUDO
    libsss_util_la_SOURCES += src/db/sysdb_sudo.c
endif
if BUILD_SSH
libsss_util_la_SOURCES += \
    src/db/sysdb_ssh.c \
    src/util/sss_ssh.c
endif
libsss_util_la_LDFLAGS = -avoid-version

SSSD_INTERNAL_LTLIBS = \
    libsss_util.la \
    libsss_crypt.la \
    libsss_debug.la \
    libsss_child.la

lib_LTLIBRARIES = libipa_hbac.la libsss_idmap.la libsss_nss_idmap.la
dist_pkgconfig_DATA += src/providers/ipa/ipa_hbac.pc
libipa_hbac_la_SOURCES = \
    src/providers/ipa/hbac_evaluator.c \
    src/util/sss_utf8.c
libipa_hbac_la_LIBADD = \
    $(UNICODE_LIBS)
libipa_hbac_la_LDFLAGS = \
    -version-info 0:1:0

dist_pkgconfig_DATA += src/lib/idmap/sss_idmap.pc
libsss_idmap_la_SOURCES = \
    src/lib/idmap/sss_idmap.c \
    src/lib/idmap/sss_idmap_conv.c \
    src/util/murmurhash3.c
libsss_idmap_la_LDFLAGS = \
    -version-info 3:0:3

dist_pkgconfig_DATA += src/sss_client/idmap/sss_nss_idmap.pc
libsss_nss_idmap_la_SOURCES = \
    src/sss_client/idmap/sss_nss_idmap.c \
    src/sss_client/common.c \
    src/util/strtonum.c
libsss_nss_idmap_la_LIBADD = \
    $(CLIENT_LIBS)
libsss_nss_idmap_la_LDFLAGS = \
    -version-info 0:1:0

include_HEADERS = \
    src/providers/ipa/ipa_hbac.h \
    src/lib/idmap/sss_idmap.h \
    src/sss_client/idmap/sss_nss_idmap.h

####################
# Program Binaries #
####################
sssd_SOURCES = \
    src/monitor/monitor.c \
    src/monitor/monitor_netlink.c \
    src/confdb/confdb_setup.c \
    src/util/nscd.c
sssd_LDADD = \
    $(SSSD_LIBS) \
    $(INOTIFY_LIBS) \
    $(LIBNL_LIBS) \
    $(KEYUTILS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)

sssd_nss_SOURCES = \
    src/responder/nss/nsssrv.c \
    src/responder/nss/nsssrv_cmd.c \
    src/responder/nss/nsssrv_netgroup.c \
    src/responder/nss/nsssrv_services.c \
    src/responder/nss/nsssrv_mmap_cache.c \
    $(SSSD_RESPONDER_OBJ)
sssd_nss_LDADD = \
    $(TDB_LIBS) \
    $(SSSD_LIBS) \
    libsss_idmap.la \
    $(SSSD_INTERNAL_LTLIBS)

sssd_pam_SOURCES = \
    src/responder/pam/pam_LOCAL_domain.c \
    src/responder/pam/pamsrv.c \
    src/responder/pam/pamsrv_cmd.c \
    src/responder/pam/pamsrv_dp.c \
    src/responder/pam/pam_helpers.c \
    $(SSSD_RESPONDER_OBJ)
sssd_pam_LDADD = \
    $(TDB_LIBS) \
    $(SSSD_LIBS) \
    $(SELINUX_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)

if BUILD_SUDO
sssd_sudo_SOURCES = \
    src/responder/sudo/sudosrv.c \
    src/responder/sudo/sudosrv_cmd.c \
    src/responder/sudo/sudosrv_get_sudorules.c \
    src/responder/sudo/sudosrv_query.c \
    src/responder/sudo/sudosrv_dp.c \
    $(SSSD_RESPONDER_OBJ)
sssd_sudo_LDADD = \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)
endif

if BUILD_AUTOFS
sssd_autofs_SOURCES = \
    src/responder/autofs/autofssrv.c \
    src/responder/autofs/autofssrv_cmd.c \
    src/responder/autofs/autofssrv_dp.c \
    $(SSSD_RESPONDER_OBJ)
sssd_autofs_LDADD = \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)
endif

if BUILD_SSH
sssd_ssh_SOURCES = \
    src/responder/ssh/sshsrv.c \
    src/responder/ssh/sshsrv_dp.c \
    src/responder/ssh/sshsrv_cmd.c \
    $(SSSD_RESPONDER_OBJ)
sssd_ssh_LDADD = \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)
endif

sssd_pac_SOURCES = \
    src/responder/pac/pacsrv.c \
    src/responder/pac/pacsrv_cmd.c \
    src/responder/pac/pacsrv_utils.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_RESPONDER_OBJ)
sssd_pac_CFLAGS = \
    $(AM_CFLAGS) \
    $(NDR_KRB5PAC_CFLAGS)
sssd_pac_LDADD = \
    $(NDR_KRB5PAC_LIBS) \
    $(TDB_LIBS) \
    $(SSSD_LIBS) \
    libsss_idmap.la \
    $(SSSD_INTERNAL_LTLIBS)

sssd_be_SOURCES = \
    src/providers/data_provider_be.c \
    src/providers/data_provider_fo.c \
    src/providers/data_provider_opts.c \
    src/providers/data_provider_callbacks.c \
    src/providers/dp_dyndns.c \
    src/providers/dp_ptask.c \
    src/providers/dp_refresh.c \
    $(SSSD_FAILOVER_OBJ)
sssd_be_LDADD = \
    $(LIBADD_DL) \
    $(SSSD_LIBS) \
    $(CARES_LIBS) \
    $(PAM_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)
sssd_be_LDFLAGS = \
    -Wl,--version-script,$(srcdir)/src/providers/sssd_be.exports \
    -export-dynamic

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

######################
# Command-line Tools #
######################
sss_useradd_SOURCES = \
    src/tools/sss_useradd.c \
    $(SSSD_TOOLS_OBJ)
sss_useradd_LDADD = \
    $(TOOLS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)

sss_userdel_SOURCES = \
    src/tools/sss_userdel.c \
    src/util/find_uid.c \
    $(SSSD_LCL_TOOLS_OBJ)
sss_userdel_LDADD = \
    $(TOOLS_LIBS) \
    $(SYSTEMD_LOGIN_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(CLIENT_LIBS)
sss_userdel_CFLAGS = \
    $(AM_CFLAGS) \
    $(SYSTEMD_LOGIN_CFLAGS)

sss_groupadd_SOURCES = \
    src/tools/sss_groupadd.c \
    $(SSSD_TOOLS_OBJ)
sss_groupadd_LDADD = \
    $(TOOLS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)

sss_groupdel_SOURCES = \
    src/tools/sss_groupdel.c \
    $(SSSD_LCL_TOOLS_OBJ)
sss_groupdel_LDADD = \
    $(TOOLS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(CLIENT_LIBS)
sss_groupdel_CFLAGS = $(AM_CFLAGS)

sss_usermod_SOURCES = \
    src/tools/sss_usermod.c \
    $(SSSD_LCL_TOOLS_OBJ)
sss_usermod_LDADD = \
    $(TOOLS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(CLIENT_LIBS)
sss_usermod_CFLAGS = $(AM_CFLAGS)

sss_groupmod_SOURCES = \
    src/tools/sss_groupmod.c \
    $(SSSD_LCL_TOOLS_OBJ)
sss_groupmod_LDADD = \
    $(TOOLS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(CLIENT_LIBS)
sss_groupmod_CFLAGS = $(AM_CFLAGS)

sss_groupshow_SOURCES = \
    src/tools/sss_groupshow.c \
    $(SSSD_TOOLS_OBJ)
sss_groupshow_LDADD = \
    $(TOOLS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)

sss_cache_SOURCES = \
    src/tools/sss_cache.c \
    $(SSSD_LCL_TOOLS_OBJ)
sss_cache_LDADD = \
    $(TOOLS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(CLIENT_LIBS)
sss_cache_CFLAGS = $(AM_CFLAGS)

sss_debuglevel_SOURCES = \
    src/tools/sss_debuglevel.c \
    $(SSSD_TOOLS_OBJ)
sss_debuglevel_LDADD = \
    $(TOOLS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)

sss_seed_SOURCES = \
    src/tools/sss_seed.c \
    $(SSSD_TOOLS_OBJ)
sss_seed_LDADD = \
    $(TOOLS_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)

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

sss_ssh_knownhostsproxy_SOURCES = \
    src/sss_client/common.c \
    src/sss_client/ssh/sss_ssh_client.c \
    src/sss_client/ssh/sss_ssh_knownhostsproxy.c
sss_ssh_knownhostsproxy_CFLAGS = $(AM_CFLAGS)
sss_ssh_knownhostsproxy_LDADD = \
    $(SSSD_INTERNAL_LTLIBS) \
    $(CLIENT_LIBS) $(TALLOC_LIBS) $(POPT_LIBS)
endif

#################
# Feature Tests #
#################
TESTS_ENVIRONMENT = LDB_MODULES_PATH=$(abs_top_builddir)/ldb_mod_test_dir

ldb_mod_test_dir: memberof.la
	mkdir -p $(builddir)/ldb_mod_test_dir
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
    $(TEVENT_LIBS)

if HAVE_CHECK
libsss_test_common_la_SOURCES += \
    src/tests/common_check.c

check_LTLIBRARIES += \
    libdlopen_test_providers.la

libdlopen_test_providers_la_SOURCES = \
    $(sssd_be_SOURCES)
libdlopen_test_providers_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS) \
    -DUNIT_TESTING
libdlopen_test_providers_la_LIBADD = \
    $(PAM_LIBS) \
    $(SSSD_LIBS) \
    $(CARES_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)
libdlopen_test_providers_la_LDFLAGS = \
    -module \
    -avoid-version \
    -Wl,--version-script,$(srcdir)/src/providers/sssd_be.exports \
    -rpath $(abs_top_builddir) \
    -export-dynamic

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
    src/providers/krb5/krb5_become_user.c \
    src/providers/krb5/krb5_common.c \
    src/util/sss_krb5.c \
    src/util/find_uid.c \
    src/providers/data_provider_fo.c \
    src/providers/data_provider_opts.c \
    src/providers/data_provider_callbacks.c \
    $(SSSD_FAILOVER_OBJ)
krb5_utils_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS) \
    $(SYSTEMD_LOGIN_CFLAGS)
krb5_utils_tests_LDADD = \
    $(SSSD_LIBS)\
    $(CARES_LIBS) \
    $(KRB5_LIBS) \
    $(CHECK_LIBS) \
    $(SYSTEMD_LOGIN_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la


check_and_open_tests_SOURCES = \
    src/tests/check_and_open-tests.c \
    src/util/check_and_open.c
check_and_open_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
check_and_open_tests_LDADD = \
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
if BUILD_SEMANAGE
    FILES_TESTS_LIBS += $(SEMANAGE_LIBS)
endif

files_tests_SOURCES = \
    src/tests/files-tests.c \
    src/util/check_and_open.c \
    src/util/atomic_io.c \
    src/tools/selinux.c \
    src/tools/files.c
files_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
files_tests_LDADD = \
    $(FILES_TESTS_LIBS) \
    libsss_test_common.la \
    $(SSSD_INTERNAL_LTLIBS)

SSSD_RESOLV_TESTS_OBJ = \
    $(SSSD_RESOLV_OBJ)
if BUILD_ARES_DATA
    SSSD_RESOLV_TESTS_OBJ += \
    src/resolv/ares/ares_parse_txt_reply.c
endif

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

refcount_tests_SOURCES = \
    src/tests/refcount-tests.c \
    $(CHECK_OBJ)
refcount_tests_CFLAGS = \
    $(CHECK_CFLAGS)
refcount_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

fail_over_tests_SOURCES = \
    src/tests/fail_over-tests.c \
    $(SSSD_FAILOVER_OBJ) \
    $(CHECK_OBJ)
fail_over_tests_CFLAGS = \
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
    $(CHECK_CFLAGS) \
    $(SYSTEMD_LOGIN_CFLAGS)
find_uid_tests_LDADD = \
    libsss_debug.la \
    $(TALLOC_LIBS) \
    $(DHASH_LIBS) \
    $(CHECK_LIBS) \
    $(SYSTEMD_LOGIN_LIBS) \
    libsss_test_common.la

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
    src/tests/ipa_ldap_opt-tests.c
ipa_ldap_opt_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
ipa_ldap_opt_tests_LDADD = \
    $(CHECK_LIBS) \
    $(TALLOC_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

ad_ldap_opt_tests_SOURCES = \
    src/tests/ad_ldap_opt-tests.c
ad_ldap_opt_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
ad_ldap_opt_tests_LDADD = \
    $(CHECK_LIBS) \
    $(TALLOC_LIBS) \
    libsss_test_common.la

simple_access_tests_SOURCES = \
    src/tests/simple_access-tests.c \
    src/providers/simple/simple_access.c \
    src/providers/simple/simple_access_check.c \
    src/providers/data_provider_be.c \
    src/providers/data_provider_fo.c \
    src/providers/data_provider_opts.c \
    src/providers/data_provider_callbacks.c \
    src/providers/dp_ptask.c \
    src/providers/dp_refresh.c \
    $(SSSD_FAILOVER_OBJ)
simple_access_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS) \
    -DUNIT_TESTING
simple_access_tests_LDADD = \
    $(LIBADD_DL) \
    $(SSSD_LIBS) \
    $(CARES_LIBS) \
    $(CHECK_LIBS) \
    $(PAM_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

util_tests_SOURCES = \
    src/tests/util-tests.c
util_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
util_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

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
    $(SSS_CRYPT_SOURCES) \
    src/tests/crypto-tests.c
crypto_tests_CFLAGS = \
    $(SSS_CRYPT_CFLAGS) \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
crypto_tests_LDADD = \
    libsss_debug.la \
    $(SSS_CRYPT_LIBS) \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
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
    src/responder/common/responder_common.c \
    src/responder/common/responder_packet.c \
    src/responder/common/responder_cmd.c
responder_socket_access_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
responder_socket_access_tests_LDADD = \
    $(CHECK_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la
endif

stress_tests_SOURCES = \
    src/tests/stress-tests.c
stress_tests_LDADD = \
    $(SSSD_LIBS) \
    libsss_test_common.la

krb5_child_test_SOURCES = \
    src/tests/krb5_child-test.c \
    src/providers/krb5/krb5_utils.c \
    src/providers/krb5/krb5_child_handler.c \
    src/providers/krb5/krb5_become_user.c \
    src/providers/krb5/krb5_common.c \
    src/util/sss_krb5.c \
    src/util/find_uid.c \
    src/providers/data_provider_fo.c \
    src/providers/data_provider_opts.c \
    src/providers/data_provider_callbacks.c \
    $(SSSD_FAILOVER_OBJ)
krb5_child_test_CFLAGS = \
    $(AM_CFLAGS) \
    -DKRB5_CHILD_DIR=\"$(builddir)\" \
    $(CHECK_CFLAGS) \
    $(SYSTEMD_LOGIN_CFLAGS)
krb5_child_test_LDADD = \
    $(SSSD_LIBS) \
    $(CARES_LIBS) \
    $(KRB5_LIBS) \
    $(CHECK_LIBS) \
    $(SYSTEMD_LOGIN_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

if HAVE_CMOCKA

TEST_MOCK_RESP_OBJ = \
     src/tests/cmocka/common_mock_resp.c \
     src/responder/common/responder_packet.c \
     src/responder/common/responder_cmd.c \
     src/responder/common/negcache.c \
     src/responder/common/responder_common.c

EXTRA_nss_srv_tests_DEPENDENCIES = \
     $(ldblib_LTLIBRARIES)
nss_srv_tests_SOURCES = \
     $(TEST_MOCK_RESP_OBJ) \
     src/tests/cmocka/test_nss_srv.c \
     src/responder/nss/nsssrv_cmd.c \
     src/responder/nss/nsssrv_netgroup.c \
     src/responder/nss/nsssrv_services.c \
     src/responder/nss/nsssrv_mmap_cache.c
nss_srv_tests_CFLAGS = \
    $(AM_CFLAGS)
nss_srv_tests_LDFLAGS = \
    -Wl,-wrap,sss_ncache_check_user \
    -Wl,-wrap,sss_packet_get_body \
    -Wl,-wrap,sss_packet_get_cmd \
    -Wl,-wrap,sss_cmd_send_empty \
    -Wl,-wrap,sss_cmd_done
nss_srv_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la \
    libsss_idmap.la

test_find_uid_SOURCES = \
    src/tests/cmocka/test_find_uid.c \
    src/util/find_uid.c \
    src/util/atomic_io.c \
    src/util/strtonum.c
test_find_uid_CFLAGS = \
    $(AM_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(DHASH_CFLAGS) \
    $(SYSTEMD_LOGIN_CFLAGS)
test_find_uid_LDADD = \
    $(TALLOC_LIBS) \
    $(DHASH_LIBS) \
    $(CMOCKA_LIBS) \
    $(SYSTEMD_LOGIN_LIBS) \
    libsss_debug.la

test_io_SOURCES = \
    src/tests/cmocka/test_io.c \
    src/util/io.c \
    src/tests/common.c
test_io_CFLAGS = \
    $(AM_CFLAGS)
test_io_LDADD = \
    $(CMOCKA_LIBS)

test_authtok_SOURCES = \
    src/tests/cmocka/test_authtok.c \
    src/util/authtok.c \
    src/util/util.c
test_authtok_CFLAGS = \
    $(AM_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(DHASH_CFLAGS)
test_authtok_LDADD = \
    $(TALLOC_LIBS) \
    $(CMOCKA_LIBS) \
    $(DHASH_LIBS) \
    libsss_debug.la

sss_nss_idmap_tests_SOURCES = \
    src/tests/cmocka/sss_nss_idmap-tests.c
sss_nss_idmap_tests_CFLAGS = \
    $(AM_CFLAGS)
sss_nss_idmap_tests_LDADD = \
    $(CMOCKA_LIBS) \
    libsss_nss_idmap.la

EXTRA_dyndns_tests_DEPENDENCIES = \
     $(ldblib_LTLIBRARIES)
dyndns_tests_SOURCES = \
     $(SSSD_RESOLV_OBJ) \
     src/tests/cmocka/test_dyndns.c \
     src/providers/data_provider_opts.c
dyndns_tests_CFLAGS = \
    $(AM_CFLAGS) \
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

fqnames_tests_SOURCES = \
    src/tests/cmocka/test_fqnames.c
fqnames_tests_CFLAGS = \
    $(AM_CFLAGS)
fqnames_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

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

test_utils_SOURCES = \
    src/tests/cmocka/test_utils.c
test_utils_CFLAGS = \
    $(AM_CFLAGS)
test_utils_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    libsss_test_common.la

test_search_bases_SOURCES = \
    $(sssd_be_SOURCES) \
    src/util/sss_ldap.c \
    src/util/sss_krb5.c \
    src/util/find_uid.c \
    src/util/user_info_msg.c \
    src/tests/cmocka/test_search_bases.c
test_search_bases_CFLAGS = \
    $(AM_CFLAGS) \
    -DUNIT_TESTING
test_search_bases_LDADD = \
    $(PAM_LIBS) \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(SSSD_LIBS) \
    $(CARES_LIBS) \
    $(KRB5_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(SYSTEMD_LOGIN_LIBS) \
    libsss_ldap_common.la \
    libsss_idmap.la \
    libsss_krb5_common.la \
    libsss_test_common.la

ad_access_filter_tests_SOURCES = \
    $(sssd_be_SOURCES) \
    src/util/sss_ldap.c \
    src/util/sss_krb5.c \
    src/util/find_uid.c \
    src/util/user_info_msg.c \
    src/providers/ad/ad_common.c \
    src/tests/cmocka/test_ad_access_filter.c
ad_access_filter_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(SYSTEMD_LOGIN_CFLAGS) \
    -DUNIT_TESTING
ad_access_filter_tests_LDADD = \
    $(PAM_LIBS) \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(CARES_LIBS) \
    $(KRB5_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(SYSTEMD_LOGIN_LIBS) \
    libsss_ldap_common.la \
    libsss_idmap.la \
    libsss_krb5_common.la \
    libsss_test_common.la

ad_common_tests_SOURCES = \
    $(sssd_be_SOURCES) \
    src/util/sss_ldap.c \
    src/util/sss_krb5.c \
    src/util/find_uid.c \
    src/util/user_info_msg.c \
    src/tests/cmocka/test_ad_common.c
ad_common_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(SYSTEMD_LOGIN_CFLAGS) \
    -DUNIT_TESTING
ad_common_tests_LDFLAGS = \
    -Wl,-wrap,sdap_set_sasl_options
ad_common_tests_LDADD = \
    $(PAM_LIBS) \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(CARES_LIBS) \
    $(KRB5_LIBS) \
    $(SSSD_INTERNAL_LTLIBS) \
    $(SYSTEMD_LOGIN_LIBS) \
    libsss_ldap_common.la \
    libsss_idmap.la \
    libsss_krb5_common.la \
    libsss_test_common.la

endif

noinst_PROGRAMS = pam_test_client
if BUILD_SUDO
noinst_PROGRAMS += sss_sudo_cli
endif
if BUILD_AUTOFS
noinst_PROGRAMS += autofs_test_client
endif

pam_test_client_SOURCES = src/sss_client/pam_test_client.c
pam_test_client_LDADD = -lpam -lpam_misc

if BUILD_AUTOFS
autofs_test_client_SOURCES = \
    src/sss_client/autofs/autofs_test_client.c \
    src/sss_client/autofs/sss_autofs.c \
    src/sss_client/common.c
autofs_test_client_CFLAGS = $(AM_CFLAGS)
autofs_test_client_LDADD = -lpopt $(CLIENT_LIBS)
endif

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
    src/sss_client/sss_cli.h \
    src/sss_client/nss_compat.h \
    src/sss_client/nss_mc_common.c \
    src/util/io.c \
    src/util/murmurhash3.c \
    src/sss_client/nss_mc_passwd.c \
    src/sss_client/nss_mc_group.c \
    src/sss_client/nss_mc.h
libnss_sss_la_LIBADD = \
    $(CLIENT_LIBS)
libnss_sss_la_LDFLAGS = \
    -module \
    -version-info 2:0:0 \
    -Wl,--version-script,$(srcdir)/src/sss_client/sss_nss.exports

pamlib_LTLIBRARIES = pam_sss.la
pam_sss_la_SOURCES = \
    src/sss_client/pam_sss.c \
    src/sss_client/common.c \
    src/sss_client/sss_cli.h \
    src/util/atomic_io.c \
    src/sss_client/sss_pam_macros.h

pam_sss_la_LIBADD = \
    $(CLIENT_LIBS) \
    -lpam
pam_sss_la_LDFLAGS = \
    -module \
    -avoid-version \
    -Wl,--version-script,$(srcdir)/src/sss_client/sss_pam.exports

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

dist_noinst_DATA += \
    src/sss_client/sss_nss.exports \
    src/sss_client/sss_pam.exports
if BUILD_SUDO
dist_noinst_DATA += src/sss_client/sss_sudo.exports
endif

if BUILD_AUTOFS
dist_noinst_DATA += src/sss_client/autofs/sss_autofs.exports
endif

####################
# Plugin Libraries #
####################

pkglib_LTLIBRARIES += libsss_ldap_common.la
libsss_ldap_common_la_SOURCES = \
    src/providers/ldap/ldap_id.c \
    src/providers/ldap/ldap_id_enum.c \
    src/providers/ldap/sdap_async_enum.c \
    src/providers/ldap/ldap_id_cleanup.c \
    src/providers/ldap/ldap_id_netgroup.c \
    src/providers/ldap/ldap_id_services.c \
    src/providers/ldap/ldap_auth.c \
    src/providers/ldap/ldap_common.c \
    src/providers/ldap/sdap_access.c \
    src/providers/ldap/sdap_async.c \
    src/providers/ldap/sdap_async_users.c \
    src/providers/ldap/sdap_async_groups.c \
    src/providers/ldap/sdap_async_nested_groups.c \
    src/providers/ldap/sdap_async_groups_ad.c \
    src/providers/ldap/sdap_async_initgroups.c \
    src/providers/ldap/sdap_async_initgroups_ad.c \
    src/providers/ldap/sdap_async_connection.c \
    src/providers/ldap/sdap_async_netgroups.c \
    src/providers/ldap/sdap_async_services.c \
    src/providers/ldap/sdap_child_helpers.c \
    src/providers/ldap/sdap_fd_events.c \
    src/providers/ldap/sdap_id_op.c \
    src/providers/ldap/sdap_idmap.c \
    src/providers/ldap/sdap_idmap.h \
    src/providers/ldap/sdap_range.c \
    src/providers/ldap/sdap_reinit.c \
    src/providers/ldap/sdap_dyndns.c \
    src/providers/ldap/sdap_refresh.c \
    src/providers/ldap/sdap.c
libsss_ldap_common_la_LDFLAGS = \
    -avoid-version

if BUILD_SUDO
libsss_ldap_common_la_SOURCES += \
    src/providers/ldap/sdap_sudo_cache.c \
    src/providers/ldap/sdap_async_sudo.c \
    src/providers/ldap/sdap_async_sudo_timer.c \
    src/providers/ldap/sdap_async_sudo_hostinfo.c \
    src/providers/ldap/sdap_sudo.c
endif

if BUILD_AUTOFS
libsss_ldap_common_la_SOURCES += \
    src/providers/ldap/sdap_autofs.c \
    src/providers/ldap/sdap_async_autofs.c
endif


pkglib_LTLIBRARIES += libsss_krb5_common.la
libsss_krb5_common_la_SOURCES = \
    src/providers/krb5/krb5_utils.c \
    src/providers/krb5/krb5_become_user.c \
    src/providers/krb5/krb5_delayed_online_authentication.c \
    src/providers/krb5/krb5_renew_tgt.c \
    src/providers/krb5/krb5_wait_queue.c \
    src/providers/krb5/krb5_common.c \
    src/providers/krb5/krb5_auth.c \
    src/providers/krb5/krb5_access.c \
    src/providers/krb5/krb5_child_handler.c \
    src/providers/krb5/krb5_init_shared.c
libsss_krb5_common_la_LDFLAGS = \
    -avoid-version

libsss_ldap_la_SOURCES = \
    src/util/find_uid.c \
    src/providers/ldap/ldap_init.c \
    src/providers/ldap/ldap_access.c \
    src/providers/krb5/krb5_common.c \
    src/providers/krb5/krb5_utils.c \
    src/providers/krb5/krb5_become_user.c \
    src/util/user_info_msg.c \
    src/util/sss_ldap.c \
    src/util/sss_krb5.c
libsss_ldap_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(SYSTEMD_LOGIN_CFLAGS) \
    $(OPENLDAP_CFLAGS) \
    $(KRB5_CFLAGS)
libsss_ldap_la_LIBADD = \
    $(OPENLDAP_LIBS) \
    $(DHASH_LIBS) \
    $(KRB5_LIBS) \
    $(SYSTEMD_LOGIN_LIBS) \
    libsss_ldap_common.la \
    libsss_idmap.la
libsss_ldap_la_LDFLAGS = \
    -avoid-version \
    -module


libsss_proxy_la_SOURCES = \
    src/providers/proxy/proxy_init.c \
    src/providers/proxy/proxy_id.c \
    src/providers/proxy/proxy_netgroup.c \
    src/providers/proxy/proxy_services.c \
    src/providers/proxy/proxy_auth.c
libsss_proxy_la_CFLAGS = \
    $(AM_CFLAGS)
libsss_proxy_la_LIBADD = \
    $(PAM_LIBS)
libsss_proxy_la_LDFLAGS = \
    -avoid-version \
    -module

libsss_simple_la_SOURCES = \
    src/providers/simple/simple_access_check.c \
    src/providers/simple/simple_access.c
libsss_simple_la_CFLAGS = \
    $(AM_CFLAGS)
libsss_simple_la_LIBADD = \
    $(PAM_LIBS)
libsss_simple_la_LDFLAGS = \
    -avoid-version \
    -module

libsss_krb5_la_SOURCES = \
    src/providers/krb5/krb5_init.c \
    src/util/find_uid.c \
    src/util/sss_krb5.c
libsss_krb5_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(SYSTEMD_LOGIN_CFLAGS) \
    $(DHASH_CFLAGS)
libsss_krb5_la_LIBADD = \
    $(SYSTEMD_LOGIN_LIBS) \
    $(DHASH_LIBS) \
    $(KEYUTILS_LIBS) \
    $(KRB5_LIBS) \
    libsss_krb5_common.la
libsss_krb5_la_LDFLAGS = \
    -avoid-version \
    -module

libsss_ipa_la_SOURCES = \
    src/providers/ipa/ipa_init.c \
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
    src/providers/ipa/ipa_subdomains_ext_groups.c \
    src/providers/ipa/ipa_s2n_exop.c \
    src/providers/ipa/ipa_hbac_hosts.c \
    src/providers/ipa/ipa_hbac_private.h \
    src/providers/ipa/ipa_hbac_rules.c \
    src/providers/ipa/ipa_hbac_rules.h \
    src/providers/ipa/ipa_hbac_services.c \
    src/providers/ipa/ipa_hbac_users.c \
    src/providers/ipa/ipa_hbac_common.c \
    src/providers/ipa/ipa_selinux.c \
    src/providers/ipa/ipa_selinux_maps.c \
    src/providers/ipa/ipa_srv.c \
    src/providers/ipa/ipa_idmap.c \
    src/providers/ad/ad_common.c \
    src/providers/ad/ad_common.h \
    src/providers/ad/ad_dyndns.c \
    src/providers/ad/ad_id.c \
    src/providers/ad/ad_srv.c \
    src/providers/ad/ad_domain_info.c \
    src/util/user_info_msg.c \
    src/util/find_uid.c \
    src/util/sss_ldap.c \
    src/util/sss_krb5.c
libsss_ipa_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(SYSTEMD_LOGIN_CFLAGS) \
    $(OPENLDAP_CFLAGS) \
    $(DHASH_CFLAGS) \
    $(NDR_NBT_CFLAGS) \
    $(KRB5_CFLAGS)
libsss_ipa_la_LIBADD = \
    $(SYSTEMD_LOGIN_LIBS) \
    $(OPENLDAP_LIBS) \
    $(DHASH_LIBS) \
    $(NDR_NBT_LIBS) \
    $(KEYUTILS_LIBS) \
    $(KRB5_LIBS) \
    libsss_ldap_common.la \
    libsss_krb5_common.la \
    libipa_hbac.la \
    libsss_idmap.la
libsss_ipa_la_LDFLAGS = \
    -avoid-version \
    -module
if BUILD_AUTOFS
libsss_ipa_la_SOURCES += \
    src/providers/ipa/ipa_autofs.c
endif

if BUILD_SUDO
libsss_ipa_la_SOURCES += \
    src/providers/ipa/ipa_sudo.c
endif

if BUILD_SSH
libsss_ipa_la_SOURCES += src/providers/ipa/ipa_hostid.c
endif


libsss_ad_la_SOURCES = \
    src/providers/ad/ad_common.c \
    src/providers/ad/ad_common.h \
    src/providers/ad/ad_init.c \
    src/providers/ad/ad_dyndns.c \
    src/providers/ad/ad_id.c \
    src/providers/ad/ad_id.h \
    src/providers/ad/ad_access.c \
    src/providers/ad/ad_access.h \
    src/providers/ad/ad_opts.h \
    src/providers/ad/ad_srv.c \
    src/providers/ad/ad_subdomains.c \
    src/providers/ad/ad_subdomains.h \
    src/providers/ad/ad_domain_info.c \
    src/providers/ad/ad_domain_info.h \
    src/util/find_uid.c \
    src/util/user_info_msg.c \
    src/util/sss_krb5.c \
    src/util/sss_ldap.c

libsss_ad_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(SYSTEMD_LOGIN_CFLAGS) \
    $(OPENLDAP_CFLAGS) \
    $(SASL_CFLAGS) \
    $(DHASH_CFLAGS) \
    $(KRB5_CFLAGS) \
    $(NDR_NBT_CFLAGS)
libsss_ad_la_LIBADD = \
    $(SYSTEMD_LOGIN_LIBS) \
    $(OPENLDAP_LIBS) \
    $(SASL_LIBS) \
    $(DHASH_LIBS) \
    $(KEYUTILS_LIBS) \
    $(KRB5_LIBS) \
    $(NDR_NBT_LIBS) \
    libsss_ldap_common.la \
    libsss_krb5_common.la \
    libsss_idmap.la
libsss_ad_la_LDFLAGS = \
    -avoid-version \
    -module

krb5_child_SOURCES = \
    src/providers/krb5/krb5_become_user.c \
    src/providers/krb5/krb5_child.c \
    src/providers/dp_pam_data_util.c \
    src/util/user_info_msg.c \
    src/util/sss_krb5.c \
    src/util/atomic_io.c \
    src/util/authtok.c \
    src/util/util.c \
    src/util/signal.c \
    src/sss_client/common.c
krb5_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS) \
    $(KRB5_CFLAGS)
krb5_child_LDADD = \
    libsss_debug.la \
    libsss_child.la \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(DHASH_LIBS) \
    $(KRB5_LIBS) \
    $(CLIENT_LIBS)

ldap_child_SOURCES = \
    src/providers/ldap/ldap_child.c \
    src/util/sss_krb5.c \
    src/util/atomic_io.c \
    src/util/authtok.c \
    src/util/util.c \
    src/util/signal.c
ldap_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS) \
    $(KRB5_CFLAGS)
ldap_child_LDADD = \
    libsss_debug.la \
    libsss_child.la \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(OPENLDAP_LIBS) \
    $(DHASH_LIBS) \
    $(KRB5_LIBS)

proxy_child_SOURCES = \
    src/providers/proxy/proxy_child.c
proxy_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS)
proxy_child_LDADD = \
    $(PAM_LIBS) \
    $(SSSD_LIBS) \
    $(SSSD_INTERNAL_LTLIBS)

memberof_la_SOURCES = \
    src/ldb_modules/memberof.c \
    src/util/util.c
memberof_la_CFLAGS = \
    $(AM_CFLAGS)
memberof_la_LIBADD = \
    libsss_debug.la \
    $(LDB_LIBS) \
    $(DHASH_LIBS)
memberof_la_LDFLAGS = \
    -avoid-version \
    -module

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
    -lkrb5
sssd_pac_plugin_la_LDFLAGS = \
    -avoid-version \
    -module

if BUILD_PYTHON_BINDINGS
pysss_la_SOURCES = \
    $(SSSD_TOOLS_OBJ) \
    src/python/pysss.c
pysss_la_CFLAGS = \
    $(AM_CFLAGS)  \
    $(PYTHON_CFLAGS)
pysss_la_LIBADD = \
    $(SSSD_INTERNAL_LTLIBS) \
    $(PYTHON_BINDINGS_LIBS) \
    $(PYTHON_LIBS)
pysss_la_LDFLAGS = \
    -avoid-version \
    -module

pyhbac_la_SOURCES = \
    src/python/pyhbac.c \
    src/util/sss_python.c
pyhbac_la_CFLAGS = \
    $(AM_CFLAGS)  \
    $(PYTHON_CFLAGS)
pyhbac_la_LIBADD = \
    $(PYTHON_LIBS) \
    libipa_hbac.la
pyhbac_la_LDFLAGS = \
    -avoid-version \
    -module

pysss_murmur_la_SOURCES = \
    src/python/pysss_murmur.c \
    src/util/murmurhash3.c
pysss_murmur_la_CFLAGS = \
    $(AM_CFLAGS)  \
    $(PYTHON_CFLAGS)
pysss_murmur_la_LIBADD = \
    $(PYTHON_LIBS)
pysss_murmur_la_LDFLAGS = \
    -avoid-version \
    -module

pysss_nss_idmap_la_SOURCES = \
    src/python/pysss_nss_idmap.c
pysss_nss_idmap_la_CFLAGS = \
    $(AM_CFLAGS)  \
    $(PYTHON_CFLAGS)
pysss_nss_idmap_la_LIBADD = \
    $(PYTHON_LIBS) \
    libsss_nss_idmap.la
pysss_nss_idmap_la_LDFLAGS = \
    -avoid-version \
    -module
endif

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

dist_init_SCRIPTS =
dist_systemdunit_DATA =
if HAVE_SYSTEMD_UNIT
    dist_systemdunit_DATA += \
        src/sysv/systemd/sssd.service
else
if HAVE_SUSE
    dist_init_SCRIPTS += \
        src/sysv/SUSE/sssd
else
if HAVE_GENTOO
    dist_init_SCRIPTS += \
        src/sysv/gentoo/sssd
else
    dist_init_SCRIPTS += \
        src/sysv/sssd
endif
endif
endif


dist_sssddata_DATA = \
    src/config/etc/sssd.api.conf
dist_sssdapiplugin_DATA = \
    src/config/etc/sssd.api.d/sssd-ipa.conf \
    src/config/etc/sssd.api.d/sssd-ad.conf \
    src/config/etc/sssd.api.d/sssd-krb5.conf \
    src/config/etc/sssd.api.d/sssd-ldap.conf \
    src/config/etc/sssd.api.d/sssd-local.conf \
    src/config/etc/sssd.api.d/sssd-proxy.conf \
    src/config/etc/sssd.api.d/sssd-simple.conf

installsssddirs::
	mkdir -p \
    $(DESTDIR)$(includedir) \
    $(DESTDIR)$(libdir) \
    $(DESTDIR)$(bindir) \
    $(DESTDIR)$(sbindir) \
    $(DESTDIR)$(mandir) \
    $(DESTDIR)$(pluginpath) \
    $(DESTDIR)$(libdir)/ldb \
    $(DESTDIR)$(dbusintrospectdir) \
    $(DESTDIR)$(pipepath)/private \
    $(DESTDIR)$(sssdlibdir) \
    $(DESTDIR)$(pkglibdir) \
    $(DESTDIR)$(sssdconfdir) \
    $(DESTDIR)$(sssddatadir) \
    $(DESTDIR)$(dbpath) \
    $(DESTDIR)$(mcpath) \
    $(DESTDIR)$(pidpath) \
    $(DESTDIR)$(logpath) \
    $(DESTDIR)$(pubconfpath) \
    $(DESTDIR)$(pubconfpath)/krb5.include.d \
    $(DESTDIR)$(sudolibdir) \
    $(DESTDIR)$(autofslibdir)

if HAVE_DOXYGEN
docs:
	$(DOXYGEN) src/doxy.config
	$(DOXYGEN) src/providers/ipa/ipa_hbac.doxy
	$(DOXYGEN) src/lib/idmap/sss_idmap.doxy
	$(DOXYGEN) src/sss_client/idmap/sss_nss_idmap.doxy
else !HAVE_DOXYGEN
docs:
	@echo "Doxygen not installed, cannot generate documentation"
	@exit 1
endif !HAVE_DOXYGEN

if BUILD_PYTHON_BINDINGS
$(abs_builddir)/src/config/SSSDConfig/ipachangeconf.py:
	-cp $(srcdir)/src/config/SSSDConfig/ipachangeconf.py $(builddir)/src/config/SSSDConfig/

$(abs_builddir)/src/config/SSSDConfig/sssd_upgrade_config.py:
	-cp $(srcdir)/src/config/SSSDConfig/sssd_upgrade_config.py $(builddir)/src/config/SSSDConfig/

SSSDCONFIG_MODULES = \
    $(abs_builddir)/src/config/SSSDConfig/ipachangeconf.py \
    $(abs_builddir)/src/config/SSSDConfig/sssd_upgrade_config.py
else
SSSSCONFIG_MODULES =
endif

all-local: ldb_mod_test_dir $(SSSDCONFIG_MODULES)
if BUILD_PYTHON_BINDINGS
	cd $(builddir)/src/config; $(PYTHON) setup.py build --build-base $(abs_builddir)/src/config
endif

install-exec-hook: installsssddirs
if BUILD_PYTHON_BINDINGS
	if [ "$(DESTDIR)" = "" ]; then \
		cd $(builddir)/src/config; $(PYTHON) setup.py build --build-base $(abs_builddir)/src/config install $(DISTSETUPOPTS) --prefix=$(PYTHON_PREFIX) --record=$(abs_builddir)/src/config/.files; \
	else \
		cd $(builddir)/src/config; $(PYTHON) setup.py build --build-base $(abs_builddir)/src/config install $(DISTSETUPOPTS) --prefix=$(PYTHON_PREFIX) --root=$(DESTDIR) --record=$(abs_builddir)/src/config/.files; \
	fi
endif
	for doc in $(SSSD_DOCS); do \
		mkdir -p $$doc $(DESTDIR)/$(docdir); \
		cp -a $$doc $(DESTDIR)/$(docdir)/; \
	done;

if HAVE_SYSTEMD_UNIT
	mkdir -p $(DESTDIR)$(systemdunitdir)
else
	mkdir -p $(DESTDIR)$(initdir)
endif

install-data-hook:
	rm $(DESTDIR)/$(nsslibdir)/libnss_sss.so.2 \
       $(DESTDIR)/$(nsslibdir)/libnss_sss.so
	mv $(DESTDIR)/$(nsslibdir)/libnss_sss.so.2.0.0 $(DESTDIR)/$(nsslibdir)/libnss_sss.so.2
	if [ ! $(krb5rcachedir) = "__LIBKRB5_DEFAULTS__" ]; then \
        mkdir -p $(DESTDIR)/$(krb5rcachedir) ; \
	fi

uninstall-hook:
	if [ -f $(abs_builddir)/src/config/.files ]; then \
	    cat $(abs_builddir)/src/config/.files | xargs -iq rm -f $(DESTDIR)/q; \
	    rm $(abs_builddir)/src/config/.files ; \
	fi
	for doc in $(SSSD_DOCS); do \
		rm -Rf $(DESTDIR)/$(docdir)/$$doc; \
	done;

clean-local:
if BUILD_PYTHON_BINDINGS
	if [ ! $(srcdir)/src/config/SSSDConfig/ipachangeconf.py -ef $(builddir)/src/config/SSSDConfig/ipachangeconf.py ]; then \
		rm -f $(builddir)/src/config/SSSDConfig/ipachangeconf.py ; \
	fi

	if [ ! $(srcdir)/src/config/SSSDConfig/ipachangeconf.py -ef $(builddir)/src/config/SSSDConfig/ipachangeconf.py ]; then \
		rm -f $(builddir)/src/config/SSSDConfig/sssd_upgrade_config.py ; \
	fi

	cd $(builddir)/src/config; $(PYTHON) setup.py build --build-base $(abs_builddir)/src/config clean --all
endif
	for doc in $(SSSD_DOCS); do \
		rm -Rf $$doc; \
	done;
	rm -Rf ldb_mod_test_dir

CLEANFILES = *.X */*.X */*/*.X

tests: all $(check_PROGRAMS)


# RPM-related tasks

RPMBUILD ?= $(PWD)/rpmbuild

dist_noinst_DATA += \
    m4 \
    contrib/sssd.spec.in \
    BUILD.txt \
    COPYING

rpmroot:
	mkdir -p $(RPMBUILD)/BUILD
	mkdir -p $(RPMBUILD)/RPMS
	mkdir -p $(RPMBUILD)/SOURCES
	mkdir -p $(RPMBUILD)/SPECS
	mkdir -p $(RPMBUILD)/SRPMS

rpmbrprep: dist-gzip rpmroot
if GIT_CHECKOUT
# When we're building RPMs from a git checkout,
# we don't want to be bothered with translation
# updates
	git checkout $(srcdir)/po $(srcdir)/src/man/po
endif
	cp $(builddir)/contrib/sssd.spec $(RPMBUILD)/SPECS
	cp $(distdir).tar.gz $(RPMBUILD)/SOURCES

rpms: rpmbrprep
	cd $(RPMBUILD); \
	rpmbuild --define "_topdir $(RPMBUILD)" -ba SPECS/sssd.spec

if GIT_CHECKOUT
prerelease-rpms:
	cp $(srcdir)/version.m4 $(srcdir)/version.m4.orig
	sed -e "s/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.*\])/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.`date +%Y%m%d.%H%M`.git`git log -1 --pretty=format:%h`\])/" < $(srcdir)/version.m4.orig > $(srcdir)/version.m4
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
	sed -e "s/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.*\])/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.`date +%Y%m%d.%H%M`.git`git log -1 --pretty=format:%h`\])/" < $(srcdir)/version.m4.orig > $(srcdir)/version.m4
	$(MAKE) srpm
	mv $(srcdir)/version.m4.orig $(srcdir)/version.m4
endif

