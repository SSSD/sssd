SUBDIRS = po
topdir=.

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
sssdconfdir = $(sysconfdir)/sssd
sssdapiplugindir = $(sssdconfdir)/sssd.api.d
dbusintrospectdir = $(datarootdir)/sssd/introspect
dbuspolicydir = $(sysconfdir)/dbus-1/system.d
localedir = @localedir@
nsslibdir = @nsslibdir@
pamlibdir = $(nsslibdir)/security

dbpath = @dbpath@
pluginpath = @pluginpath@
pidpath = @pidpath@
pipepath = @pipepath@
initdir = @initdir@
logpath = @logpath@
pubconfpath = @pubconfpath@

AM_CFLAGS =
if WANT_AUX_INFO
    AM_CFLAGS += -aux-info $@.X
endif
if HAVE_GCC
    AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
                 -Wcast-qual -Wcast-align -Wwrite-strings \
                 -Werror-implicit-function-declaration
endif

ACLOCAL_AMFLAGS = -I m4 -I .

sbin_PROGRAMS = \
    sssd \
    sss_useradd \
    sss_userdel \
    sss_groupadd \
    sss_groupdel \
    sss_usermod \
    sss_groupmod \
    sss_groupshow

sssdlibexec_PROGRAMS = \
    sssd_nss \
    sssd_pam \
    sssd_be \
    krb5_child \
    ldap_child \
    $(sssd_pk) \
    $(sssd_info) \
    proxy_child

dist_sssdlibexec_SCRIPTS = \
    config/upgrade_config.py

if HAVE_CHECK
    non_interactive_check_based_tests = \
        sysdb-tests \
        strtonum-tests \
        resolv-tests \
        krb5-utils-tests \
        check_and_open-tests \
        ipa_timerules-tests \
        files-tests \
        refcount-tests \
        fail_over-tests \
        find_uid-tests \
        auth-tests \
        ipa_ldap_opt-tests \
        simple_access-tests \
        util-tests
endif

check_PROGRAMS = \
    stress-tests \
    $(non_interactive_check_based_tests)

TESTS = \
    $(srcdir)/config/SSSDConfigTest.py \
    $(non_interactive_check_based_tests)

sssdlib_LTLIBRARIES = \
    libsss_ldap.la \
    libsss_krb5.la \
    libsss_proxy.la \
    libsss_ipa.la \
    libsss_simple.la

ldblib_LTLIBRARIES = \
    memberof.la

if BUILD_KRB5_LOCATOR_PLUGIN
krb5plugin_LTLIBRARIES = \
    sssd_krb5_locator_plugin.la
endif

noinst_LTLIBRARIES = \
    libsss_crypt.la

if HAVE_NSS
    SSS_CRYPT_SOURCES = util/nss_sha512crypt.c
    SSS_CRYPT_CFLAGS = $(NSS_CFLAGS)
    SSS_CRYPT_LIBS = $(NSS_LIBS)
else
    SSS_CRYPT_SOURCES = util/crypto_sha512crypt.c
    SSS_CRYPT_CFLAGS = $(CRYPTO_CFLAGS)
    SSS_CRYPT_LIBS = $(CRYPTO_LIBS)
endif

libsss_crypt_la_SOURCES = \
    $(SSS_CRYPT_SOURCES)
libsss_crypt_la_CPPFLAGS = \
    $(SSS_CRYPT_CFLAGS)
libsss_crypt_la_LIBADD = \
    $(SSS_CRYPT_LIBS)

if BUILD_PYTHON_BINDINGS
pyexec_LTLIBRARIES = \
    pysss.la
endif

dist_noinst_SCRIPTS = \
    $(EXTRA_SCRIPTS) \
    config/setup.py \
    config/ipachangeconf.py \
    config/SSSDConfig.py \
    config/SSSDConfigTest.py

dist_noinst_DATA = \
    config/testconfigs/sssd-valid.conf \
    config/testconfigs/noparse.api.conf \
    config/testconfigs/sssd-noversion.conf \
    config/testconfigs/sssd-badversion.conf \
    config/testconfigs/sssd-invalid.conf \
    config/testconfigs/sssd-invalid-badbool.conf

###############################
# Global compilation settings #
###############################

if HAVE_SYSTEM_COLLECTION
    COLLECTION_CFLAGS = $(SYSTEM_COLLECTION_CFLAGS)
    COLLECTION_LIBS = $(SYSTEM_COLLECTION_LIBS)
else
    COLLECTION_CFLAGS = \
        -I$(srcdir)/../common/collection
    COLLECTION_LIBS = \
        -L$(builddir)/../common/collection \
        -lcollection
endif

if HAVE_SYSTEM_INI_CONFIG
    INI_CFG_CFLAGS = $(SYSTEM_INI_CONFIG_CFLAGS)
    INI_CFG_LIBS = $(SYSTEM_INI_CONFIG_LIBS)
else
    INI_CFG_CFLAGS = \
        -I$(srcdir)/../common/ini
    INI_CFG_LIBS = \
        -L$(builddir)/../common/ini/ \
        -lini_config
endif

if HAVE_SYSTEM_DHASH
    DHASH_CFLAGS = $(SYSTEM_DHASH_CFLAGS)
    DHASH_LIBS = $(SYSTEM_DHASH_LIBS)
else
    DHASH_CFLAGS = \
        -I$(srcdir)/../common/dhash
    DHASH_LIBS = \
        -L$(builddir)/../common/dhash/ \
        -ldhash
endif

AM_CPPFLAGS = -Wall \
    -Iinclude \
    -I.. \
    -I$(srcdir)/include \
    -I$(srcdir)/sss_client \
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
    $(INI_CFG_CFLAGS) \
    $(DHASH_CFLAGS) \
    -DLIBDIR=\"$(libdir)\" \
    -DVARDIR=\"$(localstatedir)\" \
    -DSHLIBEXT=\"$(SHLIBEXT)\" \
    -DSSSD_LIBEXEC_PATH=\"$(sssdlibexecdir)\" \
    -DSSSD_INTROSPECT_PATH=\"$(dbusinstropectdir)\" \
    -DSSSD_CONF_DIR=\"$(sssdconfdir)\" \
    -DSSS_NSS_SOCKET_NAME=\"$(pipepath)/nss\" \
    -DSSS_PAM_SOCKET_NAME=\"$(pipepath)/pam\" \
    -DSSS_PAM_PRIV_SOCKET_NAME=\"$(pipepath)/private/pam\" \
    -DUSE_MMAP=1 \
    -DTEVENT_DEPRECATED=1\
    -DLOCALEDIR=\"$(localedir)\"

EXTRA_DIST = build/config.rpath

SSSD_DEBUG_OBJ = \
    util/debug.c \
    util/sss_log.c

SSSD_UTIL_OBJ = \
    confdb/confdb.c \
    db/sysdb.c \
    db/sysdb_ops.c \
    db/sysdb_search.c \
    monitor/monitor_sbus.c \
    providers/dp_auth_util.c \
    providers/dp_pam_data_util.c \
    providers/dp_sbus.c \
    sbus/sbus_client.c \
    sbus/sssd_dbus_common.c \
    sbus/sssd_dbus_connection.c \
    sbus/sssd_dbus_server.c \
    util/util.c \
    util/memory.c \
    util/server.c \
    util/signal.c \
    util/usertools.c \
    util/backup_file.c \
    util/strtonum.c \
    util/check_and_open.c \
    util/refcount.c \
    $(SSSD_DEBUG_OBJ)

SSSD_RESPONDER_OBJ = \
    responder/common/negcache.c \
    responder/common/responder_cmd.c \
    responder/common/responder_common.c \
    responder/common/responder_dp.c \
    responder/common/responder_packet.c

SSSD_TOOLS_OBJ = \
    tools/sss_sync_ops.c \
    tools/tools_util.c \
    tools/files.c \
    tools/selinux.c \
    tools/nscd.c

SSSD_RESOLV_OBJ = \
    resolv/async_resolv.c
if BUILD_ARES_DATA
    SSSD_RESOLV_OBJ += \
	resolv/ares/ares_parse_srv_reply.c \
	resolv/ares/ares_data.c
endif

SSSD_FAILOVER_OBJ = \
    providers/fail_over.c \
    $(SSSD_RESOLV_OBJ)

SSSD_LIBS = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(LDB_LIBS) \
    $(DBUS_LIBS) \
    $(PCRE_LIBS) \
    $(INI_CFG_LIBS) \
    $(COLLECTION_LIBS) \
    $(DHASH_LIBS) \
    $(SSS_CRYPT_LIBS) \
    libsss_crypt.la

PYTHON_BINDINGS_LIBS = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(LDB_LIBS) \
    $(DBUS_LIBS) \
    $(PCRE_LIBS) \
    $(SSS_CRYPT_LIBS) \
    libsss_crypt.la

TOOLS_LIBS = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(LDB_LIBS) \
    $(DBUS_LIBS) \
    $(PCRE_LIBS) \
    $(INI_CFG_LIBS) \
    $(COLLECTION_LIBS) \
    $(DHASH_LIBS) \
    libsss_crypt.la

if BUILD_SELINUX
    TOOLS_LIBS += $(SELINUX_LIBS)
endif
if BUILD_SEMANAGE
    TOOLS_LIBS += $(SEMANAGE_LIBS)
endif

dist_noinst_HEADERS = \
    monitor/monitor.h \
    util/sha512crypt.h \
    util/dlinklist.h \
    util/util.h \
    util/strtonum.h \
    util/sss_ldap.h \
    util/sss_krb5.h \
    util/refcount.h \
    util/find_uid.h \
    util/user_info_msg.h \
    config.h \
    monitor/monitor.h \
    monitor/monitor_interfaces.h \
    responder/common/responder.h \
    responder/common/responder_packet.h \
    responder/pam/pamsrv.h \
    responder/nss/nsssrv.h \
    responder/common/negcache.h \
    sbus/sbus_client.h \
    sbus/sssd_dbus.h \
    sbus/sssd_dbus_private.h \
    db/sysdb.h \
    db/sysdb_private.h \
    confdb/confdb.h \
    confdb/confdb_private.h \
    confdb/confdb_setup.h \
    providers/data_provider.h \
    providers/dp_backend.h \
    providers/fail_over.h \
    providers/providers.h \
    providers/child_common.h \
    providers/simple/simple_access.h \
    providers/krb5/krb5_auth.h \
    providers/krb5/krb5_common.h \
    providers/krb5/krb5_utils.h \
    providers/ldap/ldap_common.h \
    providers/ldap/sdap.h \
    providers/ldap/sdap_access.h \
    providers/ldap/sdap_async.h \
    providers/ldap/sdap_async_private.h \
    providers/ipa/ipa_common.h \
    providers/ipa/ipa_access.h \
    providers/ipa/ipa_timerules.h \
    providers/ipa/ipa_auth.h \
    providers/ipa/ipa_dyndns.h \
    providers/proxy/proxy.h \
    tools/tools_util.h \
    tools/sss_sync_ops.h \
    resolv/async_resolv.h \
    resolv/ares/ares_parse_srv_reply.h \
    resolv/ares/ares_parse_txt_reply.h \
    resolv/ares/ares_data.h \
    tests/common.h


####################
# Program Binaries #
####################
sssd_SOURCES = \
    monitor/monitor.c \
    confdb/confdb_setup.c \
    $(SSSD_UTIL_OBJ)
sssd_LDADD = \
    $(SSSD_LIBS)

sssd_nss_SOURCES = \
    responder/nss/nsssrv.c \
    responder/nss/nsssrv_cmd.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_RESPONDER_OBJ)
sssd_nss_LDADD = \
    $(TDB_LIBS) \
    $(SSSD_LIBS)

sssd_pam_SOURCES = \
    responder/pam/pam_LOCAL_domain.c \
    responder/pam/pamsrv.c \
    responder/pam/pamsrv_cmd.c \
    responder/pam/pamsrv_dp.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_RESPONDER_OBJ)
sssd_pam_LDADD = \
    $(TDB_LIBS) \
    $(SSSD_LIBS)

sssd_be_SOURCES = \
    providers/data_provider_be.c \
    providers/data_provider_fo.c \
    providers/data_provider_opts.c \
    providers/data_provider_callbacks.c \
    $(SSSD_FAILOVER_OBJ) \
    $(SSSD_UTIL_OBJ)
sssd_be_LDADD = $(SSSD_LIBS) $(CARES_LIBS)
sssd_be_LDFLAGS = \
    -Wl,--version-script,$(srcdir)/providers/sssd_be.exports \
    -export-dynamic

dist_noinst_DATA += \
    examples/sssd.conf \
    examples/sssdproxytest \
    examples/sudo \
    examples/logrotate \
    providers/sssd_be.exports \
    sss_client/COPYING \
    sss_client/COPYING.LESSER \
    m4

######################
# Command-line Tools #
######################
sss_useradd_SOURCES = \
    tools/sss_useradd.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ)
sss_useradd_LDADD = \
    $(TOOLS_LIBS)

sss_userdel_SOURCES = \
    tools/sss_userdel.c \
    util/find_uid.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ)
sss_userdel_LDADD = \
    $(TOOLS_LIBS)

sss_groupadd_SOURCES = \
    tools/sss_groupadd.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ)
sss_groupadd_LDADD = \
    $(TOOLS_LIBS)

sss_groupdel_SOURCES = \
    tools/sss_groupdel.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ)
sss_groupdel_LDADD = \
    $(TOOLS_LIBS)

sss_usermod_SOURCES = \
    tools/sss_usermod.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ)
sss_usermod_LDADD = \
    $(TOOLS_LIBS)

sss_groupmod_SOURCES = \
    tools/sss_groupmod.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ)
sss_groupmod_LDADD = \
    $(TOOLS_LIBS)

sss_groupshow_SOURCES = \
    tools/sss_groupshow.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ)
sss_groupshow_LDADD = \
    $(TOOLS_LIBS)

#################
# Feature Tests #
#################
noinst_LTLIBRARIES += \
    libsss_test_common.la

libsss_test_common_la_SOURCES = \
    tests/common.c

if HAVE_CHECK
libsss_test_common_la_SOURCES += \
    tests/common_check.c

sysdb_tests_DEPENDENCIES = \
    $(ldblib_LTLIBRARIES)
sysdb_tests_SOURCES = \
    tests/sysdb-tests.c \
    $(SSSD_UTIL_OBJ)
sysdb_tests_CFLAGS = \
    -DSYSDB_TEST \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
sysdb_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    libsss_test_common.la

strtonum_tests_SOURCES = \
    tests/strtonum-tests.c \
    util/debug.c \
    util/strtonum.c
strtonum_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
strtonum_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    libsss_test_common.la

krb5_utils_tests_SOURCES = \
    tests/krb5_utils-tests.c \
    providers/krb5/krb5_utils.c \
    providers/krb5/krb5_common.c \
    providers/data_provider_fo.c \
    providers/data_provider_opts.c \
    providers/data_provider_callbacks.c \
    $(SSSD_FAILOVER_OBJ) \
    $(SSSD_UTIL_OBJ)
krb5_utils_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
krb5_utils_tests_LDADD = \
    $(SSSD_LIBS)\
    $(CARES_LIBS) \
    $(CHECK_LIBS) \
    libsss_test_common.la


check_and_open_tests_SOURCES = \
    $(SSSD_DEBUG_OBJ) \
    tests/check_and_open-tests.c \
    util/check_and_open.c
check_and_open_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
check_and_open_tests_LDADD = \
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
    $(SSSD_DEBUG_OBJ) \
    tests/files-tests.c \
    util/check_and_open.c \
    tools/selinux.c \
    tools/files.c
files_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
files_tests_LDADD = \
    $(FILES_TESTS_LIBS) \
    libsss_test_common.la

SSSD_RESOLV_TESTS_OBJ = \
    $(SSSD_RESOLV_OBJ)
if BUILD_ARES_DATA
    SSSD_RESOLV_TESTS_OBJ += \
	resolv/ares/ares_parse_txt_reply.c
endif

resolv_tests_SOURCES = \
    tests/resolv-tests.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_RESOLV_TESTS_OBJ)
resolv_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS) \
    -DBUILD_TXT
resolv_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(CARES_LIBS) \
    libsss_test_common.la

refcount_tests_SOURCES = \
    tests/refcount-tests.c \
    $(CHECK_OBJ) \
    $(SSSD_UTIL_OBJ)
refcount_tests_CFLAGS = \
    $(CHECK_CFLAGS)
refcount_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    libsss_test_common.la

fail_over_tests_SOURCES = \
    tests/fail_over-tests.c \
    $(SSSD_FAILOVER_OBJ) \
    $(CHECK_OBJ) \
    $(SSSD_UTIL_OBJ)
fail_over_tests_CFLAGS = \
    $(CHECK_CFLAGS)
fail_over_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(CARES_LIBS) \
    libsss_test_common.la

ipa_timerules_tests_SOURCES = \
    providers/ipa/ipa_timerules.c \
    tests/ipa_timerules-tests.c \
    $(SSSD_DEBUG_OBJ)
ipa_timerules_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(PCRE_CFLAGS) \
    $(CHECK_CFLAGS)
ipa_timerules_tests_LDADD = \
    $(POPT_LIBS) \
    $(PCRE_LIBS) \
    $(TALLOC_LIBS) \
    $(CHECK_LIBS) \
    libsss_test_common.la

find_uid_tests_SOURCES = \
    tests/find_uid-tests.c \
    util/find_uid.c \
    $(SSSD_DEBUG_OBJ)
find_uid_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(DHASH_CFLAGS) \
    $(CHECK_CFLAGS)
find_uid_tests_LDADD = \
    $(TALLOC_LIBS) \
    $(DHASH_LIBS) \
    $(CHECK_LIBS) \
    libsss_test_common.la

auth_tests_SOURCES = \
    tests/auth-tests.c \
    $(SSSD_UTIL_OBJ)
auth_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
auth_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    libsss_test_common.la

ipa_ldap_opt_tests_SOURCES = \
    providers/ipa/ipa_utils.c \
    tests/ipa_ldap_opt-tests.c
ipa_ldap_opt_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
ipa_ldap_opt_tests_LDADD = \
    $(CHECK_LIBS) \
    $(TALLOC_LIBS) \
    libsss_test_common.la

simple_access_tests_SOURCES = \
    tests/simple_access-tests.c \
    providers/simple/simple_access.c \
    $(SSSD_UTIL_OBJ)
simple_access_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
simple_access_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS)

util_tests_SOURCES = \
    tests/util-tests.c \
    $(SSSD_UTIL_OBJ)
util_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
util_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    libsss_test_common.la

endif

stress_tests_SOURCES = \
    tests/stress-tests.c \
    $(SSSD_UTIL_OBJ)
stress_tests_LDADD = \
    $(SSSD_LIBS) \
    libsss_test_common.la

noinst_PROGRAMS = pam_test_client
pam_test_client_SOURCES = sss_client/pam_test_client.c
pam_test_client_LDFLAGS = -lpam -lpam_misc

####################
# Client Libraries #
####################

nsslib_LTLIBRARIES = libnss_sss.la
libnss_sss_la_SOURCES = \
    sss_client/common.c \
    sss_client/passwd.c \
    sss_client/group.c \
    sss_client/sss_cli.h
libnss_sss_la_LDFLAGS = \
    -module \
    -version-info 2:0:0 \
    -Wl,--version-script,$(srcdir)/sss_client/sss_nss.exports

pamlib_LTLIBRARIES = pam_sss.la
pam_sss_la_SOURCES = \
    sss_client/pam_sss.c \
    sss_client/common.c \
    sss_client/sss_cli.h \
    sss_client/sss_pam_macros.h

pam_sss_la_LDFLAGS = \
    -lpam \
    -module \
    -avoid-version \
    -Wl,--version-script,$(srcdir)/sss_client/sss_pam.exports

dist_noinst_DATA += \
    sss_client/sss_nss.exports \
    sss_client/sss_pam.exports

####################
# Plugin Libraries #
####################
libsss_ldap_la_SOURCES = \
    util/find_uid.c \
    providers/child_common.c \
    providers/ldap/ldap_id.c \
    providers/ldap/ldap_id_enum.c \
    providers/ldap/ldap_id_cleanup.c \
    providers/ldap/sdap_access.c \
    providers/ldap/ldap_auth.c \
    providers/ldap/ldap_init.c \
    providers/ldap/ldap_common.c \
    providers/ldap/sdap_async.c \
    providers/ldap/sdap_async_accounts.c \
    providers/ldap/sdap_async_connection.c \
    providers/ldap/sdap_child_helpers.c \
    providers/ldap/sdap_fd_events.c \
    providers/ldap/sdap.c \
    util/user_info_msg.c \
    util/sss_ldap.c \
    util/sss_krb5.c
libsss_ldap_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(LDAP_CFLAGS) \
    $(KRB5_CFLAGS)
libsss_ldap_la_LIBADD = \
    $(OPENLDAP_LIBS) \
    $(KRB5_LIBS)
libsss_ldap_la_LDFLAGS = \
    -version-info 1:0:0 \
    -module

libsss_proxy_la_SOURCES = \
    providers/proxy/proxy.c
libsss_proxy_la_CFLAGS = \
    $(AM_CFLAGS)
libsss_proxy_la_LIBADD = \
    $(PAM_LIBS)
libsss_proxy_la_LDFLAGS = \
    -version-info 1:0:0 \
    -module

libsss_simple_la_SOURCES = \
    providers/simple/simple_access.c
libsss_simple_la_CFLAGS = \
    $(AM_CFLAGS)
libsss_simple_la_LIBADD = \
    $(PAM_LIBS)
libsss_simple_la_LDFLAGS = \
    -version-info 1:0:0 \
    -module

libsss_krb5_la_SOURCES = \
    util/find_uid.c \
    providers/child_common.c \
    providers/krb5/krb5_utils.c \
    providers/krb5/krb5_become_user.c \
    providers/krb5/krb5_delayed_online_authentication.c \
    providers/krb5/krb5_auth.c \
    providers/krb5/krb5_common.c \
    providers/krb5/krb5_init.c \
    util/sss_krb5.c
libsss_krb5_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(DHASH_CFLAGS)
libsss_krb5_la_LIBADD = \
    $(DHASH_LIBS) \
    $(KEYUTILS_LIBS) \
    $(KRB5_LIBS)
libsss_krb5_la_LDFLAGS = \
    -version-info 1:0:0 \
    -module

libsss_ipa_la_SOURCES = \
    providers/child_common.c \
    providers/ipa/ipa_init.c \
    providers/ipa/ipa_common.c \
    providers/ipa/ipa_utils.c \
    providers/ipa/ipa_auth.c \
    providers/ipa/ipa_access.c \
    providers/ipa/ipa_timerules.c \
    providers/ipa/ipa_dyndns.c \
    providers/ldap/ldap_id.c \
    providers/ldap/ldap_id_enum.c \
    providers/ldap/ldap_id_cleanup.c \
    providers/ldap/ldap_auth.c \
    providers/ldap/ldap_common.c \
    providers/ldap/sdap_async.c \
    providers/ldap/sdap_async_accounts.c \
    providers/ldap/sdap_async_connection.c \
    providers/ldap/sdap_child_helpers.c \
    providers/ldap/sdap_fd_events.c \
    providers/ldap/sdap.c \
    util/user_info_msg.c \
    util/sss_ldap.c \
    util/sss_krb5.c \
    util/find_uid.c \
    providers/krb5/krb5_utils.c \
    providers/krb5/krb5_become_user.c \
    providers/krb5/krb5_delayed_online_authentication.c \
    providers/krb5/krb5_common.c \
    providers/krb5/krb5_auth.c
libsss_ipa_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(LDAP_CFLAGS) \
    $(DHASH_CFLAGS) \
    $(KRB5_CFLAGS)
libsss_ipa_la_LIBADD = \
    $(OPENLDAP_LIBS) \
    $(DHASH_LIBS) \
    $(KEYUTILS_LIBS) \
    $(KRB5_LIBS)
libsss_ipa_la_LDFLAGS = \
    -version-info 1:0:0 \
    -module

krb5_child_SOURCES = \
    $(SSSD_DEBUG_OBJ) \
    providers/krb5/krb5_become_user.c \
    providers/krb5/krb5_child.c \
    providers/child_common.c \
    providers/dp_pam_data_util.c \
    util/user_info_msg.c \
    util/sss_krb5.c
krb5_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS) \
    $(KRB5_CFLAGS)
krb5_child_LDADD = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(KRB5_LIBS)

ldap_child_SOURCES = \
    $(SSSD_DEBUG_OBJ) \
    providers/ldap/ldap_child.c \
    providers/child_common.c \
    util/sss_krb5.c
ldap_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS) \
    $(KRB5_CFLAGS)
ldap_child_LDADD = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(OPENLDAP_LIBS) \
    $(KRB5_LIBS)

proxy_child_SOURCES = \
    $(SSSD_UTIL_OBJ) \
    providers/proxy/proxy_child.c
proxy_child_CFLAGS = \
    $(AM_CFLAGS) \
    $(POPT_CFLAGS)
proxy_child_LDADD = \
    $(PAM_LIBS) \
    $(SSSD_LIBS)

memberof_la_SOURCES = \
    ldb_modules/memberof.c
memberof_la_CFLAGS = \
    $(AM_CFLAGS)
memberof_la_LIBADD = $(LDB_LIBS) $(DHASH_LIBS)
memberof_la_LDFLAGS = \
    -avoid-version \
    -module

if BUILD_KRB5_LOCATOR_PLUGIN
sssd_krb5_locator_plugin_la_SOURCES = \
    krb5_plugin/sssd_krb5_locator_plugin.c
sssd_krb5_locator_plugin_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(KRB5_CFLAGS)
sssd_krb5_locator_plugin_la_LDFLAGS = \
    -avoid-version \
    -module
endif

if BUILD_PYTHON_BINDINGS
pysss_la_SOURCES = \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ) \
    python/pysss.c
pysss_la_CFLAGS = \
    $(AM_CFLAGS)  \
    $(PYTHON_CFLAGS)
pysss_la_LIBADD = \
    $(PYTHON_BINDINGS_LIBS) \
    $(PYTHON_LIBS)
pysss_la_LDFLAGS = \
    -avoid-version \
    -module
endif

############
# MANPAGES #
############

#Special Rules:
export SGML_CATALOG_FILES
DOCBOOK_XSLT = http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl
XMLLINT_FLAGS = --catalogs --postvalid --nonet --xinclude --noout
XSLTPROC_FLAGS = --catalogs --xinclude --nonet

dist_man_MANS = man/sss_useradd.8 man/sss_userdel.8 man/sss_usermod.8 \
		man/sss_groupadd.8 man/sss_groupdel.8 man/sss_groupmod.8 \
		man/sssd.8 man/sssd.conf.5 man/sssd-ldap.5 man/sssd-krb5.5 \
		man/sssd-ipa.5 man/sssd-simple.5 \
		man/sssd_krb5_locator_plugin.8 man/sss_groupshow.8 man/pam_sss.8

SUFFIXES = .1.xml .1 .3.xml .3 .5.xml .5 .8.xml .8
.1.xml.1:
	$(XMLLINT) $(XMLLINT_FLAGS) $<
	$(XSLTPROC) -o $@  $(XSLTPROC_FLAGS) $(DOCBOOK_XSLT) $<

.3.xml.3:
	$(XMLLINT) $(XMLLINT_FLAGS) $<
	$(XSLTPROC) -o $@  $(XSLTPROC_FLAGS) $(DOCBOOK_XSLT) $<

.5.xml.5:
	$(XMLLINT) $(XMLLINT_FLAGS) $<
	$(XSLTPROC) -o $@  $(XSLTPROC_FLAGS) $(DOCBOOK_XSLT) $<

.8.xml.8:
	$(XMLLINT) $(XMLLINT_FLAGS) $<
	$(XSLTPROC) -o $@  $(XSLTPROC_FLAGS) $(DOCBOOK_XSLT) $<

#######################
# Installation Extras #
#######################

dist_init_SCRIPTS =
if HAVE_SUSE
    dist_init_SCRIPTS += \
        sysv/SUSE/sssd
else
    dist_init_SCRIPTS += \
        sysv/sssd
endif


dist_sssdconf_DATA = \
    config/etc/sssd.api.conf
dist_sssdapiplugin_DATA = \
    config/etc/sssd.api.d/sssd-ipa.conf \
    config/etc/sssd.api.d/sssd-krb5.conf \
    config/etc/sssd.api.d/sssd-ldap.conf \
    config/etc/sssd.api.d/sssd-local.conf \
    config/etc/sssd.api.d/sssd-proxy.conf \
    config/etc/sssd.api.d/sssd-simple.conf

installsssddirs::
	mkdir -p \
    $(DESTDIR)$(includedir) \
    $(DESTDIR)$(libdir) \
    $(DESTDIR)$(sbindir) \
    $(DESTDIR)$(initdir) \
    $(DESTDIR)$(mandir) \
    $(DESTDIR)$(pluginpath) \
    $(DESTDIR)$(libdir)/ldb \
    $(DESTDIR)$(dbuspolicydir) \
    $(DESTDIR)$(infpintrospectdir) \
    $(DESTDIR)$(dbusintrospectdir) \
    $(DESTDIR)$(pipepath)/private \
    $(DESTDIR)$(sssdlibdir) \
    $(DESTDIR)$(sssdconfdir) \
    $(DESTDIR)$(dbpath) \
    $(DESTDIR)$(pidpath) \
    $(DESTDIR)$(initdir) \
    $(DESTDIR)$(logpath) \
    $(DESTDIR)$(pubconfpath)

if HAVE_DOXYGEN
docs:
	$(DOXYGEN) doxy.config
else
docs:
	@echo "Doxygen not installed, cannot generate documentation"
	@exit 1
endif
all-local:
	cd $(srcdir)/config; $(PYTHON) setup.py build --build-base $(abs_builddir)/config

install-exec-hook: installsssddirs
	if [ "$(DESTDIR)" = "" ]; then \
		cd $(srcdir)/config; $(PYTHON) setup.py build --build-base $(abs_builddir)/config install $(DISTSETUPOPTS) --prefix=$(PYTHON_PREFIX) --record=$(abs_builddir)/config/.files; \
	else \
		cd $(srcdir)/config; $(PYTHON) setup.py build --build-base $(abs_builddir)/config install $(DISTSETUPOPTS) --prefix=$(PYTHON_PREFIX) --root=$(DESTDIR) --record=$(abs_builddir)/config/.files; \
	fi
	mkdir -p doc $(DESTDIR)/$(docdir); cp -a doc $(DESTDIR)/$(docdir)/

install-data-hook:
	rm $(DESTDIR)/$(nsslibdir)/libnss_sss.so.2 \
       $(DESTDIR)/$(nsslibdir)/libnss_sss.so
	mv $(DESTDIR)/$(nsslibdir)/libnss_sss.so.2.0.0 $(DESTDIR)/$(nsslibdir)/libnss_sss.so.2

uninstall-hook:
	if [ -f $(abs_builddir)/config/.files ]; then \
	    cat $(abs_builddir)/config/.files | xargs -iq rm -f $(DESTDIR)/q; \
	    rm $(abs_builddir)/config/.files ; \
	fi
	rm -Rf $(DESTDIR)/$(docdir)/doc

clean-local:
	cd $(srcdir)/config; $(PYTHON) setup.py build --build-base $(abs_builddir)/config clean --all
	rm -Rf doc

CLEANFILES = *.X */*.X */*/*.X

tests: all $(check_PROGRAMS)
