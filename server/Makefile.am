SUBDIRS = po
topdir=.

# Some old versions of automake don't define builddir
builddir ?= .

sssdlibexecdir = $(libexecdir)/sssd
sssdlibdir = $(libdir)/sssd
ldblibdir = $(libdir)/ldb
krb5plugindir = @krb5pluginpath@
sssdconfdir = $(sysconfdir)/sssd
dbusintrospectdir = $(datarootdir)/sssd/introspect
dbuspolicydir = $(sysconfdir)/dbus-1/system.d
localedir = @localedir@

dbpath = @dbpath@
pluginpath = @pluginpath@
pidpath = @pidpath@
pipepath = @pipepath@
initdir = @initdir@
shadow_utils_path = @shadow_utils_path@

AM_CFLAGS =
if WANT_AUX_INFO
    AM_CFLAGS += -aux-info $@.X
endif
if HAVE_GCC
    AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
                 -Wcast-qual -Wcast-align -Wwrite-strings
endif

REPLACE_CFLAGS = \
    -I $(srcdir)/../replace
REPLACE_LIBS = \
    -L$(builddir)/../replace \
    -lreplace

ACLOCAL_AMFLAGS = -I m4 -I .

sbin_PROGRAMS = \
    sssd \
    sss_useradd \
    sss_userdel \
    sss_groupadd \
    sss_groupdel \
    sss_usermod \
    sss_groupmod

sssdlibexec_PROGRAMS = \
    sssd_nss \
    sssd_pam \
    sssd_dp \
    sssd_be \
    $(sssd_pk) \
    $(sssd_info)

if HAVE_CHECK
    non_interactive_check_based_tests = \
        sysdb-tests \
        resolv-tests
endif

check_PROGRAMS = \
    stress-tests \
    $(non_interactive_check_based_tests)

TESTS = \
    $(non_interactive_check_based_tests)

sssdlib_LTLIBRARIES = \
    libsss_ldap.la \
    libsss_krb5.la \
    libsss_proxy.la

ldblib_LTLIBRARIES = \
    memberof.la

krb5plugin_LTLIBRARIES = \
    sssd_krb5_locator_plugin.la

noinst_LTLIBRARIES = \
    libsss_crypt.la
libsss_crypt_la_SOURCES = \
    util/nss_sha512crypt.c
libsss_crypt_la_CPPFLAGS = \
    $(NSS_CFLAGS)

###############################
# Global compilation settings #
###############################
COLLECTION_CFLAGS = \
    -I$(srcdir)/../common/collection \
    -I$(srcdir)/../common/trace
COLLECTION_LIBS = \
    -L$(builddir)/../common/collection/.libs/ \
    -lcollection

INI_CFG_CFLAGS = \
    -I$(srcdir)/../common/ini
INI_CFG_LIBS = \
    -L$(builddir)/../common/ini/.libs/ \
    -lini_config

DHASH_CFLAGS = \
    -I$(srcdir)/../common/dhash
DHASH_LIBS = \
    -L$(builddir)/../common/dhash/.libs/ \
    -ldhash

AM_CPPFLAGS = -Wall \
    -Iinclude \
    -I.. \
    -I$(srcdir)/include \
    -Iinclude \
    -I. \
    $(POPT_CFLAGS) \
    $(TALLOC_CFLAGS) \
    $(TDB_CFLAGS) \
    $(TEVENT_CFLAGS) \
    $(LDB_CFLAGS) \
    $(DBUS_CFLAGS) \
    $(PCRE_CFLAGS) \
    $(REPLACE_CFLAGS) \
    $(COLLECTION_CFLAGS) \
    $(INI_CFG_CFLAGS) \
    $(DHASH_CFLAGS) \
    -DLIBDIR=\"$(libdir)\" \
    -DVARDIR=\"$(localstatedir)\" \
    -DSHLIBEXT=\"$(SHLIBEXT)\" \
    -DSSSD_LIBEXEC_PATH=\"$(sssdlibexecdir)\" \
    -DSHADOW_UTILS_PATH=\"$(shadow_utils_path)\" \
    -DSSSD_INTROSPECT_PATH=\"$(dbusinstropectdir)\" \
    -DSSSD_CONF_DIR=\"$(sssdconfdir)\" \
    -DSSS_NSS_SOCKET_NAME=\"$(pipepath)/nss\" \
    -DSSS_PAM_SOCKET_NAME=\"$(pipepath)/pam\" \
    -DSSS_PAM_PRIV_SOCKET_NAME=\"$(pipepath)/private/pam\" \
    -DUSE_MMAP=1 \
    -DLOCALEDIR=\"$(localedir)\"

EXTRA_DIST = build/config.rpath

SSSD_DEBUG_OBJ = \
    util/debug.c

SSSD_UTIL_OBJ = \
    confdb/confdb.c \
    db/sysdb.c \
    db/sysdb_ops.c \
    db/sysdb_search.c \
    monitor/monitor_sbus.c \
    providers/dp_auth_util.c \
    providers/dp_sbus.c \
    sbus/sbus_client.c \
    sbus/sssd_dbus_common.c \
    sbus/sssd_dbus_connection.c \
    sbus/sssd_dbus_server.c \
    util/btreemap.c \
    util/memory.c \
    util/server.c \
    util/signal.c \
    util/usertools.c \
    $(SSSD_DEBUG_OBJ)

SSSD_RESPONDER_OBJ = \
    responder/common/responder_cmd.c \
    responder/common/responder_common.c \
    responder/common/responder_dp.c \
    responder/common/responder_packet.c

SSSD_TOOLS_OBJ = \
    tools/tools_util.c

SSSD_RESOLV_OBJ = \
    resolv/async_resolv.c
if BUILD_ARES_PARSE_SRV
    SSSD_RESOLV_OBJ += resolv/ares/ares_parse_srv_reply.c
endif
if BUILD_ARES_PARSE_TXT
    SSSD_RESOLV_OBJ += resolv/ares/ares_parse_txt_reply.c
endif


SSSD_LIBS = \
    $(TALLOC_LIBS) \
    $(TDB_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(LDB_LIBS) \
    $(DBUS_LIBS) \
    $(PCRE_LIBS) \
    $(INI_CFG_LIBS) \
    $(COLLECTION_LIBS) \
    $(DHASH_LIBS) \
    $(REPLACE_LIBS) \
    $(NSS_LIBS) \
    libsss_crypt.la

dist_noinst_HEADERS = \
    monitor/monitor.h \
    util/btreemap.h \
    util/nss_sha512crypt.h \
    util/dlinklist.h \
    util/sssd-i18n.h \
    util/util.h \
    config.h \
    monitor/monitor.h \
    monitor/monitor_interfaces.h \
    responder/common/responder.h \
    responder/common/responder_packet.h \
    responder/pam/pamsrv.h \
    responder/nss/nsssrv.h \
    responder/nss/nsssrv_nc.h \
    sbus/sbus_client.h \
    sbus/sssd_dbus.h \
    sbus/sssd_dbus_private.h \
    db/sysdb.h \
    db/sysdb_private.h \
    confdb/confdb.h \
    confdb/confdb_private.h \
    confdb/confdb_setup.h \
    providers/data_provider.h \
    providers/dp_interfaces.h \
    providers/dp_backend.h \
    providers/providers.h \
    providers/krb5/krb5_auth.h \
    providers/ldap/sdap.h \
    providers/ldap/sdap_async.h \
    tools/tools_util.h \
    krb5_plugin/sssd_krb5_locator_plugin.h \
    resolv/async_resolv.h \
    resolv/ares/ares_parse_srv_reply.h \
    resolv/ares/ares_parse_txt_reply.h


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
    responder/nss/nsssrv_nc.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_RESPONDER_OBJ)
sssd_nss_LDADD = \
    $(SSSD_LIBS)

sssd_pam_SOURCES = \
    responder/pam/pam_LOCAL_domain.c \
    responder/pam/pamsrv.c \
    responder/pam/pamsrv_cache.c \
    responder/pam/pamsrv_cmd.c \
    responder/pam/pamsrv_dp.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_RESPONDER_OBJ)
sssd_pam_LDADD = \
    $(SSSD_LIBS)

sssd_dp_SOURCES = \
    providers/data_provider.c\
    $(SSSD_UTIL_OBJ)

sssd_dp_LDADD = $(SSSD_LIBS)

sssd_be_SOURCES = \
    providers/data_provider_be.c \
    $(SSSD_UTIL_OBJ)
sssd_be_LDADD = $(SSSD_LIBS)
sssd_be_LDFLAGS = \
    -Wl,--version-script,$(srcdir)/providers/sssd_be.exports \
    -export-dynamic

dist_noinst_DATA = \
    examples/sssd.conf \
    examples/sssdproxylocal \
    examples/sssdproxytest \
    examples/sudo \
    providers/sssd_be.exports

######################
# Command-line Tools #
######################
sss_useradd_SOURCES = \
    tools/sss_useradd.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ)
sss_useradd_LDADD = \
    $(SSSD_LIBS)

sss_userdel_SOURCES = \
    tools/sss_userdel.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ)
sss_userdel_LDADD = \
    $(SSSD_LIBS)

sss_groupadd_SOURCES = \
    tools/sss_groupadd.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ)
sss_groupadd_LDADD = \
    $(SSSD_LIBS)

sss_groupdel_SOURCES = \
    tools/sss_groupdel.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ)
sss_groupdel_LDADD = \
    $(SSSD_LIBS)

sss_usermod_SOURCES = \
    tools/sss_usermod.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ)
sss_usermod_LDADD = \
    $(SSSD_LIBS)

sss_groupmod_SOURCES = \
    tools/sss_groupmod.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_TOOLS_OBJ)
sss_groupmod_LDADD = \
    $(SSSD_LIBS)

#################
# Feature Tests #
#################
if HAVE_CHECK
sysdb_tests_SOURCES = \
    tests/sysdb-tests.c \
    $(SSSD_UTIL_OBJ)
sysdb_tests_CFLAGS = \
    $(CHECK_CFLAGS)
sysdb_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS)
endif

stress_tests_SOURCES = \
    tests/stress-tests.c \
    $(SSSD_UTIL_OBJ)
stress_tests_LDADD = \
    $(SSSD_LIBS)

if HAVE_CHECK
resolv_tests_SOURCES = \
    tests/resolv-tests.c \
    $(SSSD_UTIL_OBJ) \
    $(SSSD_RESOLV_OBJ)
resolv_tests_CFLAGS = \
    $(CHECK_CFLAGS)
resolv_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS) \
    $(CARES_LIBS)
endif

####################
# Plugin Libraries #
####################
libsss_ldap_la_SOURCES = \
    providers/ldap/ldap_id.c \
    providers/ldap/ldap_auth.c \
    providers/ldap/sdap_async.c \
    providers/ldap/sdap.c
libsss_ldap_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(LDAP_CFLAGS)
libsss_ldap_la_LIBADD = \
    $(PAM_LIBS)
libsss_ldap_la_LDFLAGS = \
    -version-info 1:0:0 \
    -module

libsss_proxy_la_SOURCES = \
    providers/proxy.c
libsss_proxy_la_CFLAGS = \
    $(AM_CFLAGS)
libsss_proxy_la_LIBADD = \
    $(PAM_LIBS)
libsss_proxy_la_LDFLAGS = \
    -version-info 1:0:0 \
    -module

libsss_krb5_la_SOURCES = \
    providers/krb5/krb5_auth.c \
    providers/krb5/tgt_req_child.c
libsss_krb5_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(KRB5_CFLAGS)
libsss_krb5_la_LIBADD = \
    $(PAM_LIBS) \
    $(KRB5_LIBS)
libsss_krb5_la_LDFLAGS = \
    -version-info 1:0:0 \
    -module

memberof_la_SOURCES = \
    ldb_modules/memberof.c
memberof_la_CFLAGS = \
    $(AM_CFLAGS)
memberof_la_LDFLAGS = \
    -avoid-version \
    -module

sssd_krb5_locator_plugin_la_SOURCES = \
    krb5_plugin/sssd_krb5_locator_plugin.c
sssd_krb5_locator_plugin_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(KRB5_CFLAGS)
sssd_krb5_locator_plugin_la_LDFLAGS = \
    -avoid-version \
    -module

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
		man/sssd.8 man/sssd.conf.5 man/sssd-ldap.5 man/sssd-krb5.5

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

dist_init_SCRIPTS = \
    sysv/sssd

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
    $(DESTDIR)$(shadow_utils_path)

install-exec-hook: installsssddirs

CLEANFILES = *.X */*.X */*/*.X
