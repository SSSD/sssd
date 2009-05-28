topdir=.
sssdlibexecdir = $(libexecdir)/sssd
sssdlibdir = $(libdir)/sssd
ldblibdir = $(libdir)/ldb
sssdconfdir = $(sysconfdir)/sssd
dbusintrospectdir = $(datarootdir)/sssd/introspect
dbuspolicydir = $(sysconfdir)/dbus-1/system.d

dbpath = @dbpath@
pluginpath = @pluginpath@
pidpath = @pidpath@
pipepath = @pipepath@
initdir = @initdir@
shadow_utils_path = @shadow_utils_path@

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

if BUILD_POLICYKIT
sssd_pk = sssd_pk
polkit_headers = \
    polkit/sssd_polkit.h
endif

if BUILD_INFOPIPE
infpintrospectdir = $(dbusintrospectdir)/infopipe
sssd_info = sssd_info
infopipe_tests = infopipe-tests
infopipe_privileged_tests = infopipe-privileged-tests
infopipe_headers = \
    infopipe/infopipe_private.h \
    infopipe/sysbus.h \
    infopipe/infopipe.h
endif

sssdlibexec_PROGRAMS = \
    sssd_nss \
    sssd_pam \
    sssd_dp \
    sssd_be \
    $(sssd_pk) \
    $(sssd_info)

if BUILD_TESTS
noinst_PROGRAMS = \
    sysdb-tests \
    stress-tests \
    $(infopipe_tests) \
    $(infopipe_privileged_tests)
endif

sssdlib_LTLIBRARIES = \
    libsss_ldap.la \
    libsss_proxy.la

ldblib_LTLIBRARIES = \
    memberof.la

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

AM_CPPFLAGS = -Wall \
    -Iinclude \
    -I.. \
    -I$(DBUS_CFLAGS) \
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
    $(INI_CFG_CFLAGS)\
    -DLIBDIR=\"$(libdir)\" \
    -DVARDIR=\"$(localstatedir)\" \
    -DSHLIBEXT=\"$(SHLIBEXT)\" \
    -DSSSD_LIBEXEC_PATH=\"$(sssdlibexecdir)\" \
    -DSHADOW_UTILS_PATH=\"$(SHADOW_UTILS_PATH)\" \
    -DSSSD_INTROSPECT_PATH=\"$(dbusinstropectdir)\" \
    -DSSSD_CONF_DIR=\"$(sssdconfdir)\" \
    -DUSE_MMAP=1

SSSD_DEBUG_OBJ = \
    util/debug.c

SSSD_UTIL_OBJ = \
    confdb/confdb.c \
    db/sysdb.c \
    db/sysdb_ops.c \
    db/sysdb_req.c \
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
    $(REPLACE_LIBS) \
    $(NSS_LIBS) \
    libsss_crypt.la

dist_noinst_HEADERS = \
    monitor/monitor.h \
    util/btreemap.h \
    util/nss_sha512crypt.h \
    util/dlinklist.h \
    util/util.h \
    config.h \
    monitor/monitor.h \
    monitor/monitor_sbus.h \
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
    providers/dp_sbus.h \
    providers/dp_interfaces.h \
    providers/dp_backend.h \
    providers/providers.h \
    tools/tools_util.h \
    $(infopipe_headers) \
    $(polkit_headers)

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
    responder/nss/nsssrv_dp.c \
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
sssd_be_LDFLAGS = -export-dynamic

if BUILD_POLICYKIT
sssd_pk_SOURCES = \
    polkit/sssd_polkit.c \
    $(SSSD_UTIL_OBJ)
sssd_pk_LDADD = $(SSSD_LIBS)
endif

if BUILD_INFOPIPE
sssd_info_SOURCES = \
    infopipe/infopipe.c \
    infopipe/infopipe_groups.c \
    infopipe/infopipe_users.c \
    infopipe/sysbus.c \
    $(SSSD_UTIL_OBJ)
sssd_info_LDADD = $(SSSD_LIBS)
dbuspolicy_DATA = \
    infopipe/org.freedesktop.sssd.infopipe.conf
infpintrospect_DATA = \
    infopipe/org.freedesktop.sssd.infopipe.Introspect.xml
endif

dist_noinst_DATA = \
    examples/sssd.conf \
    examples/sssdproxylocal \
    examples/sssdproxytest \
    examples/sudo

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
if BUILD_TESTS
sysdb_tests_SOURCES = \
    tests/sysdb-tests.c \
    $(SSSD_UTIL_OBJ)
sysdb_tests_CFLAGS = \
    $(CHECK_CFLAGS)
sysdb_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS)

stress_tests_SOURCES = \
    tests/stress-tests.c \
    $(SSSD_UTIL_OBJ)
stress_tests_LDADD = \
    $(SSSD_LIBS)

if BUILD_INFOPIPE
infopipe_tests_SOURCES = \
    tests/infopipe-tests.c \
    $(SSSD_UTIL_OBJ)
infopipe_tests_CFLAGS = \
    $(CHECK_CFLAGS)
infopipe_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS)

infopipe_privileged_tests_SOURCES = \
    tests/infopipe-privileged-tests.c \
    $(SSSD_UTIL_OBJ)
infopipe_privileged_tests_CFLAGS = \
    $(CHECK_CFLAGS)
infopipe_privileged_tests_LDADD = \
    $(SSSD_LIBS) \
    $(CHECK_LIBS)
endif #BUILD_INFOPIPE

endif #BUILD_TESTS

####################
# Plugin Libraries #
####################
libsss_ldap_la_SOURCES = \
    providers/ldap/ldap_id.c \
    providers/ldap/ldap_auth.c
libsss_ldap_la_CFLAGS = \
    $(AM_CFLAGS) \
    $(LDAP_CFLAGS)
libsss_ldap_la_LIBADD = \
    $(PAM_LIBS) \
    libsss_crypt.la
libsss_ldap_la_LDFLAGS = \
    -version-info 1:0:0 \
    -module

libsss_proxy_la_SOURCES = \
    providers/proxy.c
libsss_proxy_la_CFLAGS = \
    $(AM_CFLAGS)
libsss_proxy_la_LIBADD = \
    $(PAM_LIBS) \
    libsss_crypt.la
libsss_proxy_la_LDFLAGS = \
    -version-info 1:0:0 \
    -module

memberof_la_SOURCES = \
    ldb_modules/memberof.c
memberof_la_CFLAGS = \
    $(AM_CFLAGS)
memberof_la_LDFLAGS = \
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
		man/sssd.8 man/sssd.conf.5

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

dist_init_DATA = \
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

