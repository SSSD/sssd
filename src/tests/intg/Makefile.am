AM_CFLAGS = $(my_CFLAGS)
dist_noinst_DATA = \
    __init__.py \
    config.py.m4 \
    util.py \
    sssd_nss.py \
    sssd_id.py \
    sssd_ldb.py \
    sssd_netgroup.py \
    sssd_passwd.py \
    sssd_group.py \
    ds.py \
    ds_openldap.py \
    ent.py \
    ent_test.py \
    ldap_ent.py \
    ldap_local_override_test.py \
    util.py \
    test_enumeration.py \
    test_ldap.py \
    test_memory_cache.py \
    test_session_recording.py \
    test_netgroup.py \
    test_sssctl.py \
    files_ops.py \
    test_files_provider.py \
    kdc.py \
    krb5utils.py \
    test_pac_responder.py \
    data/ad_data.ldif \
    data/ad_schema.ldif \
    data/cert_schema.ldif \
    data/ssh_schema.ldif \
    data/sudo_schema.ldif \
    test_pysss_nss_idmap.py \
    test_infopipe.py \
    test_ssh_pubkey.py \
    test_pam_responder.py \
    test_resolver.py \
    conftest.py \
    sssd_hosts.py \
    sssd_nets.py \
    $(NULL)

EXTRA_DIST = data/cwrap-dbus-system.conf.in

dbussysconfdir = $(sysconfdir)/dbus-1
dbusservicedir = $(datadir)/dbus-1/system-services

if INTG_BUILD
lib_LTLIBRARIES = getsockopt_wrapper.la

getsockopt_wrapper_la_SOURCES = \
    getsockopt_wrapper.c
getsockopt_wrapper_la_CFLAGS = \
    $(AM_CFLAGS)
getsockopt_wrapper_la_LIBADD = \
    $(LIBADD_DL) \
    $(NULL)
getsockopt_wrapper_la_LDFLAGS = \
    -avoid-version \
    -module

bin_PROGRAMS = sss_netgroup_thread_test

sss_netgroup_thread_test_SOURCES = \
    sss_netgroup_thread_test.c \
    $(NULL)
sss_netgroup_thread_test_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
sss_netgroup_thread_test_LDADD = \
    -lpthread \
    $(NULL)

nsslib_LTLIBRARIES = libnss_call.la
libnss_call_la_SOURCES = \
    nss_call.c \
    $(NULL)
libnss_call_la_LDFLAGS = \
    -module \
    -version-info 2:0:0 \
    $(NULL)

dist_dbussysconf_DATA = cwrap-dbus-system.conf

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(runstatedir)/dbus
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/session.d

endif

if BUILD_KCM_RENEWAL
KCM_RENEW = "enabled"
else
KCM_RENEW = "disabled"
endif

if BUILD_FILES_PROVIDER
FILES_PROVIDER = "enabled"
else
FILES_PROVIDER = "disabled"
endif


cwrap-dbus-system.conf: data/cwrap-dbus-system.conf.in Makefile
	$(SED) -e "s!@runstatedir[@]!$(runstatedir)!" \
           -e "s!@dbusservicedir[@]!$(dbusservicedir)!" \
       $< > $@

config.py: config.py.m4
	m4 -D "prefix=\`$(prefix)'" \
	   -D "sysconfdir=\`$(sysconfdir)'" \
	   -D "nsslibdir=\`$(nsslibdir)'" \
	   -D "dbpath=\`$(dbpath)'" \
	   -D "pubconfpath=\`$(pubconfpath)'" \
	   -D "pidpath=\`$(pidpath)'" \
	   -D "logpath=\`$(logpath)'" \
	   -D "mcpath=\`$(mcpath)'" \
	   -D "secdbpath=\`$(secdbpath)'" \
	   -D "libexecpath=\`$(libexecdir)'" \
	   -D "runstatedir=\`$(runstatedir)'" \
	   -D "abs_builddir=\`$(abs_builddir)'" \
	   -D "session_recording_shell=\`$(session_recording_shell)'" \
	   -D "py2execdir=\`$(py2execdir)'" \
	   -D "py3execdir=\`$(py3execdir)'" \
	   -D "python2dir=\`$(python2dir)'" \
	   -D "python3dir=\`$(python3dir)'" \
	   $< > $@

root:
	: "Create directory for emulated root's D-Bus cookies."
	: "See http://dbus.freedesktop.org/doc/dbus-specification.html#auth-mechanisms"
	$(MKDIR_P) -m 0700 root/.dbus-keyrings

passwd: root
	echo "root:x:0:0:root:$(abs_builddir)/root:/bin/bash" > $@

group:
	echo "root:x:0:" > $@

PAM_SERVICE_DIR=pam_service_dir
pam_sss_service:
	$(MKDIR_P) $(PAM_SERVICE_DIR)
	echo "auth     required       $(DESTDIR)$(pammoddir)/pam_sss.so"  > $(PAM_SERVICE_DIR)/$@
	echo "account  required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@
	echo "password required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@
	echo "session  required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@

pam_sss_alt_service:
	$(MKDIR_P) $(PAM_SERVICE_DIR)
	echo "auth     required       $(DESTDIR)$(pammoddir)/pam_sss.so"  > $(PAM_SERVICE_DIR)/$@
	echo "account  required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@
	echo "password required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@
	echo "session  required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@

pam_sss_sc_required:
	$(MKDIR_P) $(PAM_SERVICE_DIR)
	echo "auth     required       $(DESTDIR)$(pammoddir)/pam_sss.so require_cert_auth retry=1"  > $(PAM_SERVICE_DIR)/$@
	echo "account  required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@
	echo "password required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@
	echo "session  required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@

pam_sss_try_sc:
	$(MKDIR_P) $(PAM_SERVICE_DIR)
	echo "auth     required       $(DESTDIR)$(pammoddir)/pam_sss.so try_cert_auth"  > $(PAM_SERVICE_DIR)/$@
	echo "account  required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@
	echo "password required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@
	echo "session  required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@

pam_sss_allow_missing_name:
	$(MKDIR_P) $(PAM_SERVICE_DIR)
	echo "auth     required       $(DESTDIR)$(pammoddir)/pam_sss.so allow_missing_name"  > $(PAM_SERVICE_DIR)/$@
	echo "account  required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@
	echo "password required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@
	echo "session  required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@

pam_sss_domains:
	$(MKDIR_P) $(PAM_SERVICE_DIR)
	echo "auth     sufficient       $(DESTDIR)$(pammoddir)/pam_sss.so forward_pass domains=wrong.dom1"  > $(PAM_SERVICE_DIR)/$@
	echo "auth     sufficient       $(DESTDIR)$(pammoddir)/pam_sss.so forward_pass domains=wrong.dom2"  >> $(PAM_SERVICE_DIR)/$@
	echo "auth     sufficient       $(DESTDIR)$(pammoddir)/pam_sss.so forward_pass domains=wrong.dom3"  >> $(PAM_SERVICE_DIR)/$@
	echo "auth     sufficient       $(DESTDIR)$(pammoddir)/pam_sss.so forward_pass domains=krb5_auth"  >> $(PAM_SERVICE_DIR)/$@
	echo "auth     required         pam_deny.so" >> $(PAM_SERVICE_DIR)/$@
	echo "account  required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@
	echo "password required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@
	echo "session  required       $(DESTDIR)$(pammoddir)/pam_sss.so" >> $(PAM_SERVICE_DIR)/$@

CLEANFILES=config.py config.pyc passwd group

clean-local:
	rm -Rf root
	rm -f $(builddir)/cwrap-dbus-system.conf

PAM_CERT_DB_PATH="$(abs_builddir)/../test_CA/SSSD_test_CA.pem"
SOFTHSM2_CONF="$(abs_builddir)/../test_CA/softhsm2_one.conf"
SOFTHSM2_TWO_CONF="$(abs_builddir)/../test_CA/softhsm2_two.conf"

intgcheck-installed: config.py passwd group pam_sss_service pam_sss_alt_service pam_sss_sc_required pam_sss_try_sc pam_sss_allow_missing_name pam_sss_domains sss_netgroup_thread_test
	pipepath="$(DESTDIR)$(pipepath)"; \
	if test $${#pipepath} -gt 80; then \
	    echo "error: Pipe directory path too long," \
	         "D-Bus won't be able to open sockets" >&2; \
	    exit 1; \
	fi
	set -e; \
	cd "$(abs_srcdir)"; \
	nss_wrapper=$$(pkg-config --libs nss_wrapper); \
	uid_wrapper=$$(pkg-config --libs uid_wrapper); \
	unset HOME; \
	PATH="$$(dirname -- $(SLAPD)):$$PATH" \
	PATH="$(DESTDIR)$(sbindir):$(DESTDIR)$(bindir):$$PATH" \
	PATH="$$PATH:$(abs_builddir):$(abs_srcdir)" \
	LANG=C \
	PYTHONPATH="$(abs_builddir):$(abs_srcdir)" \
	LDB_MODULES_PATH="$(DESTDIR)$(ldblibdir)" \
	NON_WRAPPED_UID=$$(id -u) \
	LD_PRELOAD="$(libdir)/getsockopt_wrapper.so:$$nss_wrapper:$$uid_wrapper" \
	LD_LIBRARY_PATH="$$LD_LIBRARY_PATH:$(DESTDIR)$(nsslibdir)" \
	NSS_WRAPPER_PASSWD="$(abs_builddir)/passwd" \
	NSS_WRAPPER_GROUP="$(abs_builddir)/group" \
	NSS_WRAPPER_MODULE_SO_PATH="$(DESTDIR)$(nsslibdir)/libnss_sss.so.2" \
	NSS_WRAPPER_MODULE_FN_PREFIX="sss" \
	UID_WRAPPER=1 \
	UID_WRAPPER_ROOT=1 \
	PAM_WRAPPER=0 \
	PAM_WRAPPER_SERVICE_DIR="$(abs_builddir)/$(PAM_SERVICE_DIR)" \
	PAM_WRAPPER_PATH=$$(pkg-config --libs pam_wrapper) \
	PAM_CERT_DB_PATH=$(PAM_CERT_DB_PATH) \
	ABS_SRCDIR=$(abs_srcdir) \
	SOFTHSM2_CONF=$(SOFTHSM2_CONF) \
	SOFTHSM2_TWO_CONF=$(SOFTHSM2_TWO_CONF) \
	KCM_RENEW=$(KCM_RENEW) \
	FILES_PROVIDER=$(FILES_PROVIDER) \
	DBUS_SOCK_DIR="$(DESTDIR)$(runstatedir)/dbus/" \
	DBUS_SESSION_BUS_ADDRESS="unix:path=$$DBUS_SOCK_DIR/fake_socket" \
	DBUS_SYSTEM_BUS_ADDRESS="unix:path=$$DBUS_SOCK_DIR/system_bus_socket" \
	DBUS_SYSTEM_BUS_DEFAULT_ADDRESS="$$DBUS_SYSTEM_BUS_ADDRESS" \
	    fakeroot $(PYTHON_EXEC_INTG) -m pytest -v -r a --tb=native $(INTGCHECK_PYTEST_ARGS) .
	rm -f $(DESTDIR)$(logpath)/*
