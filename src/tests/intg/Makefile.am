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
    test_local_domain.py \
    util.py \
    test_enumeration.py \
    test_ldap.py \
    test_memory_cache.py \
    test_session_recording.py \
    test_ts_cache.py \
    test_netgroup.py \
    secrets.py \
    test_secrets.py \
    test_sssctl.py \
    files_ops.py \
    test_files_ops.py \
    test_files_provider.py \
    kdc.py \
    krb5utils.py \
    test_kcm.py \
    test_pac_responder.py \
    data/ad_data.ldif \
    data/ad_schema.ldif \
    test_pysss_nss_idmap.py \
    test_infopipe.py \
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

dist_dbussysconf_DATA = cwrap-dbus-system.conf

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(runstatedir)/dbus
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/session.d

endif

cwrap-dbus-system.conf: data/cwrap-dbus-system.conf.in Makefile
	$(SED) -e "s!@runstatedir[@]!$(runstatedir)!" \
           -e "s!@dbusservicedir[@]!$(dbusservicedir)!" \
       $< > $@

config.py: config.py.m4
	m4 -D "prefix=\`$(prefix)'" \
	   -D "sysconfdir=\`$(sysconfdir)'" \
	   -D "dbpath=\`$(dbpath)'" \
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

CLEANFILES=config.py config.pyc passwd group

clean-local:
	rm -Rf root
	rm -f $(builddir)/cwrap-dbus-system.conf

intgcheck-installed: config.py passwd group
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
	PYTHONPATH="$(abs_builddir):$(abs_srcdir)" \
	LDB_MODULES_PATH="$(DESTDIR)$(ldblibdir)" \
	NON_WRAPPED_UID=$$(id -u) \
	LD_PRELOAD="$(libdir)/getsockopt_wrapper.so:$$nss_wrapper:$$uid_wrapper" \
	NSS_WRAPPER_PASSWD="$(abs_builddir)/passwd" \
	NSS_WRAPPER_GROUP="$(abs_builddir)/group" \
	NSS_WRAPPER_MODULE_SO_PATH="$(DESTDIR)$(nsslibdir)/libnss_sss.so.2" \
	NSS_WRAPPER_MODULE_FN_PREFIX="sss" \
	UID_WRAPPER=1 \
	UID_WRAPPER_ROOT=1 \
	DBUS_SOCK_DIR="$(DESTDIR)$(runstatedir)/dbus/" \
	DBUS_SESSION_BUS_ADDRESS="unix:path=$$DBUS_SOCK_DIR/fake_socket" \
	DBUS_SYSTEM_BUS_ADDRESS="unix:path=$$DBUS_SOCK_DIR/system_bus_socket" \
	DBUS_SYSTEM_BUS_DEFAULT_ADDRESS="$$DBUS_SYSTEM_BUS_ADDRESS" \
	    fakeroot $(PYTHON2) $(PYTEST) -v --tb=native $(INTGCHECK_PYTEST_ARGS) .
	rm -f $(DESTDIR)$(logpath)/*
