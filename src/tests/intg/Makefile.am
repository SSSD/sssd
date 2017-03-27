dist_noinst_DATA = \
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
    $(NULL)

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
	PATH="$$(dirname -- $(SLAPD)):$$PATH" \
	PATH="$(DESTDIR)$(sbindir):$(DESTDIR)$(bindir):$$PATH" \
	PATH="$(abs_builddir):$(abs_srcdir):$$PATH" \
	PYTHONPATH="$(abs_builddir):$(abs_srcdir)" \
	LDB_MODULES_PATH="$(DESTDIR)$(ldblibdir)" \
	NON_WRAPPED_UID=$$(id -u) \
	LD_PRELOAD="$$nss_wrapper $$uid_wrapper" \
	NSS_WRAPPER_PASSWD="$(abs_builddir)/passwd" \
	NSS_WRAPPER_GROUP="$(abs_builddir)/group" \
	NSS_WRAPPER_MODULE_SO_PATH="$(DESTDIR)$(nsslibdir)/libnss_sss.so.2" \
	NSS_WRAPPER_MODULE_FN_PREFIX="sss" \
	UID_WRAPPER=1 \
	UID_WRAPPER_ROOT=1 \
	    fakeroot $(PYTHON2) $(PYTEST) -v --tb=native $(INTGCHECK_PYTEST_ARGS) .
	rm -f $(DESTDIR)$(logpath)/*
