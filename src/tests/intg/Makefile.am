dist_noinst_DATA = \
    config.py.m4 \
    sssd_id.py \
    ds.py \
    ds_openldap.py \
    ent.py \
    ent_test.py \
    ldap_ent.py \
    ldap_local_override_test.py \
    ldap_test.py \
    util.py \
    test_memory_cache.py \
    $(NULL)

config.py: config.py.m4
	m4 -D "prefix=\`$(prefix)'" \
	   -D "sysconfdir=\`$(sysconfdir)'" \
	   -D "dbpath=\`$(dbpath)'" \
	   -D "pidpath=\`$(pidpath)'" \
	   -D "logpath=\`$(logpath)'" \
	   -D "mcpath=\`$(mcpath)'" \
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
	LD_PRELOAD="$$nss_wrapper $$uid_wrapper" \
	NSS_WRAPPER_PASSWD="$(abs_builddir)/passwd" \
	NSS_WRAPPER_GROUP="$(abs_builddir)/group" \
	NSS_WRAPPER_MODULE_SO_PATH="$(DESTDIR)$(nsslibdir)/libnss_sss.so.2" \
	NSS_WRAPPER_MODULE_FN_PREFIX="sss" \
	UID_WRAPPER=1 \
	UID_WRAPPER_ROOT=1 \
	    fakeroot $(PYTHON2) $(PYTEST) -v --tb=native $(INTGCHECK_PYTEST_ARGS) .
	rm -f $(DESTDIR)$(logpath)/*
