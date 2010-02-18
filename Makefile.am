SUBDIRS = common server sss_client

DISTCHECK_CONFIGURE_FLAGS = --with-ldb-lib-dir="$$dc_install_base"/lib/ldb

RPMBUILD ?= $(PWD)/rpmbuild

#Some old versions of automake don't define builddir
builddir ?= .

dist_noinst_DATA = \
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

rpms: dist-gzip rpmroot
	cp $(builddir)/contrib/sssd.spec $(RPMBUILD)/SPECS
	cp $(distdir).tar.gz $(RPMBUILD)/SOURCES
	cd $(RPMBUILD); \
	rpmbuild --define "_topdir $(RPMBUILD)" -ba SPECS/sssd.spec

if GIT_CHECKOUT
prerelease-rpms:
	cp $(srcdir)/version.m4 $(srcdir)/version.m4.orig
	sed -e "s/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.*\])/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.`date +%Y%m%d`git`git log -1 --pretty=format:%h`\])/" < $(srcdir)/version.m4.orig > $(srcdir)/version.m4
	$(MAKE) rpms
	mv $(srcdir)/version.m4.orig $(srcdir)/version.m4
endif

# make srpms will use the old digest algorithm to be compatible
# with RHEL5
srpms: dist-gzip rpmroot
	cp $(builddir)/contrib/sssd.spec $(RPMBUILD)/SPECS
	cp $(distdir).tar.gz $(RPMBUILD)/SOURCES
	cd $(RPMBUILD); \
	rpmbuild --define "_topdir $(RPMBUILD)" \
	         --define _source_filedigest_algorithm=1 \
	         -bs SPECS/sssd.spec

if GIT_CHECKOUT
prerelease-srpms:
	cp $(srcdir)/version.m4 $(srcdir)/version.m4.orig
	sed -e "s/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.*\])/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.`date +%Y%m%d`git`git log -1 --pretty=format:%h`\])/" < $(srcdir)/version.m4.orig > $(srcdir)/version.m4
	$(MAKE) srpms
	mv $(srcdir)/version.m4.orig $(srcdir)/version.m4
endif

tests: all
	for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done

