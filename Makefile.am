SUBDIRS = replace common server sss_client

RPMBUILD ?= $(PWD)/rpmbuild

dist_noinst_DATA = \
    sssd.spec.in \
    BUILD.txt \
    COPYING

rpmroot:
	mkdir -p $(RPMBUILD)/BUILD
	mkdir -p $(RPMBUILD)/RPMS
	mkdir -p $(RPMBUILD)/SOURCES
	mkdir -p $(RPMBUILD)/SPECS
	mkdir -p $(RPMBUILD)/SRPMS

rpmdistdir:
	mkdir -p dist/rpms
	mkdir -p dist/srpms

rpms: dist-gzip rpmroot rpmdistdir
	cp $(builddir)/sssd.spec $(RPMBUILD)/SPECS
	cp $(distdir).tar.gz $(RPMBUILD)/SOURCES
	cd $(RPMBUILD); rpmbuild --define "_topdir $(RPMBUILD)" -ba SPECS/sssd.spec
