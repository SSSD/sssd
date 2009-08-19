SUBDIRS = replace common server sss_client

RPMBUILD ?= $(PWD)/rpmbuild

#Some old versions of automake don't define builddir
builddir ?= .

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

rpms: dist-gzip rpmroot
	cp $(builddir)/sssd.spec $(RPMBUILD)/SPECS
	cp $(distdir).tar.gz $(RPMBUILD)/SOURCES
	cd $(RPMBUILD); rpmbuild --define "_topdir $(RPMBUILD)" -ba SPECS/sssd.spec

srpms: dist-gzip rpmroot
	cp $(builddir)/sssd.spec $(RPMBUILD)/SPECS
	cp $(distdir).tar.gz $(RPMBUILD)/SOURCES
	cd $(RPMBUILD); rpmbuild --define "_topdir $(RPMBUILD)" -bs SPECS/sssd.spec
