PACKAGE_NAME = sssd
PACKAGE_VERSION = 0.3.0
TARGET ?= master
SUBDIRS = common server replace sss_client
TARBALL_PREFIX = $(PACKAGE_NAME)-$(PACKAGE_VERSION)
TARBALL = $(TARBALL_PREFIX).tar.gz
LIBDIR ?= /usr/lib
RPMBUILD ?= $(PWD)/rpmbuild
DOC = BUILD.txt COPYING

all:

clean:
	rm -Rf dist
	rm -Rf $(RPMBUILD)

realdistclean: clean
	-make -C common maintainer-clean
	-make -C server realdistclean

archive:
	-mkdir -p dist/$(TARBALL_PREFIX)
	git archive --format=tar --prefix=sssd/ $(TARGET) | (cd dist && tar xf -)
	@for subdir in $(SUBDIRS); do \
	    cp -pr dist/sssd/$$subdir dist/$(TARBALL_PREFIX)/.; \
	done

local-archive: realdistclean
	-mkdir -p dist/$(TARBALL_PREFIX)
	@for subdir in $(SUBDIRS); do \
	    cp -pr $$subdir dist/$(TARBALL_PREFIX)/.; \
	done
	cp -p $(DOC) dist/$(TARBALL_PREFIX)/.

tarballs: local-archive
	-mkdir -p dist/sources
	rm -f dist/sources/$(TARBALL)
	cd dist/$(TARBALL_PREFIX)/server; ./autogen.sh
	cd dist; tar cfz sources/$(TARBALL) $(TARBALL_PREFIX)


rpmroot:
	mkdir -p $(RPMBUILD)/BUILD
	mkdir -p $(RPMBUILD)/RPMS
	mkdir -p $(RPMBUILD)/SOURCES
	mkdir -p $(RPMBUILD)/SPECS
	mkdir -p $(RPMBUILD)/SRPMS

rpmdistdir:
	mkdir -p dist/rpms
	mkdir -p dist/srpms

rpms: tarballs rpmroot rpmdistdir
	cp sssd.spec $(RPMBUILD)/SPECS
	cp dist/sources/$(TARBALL) $(RPMBUILD)/SOURCES
	cd $(RPMBUILD); rpmbuild --define "_topdir $(RPMBUILD)" -ba SPECS/sssd.spec

