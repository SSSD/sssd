# The following variable is dependent on placement of this file
top_builddir = ../..

############
# MANPAGES #
############

#Special Rules:
export SGML_CATALOG_FILES
DOCBOOK_XSLT = http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl
XMLLINT_FLAGS = --catalogs --postvalid --nonet --xinclude --noout
XSLTPROC_FLAGS = --catalogs --xinclude --nonet

man_MANS = \
    sss_useradd.8 sss_userdel.8 sss_usermod.8 \
    sss_groupadd.8 sss_groupdel.8 sss_groupmod.8 \
    sssd.8 sssd.conf.5 sssd-ldap.5 \
    sssd-krb5.5 sssd-ipa.5 sssd-simple.5 \
    sssd_krb5_locator_plugin.8 sss_groupshow.8 \
    pam_sss.8 sss_obfuscate.8
EXTRA_DIST = $(man_MANS:%=%.xml) $(wildcard $(srcdir)/include/*.xml)

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

########################
# MANPAGE TRANSLATIONS #
########################

PO4A=@PO4A@
SED=@SED@

PACKAGE_DOC=sssd-docs

POTFILE = po/$(PACKAGE_DOC).pot
PO4A_CONFIG = po/po4a.cfg

# Extract the list of languages from the po4a config file.
LINGUAS_DIST = `$(SED) -ne 's/^.*\[po4a_langs\] \(.*\)$$/\1/p' $(srcdir)/$(PO4A_CONFIG)`

# If the user has not defined it let's use the default.
LINGUAS ?= $(LINGUAS_DIST)

PO4A_COMMON_OPTS = --option doctype=docbook \
		   --package-name $(PACKAGE_DOC) \
		   --variable builddir=$(CURDIR) \
		   --package-version $(PACKAGE_VERSION) \
		   --msgid-bugs-address sssd-devel@redhat.com \
		   --copyright-holder "Red Hat"

PO4A_BUILD_OPTS = $(PO4A_COMMON_OPTS) --no-backups

EXTRA_DIST += \
	$(POTFILE)\
	$(PO4A_CONFIG)

XML_DOC = $(wildcard $(srcdir)/*.xml) $(wildcard $(srcdir)/include/*.xml)

if HAVE_PO4A

# FIXME: Use a stamp file until po4a supports them internally.
man.stamp: $(XML_DOC)
	cd $(srcdir) && \
	$(PO4A) $(PO4A_BUILD_OPTS) $(PO4A_CONFIG)
	touch $@

update-po:
	cd $(srcdir) && \
	$(PO4A) $(PO4A_BUILD_OPTS) --force $(PO4A_CONFIG)

dist-hook: man.stamp
	if [ -f man.stamp ]; then \
		cp man.stamp $(distdir); \
		for lang in $(LINGUAS_DIST); do \
			cp $(srcdir)/po/$$lang.po $(distdir)/po; \
			$(mkdir_p) $(distdir)/$$lang; \
			cp -r $(builddir)/$$lang $(distdir)/; \
		done; \
	else \
		cp $(srcdir)/man.stamp $(distdir); \
		for lang in $(LINGUAS_DIST); do \
			cp $(srcdir)/po/$$lang.po $(distdir)/po; \
			$(mkdir_p) $(distdir)/$$lang; \
			cp -r $(srcdir)/$$lang $(distdir)/; \
		done; \
	fi


clean-local-no:
clean-local-yes:
	for lang in $(LINGUAS); do \
		if [ -d $$lang ]; then \
			rm -rf $$lang; \
		fi \
	done
	rm -f $(man_MANS)
	rm -f man.stamp

else

man.stamp: $(XML_DOC)
	touch $@

clean-local-no:
clean-local-yes:
	rm -f $(man_MANS)
	rm -f man.stamp

endif

clean-local: clean-local-@USE_NLS@
distclean-local: clean-local-@USE_NLS@
mostlyclean-local: clean-local-@USE_NLS@
maintainer-clean-local: clean-local-@USE_NLS@

# Generate translated manual pages
all-local: all-local-@USE_NLS@
all-local-no:
all-local-yes: man.stamp
	if [ -z $$recursion ]; then \
		for lang in $(LINGUAS); do \
			if [ -d $$lang ]; then \
				sources=$$(ls $$lang/*.xml); \
				manpages=$$(echo $$sources | $(SED) 's/\.xml//'); \
				$(MAKE) recursion=1 man_MANS="$$manpages"; \
			fi \
		done \
	fi

install-data-local: install-data-local-@USE_NLS@
install-data-local-no:
install-data-local-yes:
	for lang in $(LINGUAS); do \
		if [ -d $$lang ]; then \
			sources=$$(ls $$lang/*.xml); \
			manpages=$$(echo $$sources | $(SED) 's/\.xml//'); \
			$(MAKE) install-man \
				mandir="$(mandir)/$$lang" \
				man_MANS="$$manpages"; \
		fi \
	done

uninstall-local: uninstall-local-@USE_NLS@
uninstall-local-no:
uninstall-local-yes:
	for lang in $(LINGUAS); do \
		if [ -d $$lang ]; then \
			sources=$$(ls $$lang/*.xml); \
			manpages=$$(echo $$sources | $(SED) 's/\.xml//'); \
			$(MAKE) uninstall-man \
				mandir="$(mandir)/$$lang" \
				man_MANS="$$manpages"; \
		fi \
	done
