# The following variable is dependent on placement of this file
top_builddir = ../..

############
# MANPAGES #
############


# If no conditions are given, *all* conditionals are expanded. We don't want
# to include any conditions by default, so we need to pass a phony conditional
if BUILD_SUDO
# conditionals are delimeted with a semicolon
SUDO_CONDS = ;with_sudo
endif
if BUILD_AUTOFS
AUTOFS_CONDS = ;with_autofs
endif
if BUILD_SSH
SSH_CONDS = ;with_ssh
endif
if BUILD_PAC_RESPONDER
PAC_RESPONDER_CONDS = ;with_pac_responder
endif
if BUILD_KCM
KCM_CONDS = ;with_kcm
endif
if BUILD_SYSTEMTAP
STAP_CONDS = ;with_stap
endif
if GPO_DEFAULT_ENFORCING
GPO_CONDS = ;gpo_default_enforcing
else
GPO_CONDS = ;gpo_default_permissive
endif
if HAVE_SYSTEMD_UNIT
SYSTEMD_CONDS = ;have_systemd
endif
if BUILD_KCM_RENEWAL
KCM_RENEWAL_CONDS = ;enable_kcm_renewal
endif
if BUILD_LOCKFREE_CLIENT
LOCKFREE_CLIENT_CONDS = ;enable_lockfree_support
endif
if HAVE_INOTIFY
HAVE_INOTIFY_CONDS = ;have_inotify
endif
if BUILD_PASSKEY
PASSKEY_CONDS = ;build_passkey
endif
if BUILD_EXTENDED_ENUMERATION_SUPPORT
ENUM_CONDS = ;with_ext_enumeration
else
ENUM_CONDS = ;without_ext_enumeration
endif
if BUILD_ALLOW_REMOTE_DOMAIN_LOCAL_GROUPS
AD_CONDS = ;with_allow_remote_domain_local_groups
endif
if SSSD_NON_ROOT_USER
SSSD_NON_ROOT_USER_CONDS = ;with_non_root_user_support
else
SSSD_NON_ROOT_USER_CONDS = ;without_non_root_user_support
endif
if HAVE_LIBNL
LIBNL_CONDS = ;have_libnl
endif


CONDS = with_false$(SUDO_CONDS)$(AUTOFS_CONDS)$(SSH_CONDS)$(PAC_RESPONDER_CONDS)$(GPO_CONDS)$(SYSTEMD_CONDS)$(KCM_CONDS)$(STAP_CONDS)$(KCM_RENEWAL_CONDS)$(LOCKFREE_CLIENT_CONDS)$(HAVE_INOTIFY_CONDS)$(PASSKEY_CONDS)$(SSSD_NON_ROOT_USER_CONDS)$(ENUM_CONDS)$(LIBNL_CONDS)$(AD_CONDS)


#Special Rules:
export SGML_CATALOG_FILES
DOCBOOK_XSLT = @DOCBOOK_XSLT@
DOCBOOK_XSLT ?= http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl
XMLLINT_FLAGS = --catalogs --postvalid --nonet --noent --xinclude --noout
XSLTPROC_FLAGS = --catalogs --xinclude --nonet

if HAVE_PROFILE_CATALOGS
XSLTPROC_FLAGS += --stringparam profile.condition "$(CONDS)"
endif

EXTRA_DIST = $(wildcard $(srcdir)/*.xml) $(wildcard $(srcdir)/include/*.xml)
man_MANS = \
    sssd.8 sssd.conf.5 sssd-ldap.5 sssd-ldap-attributes.5 \
    sssd-krb5.5 sssd-simple.5 sss-certmap.5 sssd-ifp.5 \
    sssd_krb5_locator_plugin.8 sssd_krb5_localauth_plugin.8 \
    pam_sss.8 pam_sss_gss.8 sss_obfuscate.8 sss_cache.8 sss_debuglevel.8 \
	sss_seed.8 sss_override.8 idmap_sss.8 sssctl.8 sssd-session-recording.5 \
    $(NULL)

if BUILD_SAMBA
man_MANS += sssd-ipa.5 sssd-ad.5
endif

if BUILD_SSH
man_MANS += sss_ssh_authorizedkeys.1 \
            sss_ssh_knownhosts.1
endif

if BUILD_SUDO
man_MANS += sssd-sudo.5
endif

if BUILD_KCM
man_MANS += sssd-kcm.8
endif

if BUILD_SYSTEMTAP
man_MANS += sssd-systemtap.5
endif

if BUILD_NFS_IDMAP
man_MANS += sss_rpcidmapd.5
endif

if BUILD_PASSKEY
man_MANS += sssd-passkey.5
endif

$(builddir)/src/man/sssd_user_name.include:
	@mkdir -p $(builddir)/src/man
	@echo -n $(SSSD_USER) > $(builddir)/src/man/sssd_user_name.include

%.1: %.1.xml
	$(XMLLINT) $(XMLLINT_FLAGS) $<
	$(XSLTPROC) -o $@  $(XSLTPROC_FLAGS) $(DOCBOOK_XSLT) $<

%.3: %.3.xml
	$(XMLLINT) $(XMLLINT_FLAGS) $<
	$(XSLTPROC) -o $@  $(XSLTPROC_FLAGS) $(DOCBOOK_XSLT) $<

%.5: %.5.xml $(builddir)/src/man/sssd_user_name.include
	$(XMLLINT) --path "$(srcdir)/src/man:$(builddir)/src/man" $(XMLLINT_FLAGS) $<
	$(XSLTPROC) --path "$(srcdir)/src/man:$(builddir)/src/man" -o $@  $(XSLTPROC_FLAGS) $(DOCBOOK_XSLT) $<

%.8: %.8.xml
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
CFG_PAGES = $(addprefix $(srcdir)/, $(shell grep '\[type:docbook\]' $(PO4A_CONFIG) | awk '{print $$2}' | tr '\n' ' '))
NONTRANSLATED_PAGES = $(filter-out $(CFG_PAGES), $(XML_DOC))


# FIXME: Use a stamp file until po4a supports them internally.
man.stamp: $(XML_DOC) $(POTFILE) $(PO4A_CONFIG)
	cd $(srcdir) && \
	$(PO4A) $(PO4A_BUILD_OPTS) $(PO4A_CONFIG)
	touch $@

update-po:
	@if test x"$(NONTRANSLATED_PAGES)" != "x"; then \
	    echo "The following pages are not translated" $(NONTRANSLATED_PAGES); \
	    exit 1; \
	fi
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


clean-local:
	for lang in $(LINGUAS); do \
		if [ -d $$lang ]; then \
			rm -rf $$lang; \
		fi \
	done
	rm -f $(man_MANS)
	rm -f man.stamp
	rm -f $(builddir)/src/man/sssd_user_name.include

else

man.stamp: $(XML_DOC)
	touch $@

clean-local:
	rm -f $(man_MANS)
	rm -f man.stamp
	rm -f $(builddir)/src/man/sssd_user_name.include

endif

# Generate translated manual pages
all-local: all-local-@USE_NLS@
all-local-no:
all-local-yes: man.stamp
	if [ -z $$recursion ]; then \
		for lang in $(LINGUAS); do \
			if [ -d $$lang ]; then \
				sources=$$(ls -1 $$lang/*.xml); \
				manpages=$$(echo $$sources | $(SED) 's/\.xml//g'); \
				$(MAKE) recursion=1 man_MANS="$$manpages"; \
			fi \
		done \
	fi

install-data-local: install-data-local-@USE_NLS@
install-data-local-no:
install-data-local-yes:
	for lang in $(LINGUAS); do \
		if [ -d $$lang ]; then \
			sources=$$(ls -1 $$lang/*.xml); \
			manpages=$$(echo $$sources | $(SED) 's/\.xml//g'); \
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
			sources=$$(ls -1 $$lang/*.xml); \
			manpages=$$(echo $$sources | $(SED) 's/\.xml//g'); \
			$(MAKE) uninstall-man \
				mandir="$(mandir)/$$lang" \
				man_MANS="$$manpages"; \
		fi \
	done
