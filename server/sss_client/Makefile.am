SUBDIRS = po

pipepath=@pipepath@
localedir = @localedir@

topdir=.
AM_CPPFLAGS = \
    -I$(topdir) \
    -DLOCALEDIR=\"$(localedir)\" \
    -DSSS_NSS_SOCKET_NAME=\"$(pipepath)/nss\" \
    -DSSS_PAM_SOCKET_NAME=\"$(pipepath)/pam\" \
    -DSSS_PAM_PRIV_SOCKET_NAME=\"$(pipepath)/private/pam\"
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS =
if WANT_AUX_INFO
    AM_CFLAGS += -aux-info $@.X
endif

if HAVE_GCC
    AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
                 -Wcast-qual -Wcast-align -Wwrite-strings
endif

nsslibdir = @nsslibdir@
pamlibdir = $(nsslibdir)/security

nsslib_LTLIBRARIES = libnss_sss.la
pamlib_LTLIBRARIES = pam_sss.la

libnss_sss_la_SOURCES = \
    common.c \
    passwd.c \
    group.c \
    sss_cli.h
libnss_sss_la_LDFLAGS = \
    -module \
    -version-info 2:0:0 \
    -Wl,--version-script,$(srcdir)/sss_nss.exports

pam_sss_la_SOURCES = \
    pam_sss.c \
    common.c \
    sss_cli.h \
    sss_pam_macros.h

pam_sss_la_LDFLAGS = \
    -lpam \
    -module \
    -avoid-version \
    -Wl,--version-script,$(srcdir)/sss_pam.exports

noinst_PROGRAMS = pam_test_client
pam_test_client_SOURCES = pam_test_client.c
pam_test_client_LDFLAGS = -lpam -lpam_misc


EXTRA_DIST = build/config.rpath
dist_noinst_DATA = \
    sss_nss.exports \
    sss_pam.exports \
    m4

install-data-hook:
	rm $(DESTDIR)/$(nsslibdir)/libnss_sss.so.2 \
       $(DESTDIR)/$(nsslibdir)/libnss_sss.so
	mv $(DESTDIR)/$(nsslibdir)/libnss_sss.so.2.0.0 $(DESTDIR)/$(nsslibdir)/libnss_sss.so.2

############
# MANPAGES #
############

#Special Rules:
export SGML_CATALOG_FILES
DOCBOOK_XSLT = http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl
XMLLINT_FLAGS = --catalogs --postvalid --nonet --xinclude --noout
XSLTPROC_FLAGS = --catalogs --xinclude --nonet

dist_man_MANS = man/pam_sss.8

SUFFIXES = .8.xml .8
.8.xml.8:
	$(XMLLINT) $(XMLLINT_FLAGS) $<
	$(XSLTPROC) -o $@  $(XSLTPROC_FLAGS) $(DOCBOOK_XSLT) $<
CLEANFILES = *.X

tests: all $(check_PROGRAMS)

