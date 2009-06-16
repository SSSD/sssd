SUBDIRS = po

topdir=.
AM_CPPFLAGS = \
    -I$(topdir) \
    -DLOCALEDIR=\"\$(localedir)\"
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS =
if WANT_AUX_INFO
    AM_CFLAGS += -aux-info $@.X
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
    -avoid-version

pam_sss_la_SOURCES = \
    pam_sss.c \
    common.c \
    sss_cli.h

pam_sss_la_CFLAGS = \
    -Wall \
    -Werror
pam_sss_la_LDFLAGS = \
    -lpam \
    -lpam_misc \
    -module \
    -avoid-version

noinst_PROGRAMS = pam_test_client
pam_test_client_SOURCES = pam_test_client.c
pam_test_client_LDFLAGS = -lpam -lpam_misc


EXTRA_DIST = build/config.rpath

install-data-hook:
	mv $(DESTDIR)/$(nsslibdir)/libnss_sss.so $(DESTDIR)/$(nsslibdir)/libnss_sss.so.2
