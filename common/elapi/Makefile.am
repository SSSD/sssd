TRACE_LEVEL=@TRACE_VAR@

topdir=$(srcdir)/..

AM_CFLAGS =
if HAVE_GCC
    AM_CFLAGS += \
        -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
        -Wcast-align -Wwrite-strings
endif

AM_CPPFLAGS = -I$(topdir) -I$(topdir)/trace -I$(topdir)/collection $(TRACE_LEVEL)

ACLOCAL_AMFLAGS = -I m4

# Set up the pkg-config file
pkgconfigdir = $(libdir)/pkgconfig
dist_noinst_DATA = elapi.pc

# Build library
noinst_LTLIBRARIES = libelapi.la
libelapi_la_SOURCES = \
    elapi_event.c \
    elapi_event.h \
    elapi_event_priv.h \
    elapi.h

# Build unit test
noinst_PROGRAMS = elapi_ut
elapi_ut_SOURCES = elapi_ut.c
elapi_ut_LDADD = ../collection/libcollection.la libelapi.la
