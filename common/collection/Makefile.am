#DEBUG_FLAGS=@DEBUG_VAR@
TRACE_LEVEL=@TRACE_VAR@

topdir=..
AM_CPPFLAGS = -Wall -I$(topdir) -I$(topdir)/trace $(TRACE_LEVEL)
ACLOCAL_AMFLAGS = -I m4

# Set up the pkg-config file
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = collection.pc

# Build library
lib_LTLIBRARIES = libcollection.la
libcollection_la_SOURCES = \
    collection.c \
    collection_tools.c

noinst_HEADERS = \
    collection_priv.h

include_HEADERS = collection.h collection_tools.h

# Build unit test
noinst_PROGRAMS = collection_ut
collection_ut_SOURCES = collection_ut.c
collection_ut_LDADD = libcollection.la
