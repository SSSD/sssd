#DEBUG_FLAGS=@DEBUG_VAR@
TRACE_LEVEL=@TRACE_VAR@

topdir=..
AM_CPPFLAGS = -Wall -I$(topdir) -I$(topdir)/trace $(TRACE_LEVEL)

# Set up the pkg-config file
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = collection.pc

# Build libraty
lib_LTLIBRARIES = libcollection.la
libcollection_la_SOURCES = collection.c collection_tools.c collection_tools.h collection_class.h
include_HEADERS = collection.h collection_tools.h

# Build unit test
noinst_PROGRAMS = collection_ut
collection_ut_SOURCES = collection_ut.c
collection_ut_LDADD = libcollection.la -lm -lz
