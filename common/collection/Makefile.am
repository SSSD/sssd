#DEBUG_FLAGS=@DEBUG_VAR@
TRACE_LEVEL=@TRACE_VAR@

topdir=..
AM_CPPFLAGS = -Wall -I$(topdir) -I$(topdir)/trace $(TRACE_LEVEL)

# Build static libraty
noinst_LIBRARIES = libcollection.a
libcollection_a_SOURCES = collection.c collection_tools.c collection.h trace.h collection_tools.h collection_class.h

# Build shared library - reserved for future
# lib_LTLIBRARIES = libcollection.la
# libcollection_la_SOURCES = collection.c collection_tools.c collection.h trace.h collection_tools.h collection_class.h

noinst_PROGRAMS = collection_ut
collection_ut_SOURCES = collection_ut.c
collection_ut_LDADD = libcollection.a -lm -lz
