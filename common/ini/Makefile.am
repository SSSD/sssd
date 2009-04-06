#DEBUG_FLAGS=@DEBUG_VAR@
TRACE_LEVEL=@TRACE_VAR@

topdir=..
AM_CPPFLAGS = -I$(topdir) -I$(topdir)/trace -I$(topdir)/collection $(TRACE_LEVEL)

# Build static libraty
noinst_LIBRARIES = libini_config.a
libini_config_a_SOURCES = ini_config.c collection.h trace.h collection_tools.h collection_class.h ini_config.h

# Build shared library
#lib_LTLIBRARIES = libini.la
#libini_la_SOURCES = ini_config.c collection.h trace.h collection_tools.h collection_class.h ini_config.h

noinst_PROGRAMS = ini_config_ut
ini_config_ut_SOURCES = ini_config_ut.c
ini_config_ut_LDADD = libini_config.a -lm -lz ../collection/libcollection.a
