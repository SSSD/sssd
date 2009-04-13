#DEBUG_FLAGS=@DEBUG_VAR@
TRACE_LEVEL=@TRACE_VAR@

topdir=..
AM_CPPFLAGS = -Wall -I$(topdir) -I$(topdir)/trace -I$(topdir)/collection $(TRACE_LEVEL)

# Set up the pkg-config file
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ini_config.pc

# Build library
lib_LTLIBRARIES = libini_config.la
libini_config_la_SOURCES = ini_config.c collection.h collection_tools.h collection_class.h
include_HEADERS = ini_config.h

# Build unit test
noinst_PROGRAMS = ini_config_ut
ini_config_ut_SOURCES = ini_config_ut.c
ini_config_ut_LDADD = libini_config.la ../collection/libcollection.la
