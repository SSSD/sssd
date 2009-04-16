AM_CPPFLAGS = -Wall

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = dhash.pc

lib_LTLIBRARIES = libdhash.la
libdhash_la_SOURCES = dhash.c
pkginclude_HEADERS = dhash.h

check_PROGRAMS = dhash_test dhash_example
dhash_test_LDADD = dhash.o
dhash_example_LDADD = dhash.o

examplesdir = $(docdir)/examples
dist_examples_DATA = dhash_test.c dhash_example.c
