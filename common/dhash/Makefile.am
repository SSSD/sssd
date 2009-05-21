AM_CPPFLAGS = -Wall
ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
dist_noinst_DATA = dhash.pc

noinst_LTLIBRARIES = libdhash.la
libdhash_la_SOURCES = \
    dhash.c \
    dhash.h

check_PROGRAMS = dhash_test dhash_example
dhash_test_LDADD = dhash.o
dhash_example_LDADD = dhash.o

examplesdir = $(docdir)/examples
dist_noinst_DATA += dhash_test.c dhash_example.c
