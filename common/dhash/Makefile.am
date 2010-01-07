AM_CFLAGS =
if HAVE_GCC
    AM_CFLAGS += \
        -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
        -Wcast-align -Wwrite-strings
endif

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
dist_pkgconfig_DATA = dhash.pc

dist_noinst_DATA = m4

dist_include_HEADERS = dhash.h

lib_LTLIBRARIES = libdhash.la
libdhash_la_SOURCES = dhash.c
libdhash_la_LDFLAGS = \
    -version-info 1:0:0

check_PROGRAMS = dhash_test dhash_example
TESTS = $(check_PROGRAMS)

dhash_test_SOURCES = examples/dhash_test.c
dhash_test_LDADD = dhash.o

dhash_example_SOURCES = examples/dhash_example.c
dhash_example_LDADD = dhash.o

examplesdir = $(docdir)/examples
dist_examples_DATA = examples/dhash_test.c examples/dhash_example.c
dist_doc_DATA = README

tests: all $(check_PROGRAMS)
