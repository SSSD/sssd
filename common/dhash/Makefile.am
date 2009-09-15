AM_CFLAGS =
if HAVE_GCC
    AM_CFLAGS += \
        -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
        -Wcast-align -Wwrite-strings
endif

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
dist_noinst_DATA = \
    dhash.pc \
    m4

noinst_LTLIBRARIES = libdhash.la
libdhash_la_SOURCES = \
    dhash.c \
    dhash.h

check_PROGRAMS = dhash_test dhash_example
dhash_test_LDADD = dhash.o
dhash_example_LDADD = dhash.o

examplesdir = $(docdir)/examples
dist_noinst_DATA += dhash_test.c dhash_example.c

tests: all $(check_PROGRAMS)
