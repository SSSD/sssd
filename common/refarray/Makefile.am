TRACE_LEVEL=@TRACE_VAR@

topdir=$(srcdir)/..

AM_CFLAGS =

if HAVE_GCC
    AM_CFLAGS += \
        -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
        -Wcast-align -Wwrite-strings
endif

AM_CPPFLAGS = -I$(topdir)/trace -I$(topdir)/elapi/refarray $(TRACE_LEVEL)

ACLOCAL_AMFLAGS = -I m4

# Set up the pkg-config file
pkgconfigdir = $(libdir)/pkgconfig
dist_noinst_DATA = \
    ref_array.pc \
    m4

# Build library
noinst_LTLIBRARIES = libref_array.la
libref_array_la_SOURCES = \
    ref_array.c \
    ref_array.h

# Build unit test
check_PROGRAMS = ref_array_ut
ref_array_ut_SOURCES = ref_array_ut.c
ref_array_ut_LDADD = libref_array.la

TESTS = ref_array_ut

tests: all $(check_PROGRAMS)
