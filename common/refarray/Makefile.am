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
pkgconfig_DATA = ref_array.pc

dist_noinst_DATA = m4

dist_include_HEADERS = ref_array.h

# Build library
lib_LTLIBRARIES = libref_array.la
libref_array_la_SOURCES = \
    ref_array.c
libref_array_la_LDFLAGS = \
    -version-info 1:0:0

# Build unit test
check_PROGRAMS = ref_array_ut
ref_array_ut_SOURCES = ref_array_ut.c
ref_array_ut_LDADD = libref_array.la

if HAVE_DOXYGEN
docs:
# A temp way of building docs until we hook into the package build
	rm -fR doc
	mkdir -p doc
	$(DOXYGEN) ref_array.cfg.doxy
else
docs:
	@echo "Doxygen not installed, cannot generate documentation"
	@exit 1
endif


TESTS = ref_array_ut

tests: all $(check_PROGRAMS)

clean-local:
	rm -Rf doc
