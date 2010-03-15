#DEBUG_FLAGS=@DEBUG_VAR@
TRACE_LEVEL=@TRACE_VAR@

builddir ?= .

topdir=$(srcdir)/..
topbuilddir=$(builddir)/..

AM_CFLAGS =
if HAVE_GCC
    AM_CFLAGS += \
        -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
        -Wcast-align -Wwrite-strings
endif

AM_CPPFLAGS = -I$(topdir) -I$(topdir)/trace -I$(topdir)/collection $(TRACE_LEVEL)

ACLOCAL_AMFLAGS = -I m4

# Set up the pkg-config file
pkgconfigdir = $(libdir)/pkgconfig
dist_pkgconfig_DATA = ini_config.pc

dist_noinst_DATA = \
    ini.conf \
    ini.d/real.conf \
    ini.d/test.conf \
    m4

dist_include_HEADERS = \
    ini_config.h

# Build library
lib_LTLIBRARIES = libini_config.la
libini_config_la_SOURCES = \
    ini_config.c
libini_config_la_LIBADD = \
    -L$(topbuilddir)/collection \
    -lcollection
libini_config_la_LDFLAGS = \
    -version-info 1:0:0

# Build unit test
check_PROGRAMS = ini_config_ut
ini_config_ut_SOURCES = ini_config_ut.c
ini_config_ut_LDADD = libini_config.la -lcollection

if HAVE_DOXYGEN
docs:
# A temp way of building docs until we hook into the package build
	rm -fR doc
	mkdir -p doc
	$(DOXYGEN) ini_config.cfg.doxy
else
docs:
	@echo "Doxygen not installed, cannot generate documentation"
	@exit 1
endif

TESTS = ini_config_ut

tests: all $(check_PROGRAMS)

clean-local:
	rm -Rf doc
