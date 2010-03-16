AM_CFLAGS =
if HAVE_GCC
    AM_CFLAGS += \
        -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
        -Wcast-align -Wwrite-strings
endif

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
dist_pkgconfig_DATA = path_utils.pc

dist_include_HEADERS = path_utils.h

dist_noinst_DATA = m4

lib_LTLIBRARIES = libpath_utils.la
libpath_utils_la_SOURCES = path_utils.c
libpath_utils_la_LDFLAGS = \
    -version-info 1:0:0

if HAVE_CHECK
    check_PROGRAMS = path_utils_ut
endif

path_utils_ut_SOURCES = \
    path_utils_ut.c
path_utils_ut_CFLAGS = \
    $(AM_CFLAGS) \
    $(CHECK_CFLAGS)
path_utils_ut_LDADD = \
    $(CHECK_LIBS) \
    libpath_utils.la
TESTS = $(check_PROGRAMS)

tests: all $(check_PROGRAMS)
