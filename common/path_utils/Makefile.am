AM_CFLAGS =
if HAVE_GCC
    AM_CFLAGS += \
        -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
        -Wcast-align -Wwrite-strings
endif

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
dist_noinst_DATA = \
    path_utils.pc \
    m4

noinst_LTLIBRARIES = libpath_utils.la
libpath_utils_la_SOURCES = \
    path_utils.c \
    path_utils.h

tests: all $(check_PROGRAMS)
