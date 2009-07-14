ACLOCAL_AMFLAGS = -I m4
SUBDIRS = trace collection ini dhash path_utils
if SINGLELIB
# Build all components as a single shared library
lib_LTLIBRARIES = libsssd_util.la
libsssd_util_la_SOURCES =
libsssd_util_la_LIBADD = \
    collection/libcollection.la \
    ini/libini_config.la \
    dhash/libdhash.la
libsssd_util_la_CFLAGS = $(AM_CFLAGS) \
    -I ./collection \
    -I ./ini \
    -I ./dhash \
    -I ./trace
endif

