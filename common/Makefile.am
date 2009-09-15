ACLOCAL_AMFLAGS = -I m4
SUBDIRS = trace collection ini dhash path_utils elapi

dist_noinst_DATA = \
    m4

if SINGLELIB
# Build all components as a single shared library
lib_LTLIBRARIES = libsssd_util.la
libsssd_util_la_SOURCES =
libsssd_util_la_LIBADD = \
    collection/libcollection.la \
    ini/libini_config.la \
    dhash/libdhash.la \
    elapi/libelapi.la
libsssd_util_la_CFLAGS = $(AM_CFLAGS) \
    -I ./collection \
    -I ./ini \
    -I ./dhash \
    -I ./elapi \
    -I ./trace
endif

tests: all
	for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done
