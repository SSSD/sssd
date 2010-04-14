ACLOCAL_AMFLAGS = -I m4
SUBDIRS = trace dhash path_utils refarray collection ini
DOCDIRS = path_utils refarray collection ini

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
    refarray/libref_array.la
libsssd_util_la_CFLAGS = $(AM_CFLAGS) \
    -I ./collection \
    -I ./ini \
    -I ./dhash \
    -I ./refarray \
    -I ./trace
endif

tests: all
	for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done

docs:
	for subdir in $(DOCDIRS); do \
		$(MAKE) -C $$subdir $@; \
	done
