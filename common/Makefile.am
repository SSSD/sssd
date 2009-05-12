ACLOCAL_AMFLAGS = -I m4

if SINGLELIB
# Build all components as a single shared library
lib_LTLIBRARIES = libsssd_util.la
libsssd_util_la_SOURCES = \
    collection/collection.c \
    collection/collection_tools.c \
    ini/ini_config.c \
    dhash/dhash.c
libsssd_util_la_CFLAGS = $(AM_CFLAGS) \
    -I ./collection \
    -I ./ini \
    -I ./dhash \
    -I ./trace
else
SUBDIRS = collection ini trace dhash
endif

