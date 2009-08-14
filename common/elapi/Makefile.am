TRACE_LEVEL=@TRACE_VAR@
DEFAULT_CONF_DIR=@elapiconfdir@
DEFAULT_CONF_APP_DIR=@elapiconfappdir@
APP_NAME=@appname@
APP_NAME_SIZE=@appnamesize@

SUBDIRS = elapi_test

topdir=$(srcdir)/..

AM_CFLAGS = -DELAPI_DEFAULT_CONFIG_DIR=\"$(DEFAULT_CONF_DIR)\"   \
            -DELAPI_DEFAULT_CONFIG_APP_DIR=\"$(DEFAULT_CONF_APP_DIR)\"   \
            -DELAPI_DEFAULT_APP_NAME=\"$(APP_NAME)\" \
            -DELAPI_DEFAULT_APP_NAME_SIZE=$(APP_NAME_SIZE)

if HAVE_GCC
    AM_CFLAGS += \
        -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
        -Wcast-align -Wwrite-strings
endif

AM_CPPFLAGS = -I$(topdir) -I$(topdir)/ini -I$(topdir)/trace -I$(topdir)/collection $(TRACE_LEVEL)

ACLOCAL_AMFLAGS = -I m4

# Set up the pkg-config file
pkgconfigdir = $(libdir)/pkgconfig
dist_noinst_DATA = elapi.pc

# Build library
noinst_LTLIBRARIES = libelapi.la
libelapi_la_SOURCES = \
    elapi_event.c \
    elapi_log.c \
    elapi_internal.c \
    elapi_event.h \
    elapi_priv.h \
    elapi_sink.h \
    elapi_log.h \
    elapi_async.h \
    elapi.h
