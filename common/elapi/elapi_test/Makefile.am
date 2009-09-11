TRACE_LEVEL=@TRACE_VAR@

topdir=$(srcdir)/../..

AM_CFLAGS = -DELAPI_DEFAULT_CONFIG_DIR=\"$(srcdir)\"   \
            -DELAPI_DEFAULT_CONFIG_APP_DIR=\"$(srcdir)\"   \
            -DELAPI_DEFAULT_APP_NAME=\"elapi_ut\" \
            -DELAPI_DEFAULT_APP_NAME_SIZE=127

if HAVE_GCC
    AM_CFLAGS += \
        -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
        -Wcast-align -Wwrite-strings
endif

AM_CPPFLAGS = -I$(topdir) -I$(topdir)/ini -I$(topdir)/trace -I$(topdir)/collection -I$(topdir)/elapi \
              -I$(topdir)/elapi/providers/file $(TRACE_LEVEL)

ACLOCAL_AMFLAGS = -I m4

# Build library
noinst_LTLIBRARIES = libelapi_test.la

libelapi_test_la_SOURCES = \
    ../elapi_event.c \
    ../elapi_log.c \
    ../elapi_internal.c \
    ../elapi_sink.c \
    ../elapi_basic.c \
    ../elapi_basic.h \
    ../elapi_event.h \
    ../elapi_priv.h \
    ../elapi_sink.h \
    ../elapi_log.h \
    ../elapi_async.h \
    ../elapi.h \
    ../providers/file/file_provider.c \
    ../providers/file/file_provider.h \
    ../providers/file/file_util.c \
    ../providers/file/file_util.h \
    ../providers/file/file_fmt_csv.c \
    ../providers/file/file_fmt_csv.h

# Build unit test
check_PROGRAMS = elapi_ut
elapi_ut_SOURCES = elapi_ut.c
elapi_ut_LDADD = libelapi_test.la ../../ini/libini_config.la ../../collection/libcollection.la -ldl

TESTS = elapi_ut

tests: all $(check_PROGRAMS)
