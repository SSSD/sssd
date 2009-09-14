#DEBUG_FLAGS=@DEBUG_VAR@
TRACE_LEVEL=@TRACE_VAR@

topdir=$(srcdir)/..

AM_CFLAGS =
if HAVE_GCC
    AM_CFLAGS += \
        -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
        -Wcast-align -Wwrite-strings
endif

AM_CPPFLAGS = -I$(topdir) -I$(topdir)/trace $(TRACE_LEVEL)

ACLOCAL_AMFLAGS = -I m4

# Set up the pkg-config file
pkgconfigdir = $(libdir)/pkgconfig
dist_noinst_DATA = \
    collection.pc \
    m4

# Build library
noinst_LTLIBRARIES = libcollection.la
libcollection_la_SOURCES = \
    collection.c \
    collection_tools.c \
    collection_cnv.c \
    collection_queue.c \
    collection_stack.c \
    collection_cmp.c \
    collection.h \
    collection_tools.h \
    collection_priv.h \
    collection_queue.h \
    collection_stack.h \
    ../trace/trace.h

# Build unit test
check_PROGRAMS = collection_ut collection_stack_ut collection_queue_ut
collection_ut_SOURCES = collection_ut.c
collection_ut_LDADD = libcollection.la
collection_stack_ut_SOURCES = collection_stack_ut.c
collection_stack_ut_LDADD = libcollection.la
collection_queue_ut_SOURCES = collection_queue_ut.c
collection_queue_ut_LDADD = libcollection.la

TESTS = collection_ut collection_stack_ut collection_queue_ut

tests: all $(check_PROGRAMS)
