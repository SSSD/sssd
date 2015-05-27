AM_CPPFLAGS = \
    -std=gnu99 \
    -Wall \
    -I$(top_srcdir)/src \
    -I. \
    -DLOCALEDIR=\"$(localedir)\" \
    -DLIBDIR=\"$(libdir)\" \
    -DVARDIR=\"$(localstatedir)\" \
    -DSSS_STATEDIR=\"$(localstatedir)/lib/sss\" \
    -DSYSCONFDIR=\"$(sysconfdir)\" \
    $(DBUS_CFLAGS) \
    $(GLIB2_CFLAGS) \
    $(NULL)

TESTS_ENVIRONMENT = \
    CWRAP_TEST_SRCDIR=$(abs_srcdir) \
    . $(srcdir)/cwrap_test_setup.sh; \
    $(AUX_TESTS_ENVIRONMENT) \
    $(NULL)

dist_noinst_SCRIPTS = \
    cwrap_test_setup.sh \
    $(NULL)

SSSD_LIBS = \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(POPT_LIBS) \
    $(LDB_LIBS) \
    $(DBUS_LIBS) \
    $(PCRE_LIBS) \
    $(INI_CONFIG_LIBS) \
    $(COLLECTION_LIBS) \
    $(DHASH_LIBS) \
    $(SSS_CRYPT_LIBS) \
    $(OPENLDAP_LIBS) \
    $(TDB_LIBS)

dist_noinst_DATA = \
    group \
    passwd \
    $(NULL)

check_PROGRAMS =
if HAVE_CMOCKA
if HAVE_NSS_WRAPPER
if HAVE_UID_WRAPPER
check_PROGRAMS += \
    become_user-tests \
    server-tests \
    usertools-tests \
    responder_common-tests \
    $(NULL)
endif # HAVE_UID_WRAPPER
endif # HAVE_NSS_WRAPPER
endif # HAVE_CMOCKA

TESTS = $(check_PROGRAMS)

become_user_tests_SOURCES = \
    test_become_user.c \
    $(NULL)
become_user_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
become_user_tests_LDADD = \
    $(POPT_LIBS) \
    $(CMOCKA_LIBS) \
    $(abs_top_builddir)/libsss_debug.la \
    $(abs_top_builddir)/libsss_test_common.la \
    $(NULL)

server_tests_SOURCES = \
    test_server.c \
    ../../../src/util/server.c \
    ../../../src/util/become_user.c \
    ../../../src/util/backup_file.c \
    ../../../src/util/domain_info_utils.c \
    ../../../src/util/atomic_io.c \
    ../../../src/util/signal.c \
    ../../../src/util/util.c \
    ../../../src/util/string_utils.c \
    ../../../src/util/strtonum.c \
    ../../../src/util/util_errors.c \
    ../../../src/util/safe-format-string.c \
    ../../../src/util/sss_tc_utf8.c \
    ../../../src/util/sss_utf8.c \
    ../../../src/util/usertools.c \
    ../../../src/confdb/confdb.c \
    ../../../src/db/sysdb.c \
    ../../../src/db/sysdb_upgrade.c \
    ../../../src/db/sysdb_ops.c \
    ../../../src/db/sysdb_search.c \
    ../../../src/db/sysdb_autofs.c \
    ../../../src/db/sysdb_services.c \
    ../../../src/db/sysdb_views.c \
    $(NULL)
server_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(LIBCAPNG_CFLAGS) \
    -DTEST_DB_PATH=\"server_tests\" \
    -DTEST_PID_PATH=\"server_tests\" \
    -DUNIT_TESTING \
    $(NULL)
server_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(LIBCAPNG_LIBS) \
    $(UNICODE_LIBS) \
    $(SSSD_LIBS) \
    $(abs_top_builddir)/libsss_debug.la \
    $(abs_top_builddir)/libsss_crypt.la \
    $(abs_top_builddir)/libsss_test_common.la \
    $(abs_top_builddir)/libsss_cert.la \
    $(NULL)

usertools_tests_SOURCES = \
    test_usertools.c \
    ../../../src/util/domain_info_utils.c \
    ../../../src/util/safe-format-string.c \
    ../../../src/util/usertools.c \
    ../../../src/util/string_utils.c \
    ../../../src/util/strtonum.c \
    ../../../src/util/backup_file.c \
    ../../../src/util/atomic_io.c \
    ../../../src/util/util.c \
    ../../../src/util/util_errors.c \
    ../../../src/util/sss_tc_utf8.c \
    ../../../src/util/sss_utf8.c \
    ../../../src/confdb/confdb.c \
    ../../../src/db/sysdb.c \
    ../../../src/db/sysdb_upgrade.c \
    ../../../src/db/sysdb_autofs.c \
    ../../../src/db/sysdb_search.c \
    ../../../src/db/sysdb_services.c \
    ../../../src/db/sysdb_ops.c \
    ../../../src/db/sysdb_views.c \
    $(NULL)
usertools_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
usertools_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(UNICODE_LIBS) \
    $(SSSD_LIBS) \
    $(abs_top_builddir)/libsss_debug.la \
    $(abs_top_builddir)/libsss_crypt.la \
    $(abs_top_builddir)/libsss_test_common.la \
    $(abs_top_builddir)/libsss_cert.la \
    $(NULL)

responder_common_tests_SOURCES =\
    test_responder_common.c \
    ../../../src/responder/common/responder_common.c \
    ../../../src/responder/common/responder_packet.c \
    ../../../src/responder/common/responder_cmd.c \
    $(NULL)
responder_common_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
responder_common_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(UNICODE_LIBS) \
    $(SSSD_LIBS) \
    $(abs_top_builddir)/libsss_util.la \
    $(abs_top_builddir)/libsss_debug.la \
    $(abs_top_builddir)/libsss_crypt.la \
    $(abs_top_builddir)/libsss_test_common.la \
    $(NULL)

tests: $(check_PROGRAMS)
