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
    ABS_TOP_BUILDDIR=$(abs_top_builddir) \
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
    $(OPENLDAP_LIBS) \
    $(TDB_LIBS)

SSSD_CACHE_REQ_OBJ = \
    ../../../src/responder/common/cache_req/cache_req.c \
    ../../../src/responder/common/cache_req/cache_req_result.c \
    ../../../src/responder/common/cache_req/cache_req_search.c \
    ../../../src/responder/common/cache_req/cache_req_data.c \
    ../../../src/responder/common/cache_req/cache_req_domain.c \
    ../../../src/responder/common/cache_req/cache_req_sr_overlay.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_common.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_enum_users.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_enum_groups.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_enum_svc.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_user_by_name.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_user_by_upn.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_user_by_id.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_user_by_filter.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_user_by_cert.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_group_by_name.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_group_by_id.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_group_by_filter.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_initgroups_by_name.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_initgroups_by_upn.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_object_by_sid.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_object_by_name.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_object_by_id.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_svc_by_name.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_svc_by_port.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_netgroup_by_name.c \
    ../../../src/responder/common/cache_req/plugins/cache_req_host_by_name.c \
    $(NULL)

SSSD_RESPONDER_IFACE_OBJ = \
    ../../../src/responder/common/iface/responder_iface.c \
    ../../../src/responder/common/iface/responder_domain.c \
    ../../../src/responder/common/iface/responder_ncache.c \
    ../../../src/responder/common/iface/responder_iface_generated.c \
    $(NULL)

SSSD_RESPONDER_OBJ = \
    ../../../src/responder/common/negcache_files.c \
    ../../../src/responder/common/negcache.c \
    ../../../src/responder/common/responder_cmd.c \
    ../../../src/responder/common/responder_common.c \
    ../../../src/responder/common/responder_dp.c \
    ../../../src/responder/common/responder_dp_ssh.c \
    ../../../src/responder/common/responder_packet.c \
    ../../../src/responder/common/responder_get_domains.c \
    ../../../src/responder/common/responder_utils.c \
    ../../../src/responder/common/data_provider/rdp_message.c \
    ../../../src/responder/common/data_provider/rdp_client.c \
    ../../../src/monitor/monitor_iface_generated.c \
    ../../../src/providers/data_provider_req.c \
    ../../../src/util/session_recording.c \
    $(SSSD_RESPONDER_IFACE_OBJ) \
    $(SSSD_CACHE_REQ_OBJ) \
    $(NULL)

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
    negcache-tests \
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
    $(NULL)
server_tests_CFLAGS = \
    $(AM_CFLAGS) \
    -DTEST_DB_PATH=\"server_tests\" \
    -DTEST_PID_PATH=\"server_tests\" \
    -DUNIT_TESTING \
    $(NULL)
server_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(TEVENT_LIBS) \
    $(abs_top_builddir)/libsss_util.la \
    $(abs_top_builddir)/libsss_debug.la \
    $(abs_top_builddir)/libsss_test_common.la \
    $(NULL)
if BUILD_SYSTEMTAP
server_tests_LDADD += $(abs_top_builddir)/stap_generated_probes.lo
endif

usertools_tests_SOURCES = \
    test_usertools.c \
    $(NULL)
usertools_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
usertools_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(abs_top_builddir)/libsss_util.la \
    $(abs_top_builddir)/libsss_debug.la \
    $(abs_top_builddir)/libsss_test_common.la \
    $(NULL)
if BUILD_SYSTEMTAP
usertools_tests_LDADD += $(abs_top_builddir)/stap_generated_probes.lo
endif

responder_common_tests_SOURCES =\
    test_responder_common.c \
    ../../../src/responder/common/iface/responder_iface.c \
    ../../../src/responder/common/iface/responder_domain.c \
    ../../../src/responder/common/iface/responder_ncache.c \
    ../../../src/responder/common/iface/responder_iface_generated.c \
    ../../../src/responder/common/negcache_files.c \
    ../../../src/responder/common/negcache.c \
    ../../../src/responder/common/data_provider/rdp_message.c \
    ../../../src/responder/common/data_provider/rdp_client.c \
    ../../../src/responder/common/responder_common.c \
    ../../../src/responder/common/responder_packet.c \
    ../../../src/responder/common/responder_cmd.c \
    ../../../src/tests/cmocka/common_mock_resp_dp.c \
    ../../../src/util/session_recording.c \
    $(SSSD_CACHE_REQ_OBJ) \
    $(NULL)
responder_common_tests_CFLAGS = \
    $(AM_CFLAGS) \
    $(NULL)
responder_common_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SELINUX_LIBS) \
    $(SYSTEMD_DAEMON_LIBS) \
    $(abs_top_builddir)/libsss_util.la \
    $(abs_top_builddir)/libsss_debug.la \
    $(abs_top_builddir)/libsss_test_common.la \
    $(NULL)

negcache_tests_SOURCES =\
    $(SSSD_RESPONDER_OBJ) \
    test_negcache.c \
    $(NULL)
negcache_tests_CFLAGS = \
    $(AM_CFLAGS) \
    -DBASE_FILE_STEM=\"$(*F)\" \
    $(NULL)
negcache_tests_LDADD = \
    $(CMOCKA_LIBS) \
    $(SSSD_LIBS) \
    $(SELINUX_LIBS) \
    $(SYSTEMD_DAEMON_LIBS) \
    $(abs_top_builddir)/libsss_util.la \
    $(abs_top_builddir)/libsss_debug.la \
    $(abs_top_builddir)/libsss_test_common.la \
    $(NULL)

tests: $(check_PROGRAMS)
