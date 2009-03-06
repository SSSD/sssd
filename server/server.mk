UTIL_OBJ = \
    util/debug.o \
    util/signal.o \
    util/server.o \
    util/memory.o \
    util/btreemap.o \
    util/usertools.o \
    monitor/monitor_sbus.o \
    providers/dp_sbus.o \
    sbus/sssd_dbus_common.o \
    sbus/sssd_dbus_connection.o \
    sbus/sssd_dbus_server.o \
    sbus/sbus_client.o \
    confdb/confdb.o \
	db/sysdb.o \
	db/sysdb_req.o \
	db/sysdb_search.o \
	db/sysdb_ops.o

RESPONDER_UTIL_OBJ = \
    responder/common/responder_dp.o \
    responder/common/responder_packet.o \
    responder/common/responder_common.o \
    responder/common/responder_cmd.o

SERVER_OBJ = \
    monitor/monitor.o

DP_OBJ = \
	providers/data_provider.o

DP_BE_OBJ = \
	providers/data_provider_be.o \

PROXY_BE_OBJ = \
	providers/proxy.o

LDAP_BE_OBJ = \
	providers/ldap_be.o

NSSSRV_OBJ = \
    responder/nss/nsssrv.o \
    responder/nss/nsssrv_cmd.o \
    responder/nss/nsssrv_dp.o

INFOPIPE_OBJ = \
    infopipe/infopipe.o \
    infopipe/infopipe_users.o \
    infopipe/infopipe_groups.o \
    infopipe/sysbus.o

POLKIT_OBJ = \
    polkit/sssd_polkit.o

MEMBEROF_OBJ = \
	ldb_modules/memberof.o

SYSDB_TEST_OBJ = \
	tests/sysdb-tests.o

INFP_TEST_OBJ = \
	tests/infopipe-tests.o

CRYPT_OBJ = util/nss_sha512crypt.o

PAMSRV_OBJ = \
    responder/pam/pamsrv.o \
    responder/pam/pamsrv_cmd.o \
    responder/pam/pam_LOCAL_domain.o \
    responder/pam/pamsrv_dp.o

PAMSRV_UTIL_OBJ = responder/pam/pamsrv_util.o

$(LDAP_BE_OBJ): CFLAGS += $(LDAP_CFLAGS)
$(CRYPT_OBJ): CFLAGS += $(NSS_CFLAGS)


TOOLS_OBJ = \
    tools/tools_util.o

USERADD_OBJ = \
	tools/sss_useradd.o

USERDEL_OBJ = \
	tools/sss_userdel.o

GROUPADD_OBJ = \
	tools/sss_groupadd.o

GROUPDEL_OBJ = \
	tools/sss_groupdel.o

sbin/sssd: $(SERVER_OBJ) $(UTIL_OBJ)
	$(CC) -o sbin/sssd $(SERVER_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

sbin/sssd_nss: $(NSSSRV_OBJ) $(UTIL_OBJ) $(RESPONDER_UTIL_OBJ)
	$(CC) -o sbin/sssd_nss $(NSSSRV_OBJ) $(UTIL_OBJ) $(RESPONDER_UTIL_OBJ) $(LDFLAGS) $(LIBS)

sbin/sssd_pam: $(PAMSRV_OBJ) $(UTIL_OBJ) $(RESPONDER_UTIL_OBJ) $(PAMSRV_UTIL_OBJ) $(CRYPT_OBJ)
	$(CC) -o sbin/sssd_pam $(PAMSRV_OBJ) $(UTIL_OBJ) $(PAMSRV_UTIL_OBJ) $(RESPONDER_UTIL_OBJ) $(CRYPT_OBJ) $(LDFLAGS) $(LIBS) $(NSS_LIBS)

sbin/sssd_dp: $(DP_OBJ) $(UTIL_OBJ) $(PAMSRV_UTIL_OBJ)
	$(CC) -o sbin/sssd_dp $(DP_OBJ) $(UTIL_OBJ) $(PAMSRV_UTIL_OBJ) $(LDFLAGS) $(LIBS)

sbin/sssd_be: $(DP_BE_OBJ) $(UTIL_OBJ)
	$(CC) -Wl,-E -o sbin/sssd_be $(DP_BE_OBJ) $(UTIL_OBJ) $(PAMSRV_UTIL_OBJ) $(LDFLAGS) $(LIBS) $(PAM_LIBS)

sbin/sssd_info: $(INFOPIPE_OBJ) $(UTIL_OBJ)
	$(CC) -o sbin/sssd_info $(INFOPIPE_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

sbin/sssd_pk: $(POLKIT_OBJ) $(UTIL_OBJ)
	$(CC) -o sbin/sssd_pk $(POLKIT_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

lib/$(PROXY_BE_SOBASE): $(PROXY_BE_OBJ)
	$(SHLD) $(SHLD_FLAGS) $(SONAMEFLAG)$(PROXY_BE_SONAME) -o lib/$(PROXY_BE_SOLIB) $(PROXY_BE_OBJ) $(LDFLAGS) $(LIBS) $(PAM_LIBS)
	ln -fs $(PROXY_BE_SOLIB) $@

lib/$(LDAP_BE_SOBASE): $(LDAP_BE_OBJ)
	$(SHLD) $(SHLD_FLAGS) $(SONAMEFLAG)$(LDAP_BE_SONAME) -o lib/$(LDAP_BE_SOLIB) $(LDAP_BE_OBJ) $(LDFLAGS) $(LIBS) $(LDAP_LIBS)
	ln -fs $(LDAP_BE_SOLIB) $@

lib/$(MEMBEROF_SOBASE): $(MEMBEROF_OBJ)
	$(SHLD) $(SHLD_FLAGS) $(SONAMEFLAG)$(MEMBEROF_SONAME) -o lib/$(MEMBEROF_SOLIB) $(MEMBEROF_OBJ) $(LDFLAGS) $(LDB_LIBS)
	ln -fs $(MEMBEROF_SOLIB) $@

#Tests
tests/sysdb-tests: $(SYSDB_TEST_OBJ) $(UTIL_OBJ)
	$(CC) -o tests/sysdb-tests $(SYSDB_TEST_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS) $(CHECK_LIBS)

tests/infopipe-tests: $(INFP_TEST_OBJ) $(UTIL_OBJ)
	$(CC) -o tests/infopipe-tests $(INFP_TEST_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS) $(CHECK_LIBS)

#Tools
sbin/sss_useradd: $(USERADD_OBJ) $(TOOLS_OBJ) $(UTIL_OBJ)
	$(CC) -o sbin/sss_useradd $(USERADD_OBJ) $(TOOLS_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

sbin/sss_userdel: $(USERDEL_OBJ) $(TOOLS_OBJ) $(UTIL_OBJ)
	$(CC) -o sbin/sss_userdel $(USERDEL_OBJ) $(TOOLS_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)
