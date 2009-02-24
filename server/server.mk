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
	db/sysdb_sync.o

SERVER_OBJ = \
    monitor/monitor.o

DP_OBJ = \
	providers/data_provider.o

DP_BE_OBJ = \
	providers/data_provider_be.o \

PROXY_BE_OBJ = \
	providers/proxy.o

NSSSRV_OBJ = \
    nss/nsssrv.o \
    nss/nsssrv_packet.o \
    nss/nsssrv_cmd.o \
    nss/nsssrv_dp.o

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

sbin/sssd: $(SERVER_OBJ) $(UTIL_OBJ)
	$(CC) -o sbin/sssd $(SERVER_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

sbin/sssd_nss: $(NSSSRV_OBJ) $(UTIL_OBJ)
	$(CC) -o sbin/sssd_nss $(NSSSRV_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

sbin/sssd_dp: $(DP_OBJ) $(UTIL_OBJ)
	$(CC) -o sbin/sssd_dp $(DP_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

sbin/sssd_be: $(DP_BE_OBJ) $(UTIL_OBJ)
	$(CC) -Wl,-E -o sbin/sssd_be $(DP_BE_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

sbin/sssd_info: $(INFOPIPE_OBJ) $(UTIL_OBJ)
	$(CC) -o sbin/sssd_info $(INFOPIPE_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

sbin/sssd_pk: $(POLKIT_OBJ) $(UTIL_OBJ)
	$(CC) -o sbin/sssd_pk $(POLKIT_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

lib/$(PROXY_BE_SOBASE): $(PROXY_BE_OBJ)
	$(SHLD) $(SHLD_FLAGS) $(SONAMEFLAG)$(PROXY_BE_SONAME) -o lib/$(PROXY_BE_SOLIB) $(PROXY_BE_OBJ) $(LDFLAGS) $(LIBS)
	ln -fs $(PROXY_BE_SOLIB) $@

lib/$(MEMBEROF_SOBASE): $(MEMBEROF_OBJ)
	$(SHLD) $(SHLD_FLAGS) $(SONAMEFLAG)$(MEMBEROF_SONAME) -o lib/$(MEMBEROF_SOLIB) $(MEMBEROF_OBJ) $(LDFLAGS) $(LDB_LIBS)
	ln -fs $(MEMBEROF_SOLIB) $@

#Tests
tests/sysdb-tests: $(SYSDB_TEST_OBJ) $(UTIL_OBJ)
	$(CC) -o tests/sysdb-tests $(SYSDB_TEST_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS) $(CHECK_LIBS)

tests/infopipe-tests: $(INFP_TEST_OBJ) $(UTIL_OBJ)
	$(CC) -o tests/infopipe-tests $(INFP_TEST_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS) $(CHECK_LIBS)
