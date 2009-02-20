UTIL_OBJ = \
    util/debug.o \
    util/signal.o \
    util/server.o \
    util/memory.o \
    util/btreemap.o \
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
    infopipe/sysbus.o

POLKIT_OBJ = \
    polkit/sssd_polkit.o

MEMBEROF_OBJ = \
	ldb_modules/memberof.o

SYSDB_TEST_OBJ = \
	tests/sysdb-tests.o

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

lib/libsss_proxy.$(SHLIBEXT): $(PROXY_BE_OBJ)
	$(SHLD) $(SHLD_FLAGS) -o $@ $(PROXY_BE_OBJ) $(LDFLAGS) $(LIBS)

lib/memberof.$(SHLIBEXT): $(MEMBEROF_OBJ)
	$(SHLD) $(SHLD_FLAGS) -o $@ $(MEMBEROF_OBJ) $(LDFLAGS) $(LDB_LIBS)

#Tests
tests/sysdb-tests: $(SYSDB_TEST_OBJ) $(UTIL_OBJ)
	$(CC) -o tests/sysdb-tests $(SYSDB_TEST_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS) $(CHECK_LIBS)
