UTIL_OBJ = \
    util/debug.o \
    util/signal.o \
    util/server.o \
    util/memory.o \
    util/btreemap.o \
    util/service_helpers.o \
    sbus/sssd_dbus_common.o \
    sbus/sssd_dbus_connection.o \
    sbus/sssd_dbus_server.o \
    providers/dp_helpers.o \
    confdb/confdb.o \
	db/sysdb.o

SERVER_OBJ = \
    monitor.o

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

install:: all
	${INSTALLCMD} -d $(DESTDIR)$(sbindir)
	${INSTALLCMD} -m 755 sssd $(DESTDIR)$(sbindir)

sbin/sssd: $(SERVER_OBJ) $(UTIL_OBJ)
	$(CC) -o sbin/sssd $(SERVER_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

sbin/sssd_nss: $(NSSSRV_OBJ) $(UTIL_OBJ)
	$(CC) -o sbin/sssd_nss $(NSSSRV_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

sbin/sssd_dp: $(DP_OBJ) $(UTIL_OBJ)
	$(CC) -o sbin/sssd_dp $(DP_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

sbin/sssd_be: $(DP_BE_OBJ) $(UTIL_OBJ)
	$(CC) -Wl,-E -o sbin/sssd_be $(DP_BE_OBJ) $(UTIL_OBJ) $(LDFLAGS) $(LIBS)

lib/libsss_proxy.$(SHLIBEXT): $(PROXY_BE_OBJ)
	$(SHLD) $(SHLD_FLAGS) -o $@ $(PROXY_BE_OBJ) $(LDFLAGS) $(LIBS)
