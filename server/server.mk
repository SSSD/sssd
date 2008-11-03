SERVER_OBJ = \
    server.o \
    monitor.o \
    process.o \
    service.o \
    service_task.o \
    util/debug.o \
    util/signal.o \
    util/become_daemon.o \
    util/memory.o \
    confdb/confdb.o \
    nss/nsssrv.o \
    nss/nsssrv_packet.o \
    nss/nsssrv_cmd.o \
    nss/nsssrv_ldb.o \
    sbus/sssd_dbus_common.o \
    sbus/sssd_dbus_connection.o \
    sbus/sssd_dbus_server.o

CLIENT_OBJ = \
    sbus/sssd_dbus_common.o \
    sbus/sssd_dbus_connection.o \
    util/debug.o \
    sbus/tests/test_client.o

install:: all
	${INSTALLCMD} -d $(DESTDIR)$(sbindir)
	${INSTALLCMD} -m 755 sssd $(DESTDIR)$(sbindir)

sbin/sssd: $(SERVER_OBJ)
	$(CC) -o sbin/sssd $(SERVER_OBJ) $(LDFLAGS) $(LIBS)

sbin/sssd-dbus-client: $(CLIENT_OBJ)
	$(CC) -o sbin/sssd-dbus-client $(CLIENT_OBJ) $(LDFLAGS) $(LIBS)
