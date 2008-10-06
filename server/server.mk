SERVER_OBJ = server.o monitor.o process.o service.o service_task.o util/signal.o util/become_daemon.o nss/nsssrv.o nss/nsssrv_packet.o nss/nsssrv_cmd.o

install:: all
	${INSTALLCMD} -d $(DESTDIR)$(sbindir)
	${INSTALLCMD} -m 755 sssd $(DESTDIR)$(sbindir)

clean::
	rm -f *~ $(SERVER_OBJS)

sbin/sssd: $(SERVER_OBJ)
	$(CC) -o sbin/sssd $(SERVER_OBJ) $(LDFLAGS) $(LIBS)

