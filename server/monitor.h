#ifndef _MONITOR_H_
#define _MONITOR_H_

#define MONITOR_VERSION "0.1"
#define MONITOR_DBUS_INTERFACE "org.freeipa.sssd.monitor"
#define MONITOR_DBUS_PATH "/org/freeipa/sssd/monitor"

/* D-BUS Methods */
#define MONITOR_METHOD_VERSION "getVersion"

int start_monitor(TALLOC_CTX *mem_ctx,
                  struct event_context *event_ctx,
                  struct confdb_ctx *cdb);

#endif /* _MONITOR_H */
