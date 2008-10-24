#ifndef MONITOR_H_
#define MONITOR_H_

#include "talloc.h"
#include "service_task.h"
#include "dbus/dbus.h"

#define MONITOR_VERSION "0.1"
#define MONITOR_DBUS_INTERFACE "org.freeipa.sssd.monitor"
#define MONITOR_DBUS_PATH "/org/freeipa/sssd/monitor"

/* D-BUS Methods */
#define MONITOR_METHOD_VERSION "getVersion"

struct mt_ctx {
    struct event_context *ev;
    struct confdb_ctx *cdb;
    char **services;
};

int start_monitor(TALLOC_CTX *mem_ctx,
                  struct event_context *event_ctx,
                  struct confdb_ctx *cdb);
int monitor_dbus_init(struct event_context *event_ctx);
void monitor_dbus_method_init(DBusConnection *conn, struct event_context *event_ctx);
DBusHandlerResult monitor_message_handler(DBusConnection *conn,
    DBusMessage *message, void *user_data);
DBusMessage *dbus_get_monitor_version(DBusMessage *message);

#endif /* MONITOR_H */
