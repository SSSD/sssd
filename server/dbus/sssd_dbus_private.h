#ifndef _SSSD_DBUS_PRIVATE_H_
#define _SSSD_DBUS_PRIVATE_H_

int sssd_add_dbus_connection(TALLOC_CTX *ctx,
                             struct event_context *ev,
                             DBusConnection *dbus_conn,
                             struct dbus_connection_toplevel_context **dct_ctx,
                             int connection_type);

struct timeval _dbus_timeout_get_interval_tv(int interval);
void remove_watch(DBusWatch *watch, void *data);
void remove_timeout(DBusTimeout *timeout, void *data);

#endif /* _SSSD_DBUS_PRIVATE_H_ */
