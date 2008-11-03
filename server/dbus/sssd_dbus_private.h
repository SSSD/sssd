#ifndef _SSSD_DBUS_PRIVATE_H_
#define _SSSD_DBUS_PRIVATE_H_

int sbus_add_connection(TALLOC_CTX *ctx,
                             struct event_context *ev,
                             DBusConnection *dbus_conn,
                             struct sbus_conn_ctx **dct_ctx,
                             int connection_type);

struct timeval _dbus_timeout_get_interval_tv(int interval);
void sbus_remove_watch(DBusWatch *watch, void *data);
void sbus_remove_timeout(DBusTimeout *timeout, void *data);

#endif /* _SSSD_DBUS_PRIVATE_H_ */
