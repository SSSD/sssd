#ifndef _SSSD_DBUS_PRIVATE_H_
#define _SSSD_DBUS_PRIVATE_H_

int sssd_add_dbus_connection(struct sssd_dbus_ctx *ctx,
                             DBusConnection *dbus_conn);

struct timeval _dbus_timeout_get_interval_tv(int interval);
void remove_watch(DBusWatch *watch, void *data);
void remove_timeout(DBusTimeout *timeout, void *data);

#endif /* _SSSD_DBUS_PRIVATE_H_ */
