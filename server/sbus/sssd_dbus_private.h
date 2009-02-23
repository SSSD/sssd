#ifndef _SSSD_DBUS_PRIVATE_H_
#define _SSSD_DBUS_PRIVATE_H_

struct timeval _dbus_timeout_get_interval_tv(int interval);
void sbus_remove_watch(DBusWatch *watch, void *data);
void sbus_remove_timeout(DBusTimeout *timeout, void *data);

#endif /* _SSSD_DBUS_PRIVATE_H_ */
