#ifndef SSSD_DBUS_COMMON_H_
#define SSSD_DBUS_COMMON_H_

#include "dbus/dbus.h"

/* TODO: get this value from LDB */
#define DBUS_ADDRESS "unix:path=/tmp/dbus-sgallagh.sock"

/* Functions */
struct timeval _dbus_timeout_get_interval_tv(int interval);
void remove_watch(DBusWatch *watch, void *data);
void remove_timeout(DBusTimeout *timeout, void *data);

#endif /*SSSD_DBUS_COMMON_H_*/
