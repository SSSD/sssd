#ifndef _SSSD_DBUS_PRIVATE_H_
#define _SSSD_DBUS_PRIVATE_H_

union dbus_pointer {
    DBusServer *server;
    DBusConnection *conn;
};
enum dbus_pointer_type {
    SBUS_SERVER,
    SBUS_CONNECTION
};

struct sbus_generic_dbus_ctx {
    struct tevent_context *ev;
    enum dbus_pointer_type type;
    union dbus_pointer dbus;
};

/* =Watches=============================================================== */

struct sbus_watch_ctx {
    DBusWatch *dbus_watch;
    enum dbus_pointer_type dbus_type;
    union dbus_pointer dbus;
    struct tevent_fd *fde;
};

dbus_bool_t sbus_add_watch(DBusWatch *watch, void *data);
void sbus_toggle_watch(DBusWatch *watch, void *data);
void sbus_remove_watch(DBusWatch *watch, void *data);

/* =Timeouts============================================================== */

struct sbus_timeout_ctx {
    DBusTimeout *dbus_timeout;
    struct tevent_timer *te;
};

dbus_bool_t sbus_add_timeout(DBusTimeout *dbus_timeout, void *data);
void sbus_toggle_timeout(DBusTimeout *dbus_timeout, void *data);
void sbus_remove_timeout(DBusTimeout *dbus_timeout, void *data);

#endif /* _SSSD_DBUS_PRIVATE_H_ */
