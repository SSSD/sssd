#ifndef _SSSD_DBUS_PRIVATE_H_
#define _SSSD_DBUS_PRIVATE_H_

union dbus_conn_pointer {
    DBusServer *server;
    DBusConnection *conn;
};
enum dbus_conn_type {
    SBUS_SERVER,
    SBUS_CONNECTION
};

struct sbus_connection {
    struct tevent_context *ev;

    enum dbus_conn_type type;
    union dbus_conn_pointer dbus;

    char *address;
    int connection_type;
    int disconnect;

    sbus_conn_destructor_fn destructor;
    void *pvt_data; /* Private data for this connection */

    /* dbus tables and handlers */
    struct method_holder *method_list;

    /* reconnect settings */
    int retries;
    int max_retries;
    sbus_conn_reconn_callback_fn reconnect_callback;
    /* Private data needed to reinit after reconnection */
    void *reconnect_pvt;

    /* server related stuff */
    struct sbus_method_ctx *server_method;
    sbus_server_conn_init_fn srv_init_fn;
    void *srv_init_data;
};

/* =Watches=============================================================== */

struct sbus_watch_ctx {
    DBusWatch *dbus_watch;
    struct sbus_connection *conn;
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
