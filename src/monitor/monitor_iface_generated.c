/* The following definitions are auto-generated from monitor_iface.xml */

#include <stddef.h>

#include "dbus/dbus-protocol.h"
#include "util/util_errors.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_invokers.h"
#include "monitor_iface_generated.h"

/* methods for org.freedesktop.sssd.monitor */
const struct sbus_method_meta mon_srv_iface__methods[] = {
    {
        "getVersion", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_srv_iface, getVersion),
        NULL, /* no invoker */
    },
    {
        "RegisterService", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_srv_iface, RegisterService),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.monitor */
const struct sbus_interface_meta mon_srv_iface_meta = {
    "org.freedesktop.sssd.monitor", /* name */
    mon_srv_iface__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* methods for org.freedesktop.sssd.service */
const struct sbus_method_meta mon_cli_iface__methods[] = {
    {
        "resInit", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, resInit),
        NULL, /* no invoker */
    },
    {
        "goOffline", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, goOffline),
        NULL, /* no invoker */
    },
    {
        "resetOffline", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, resetOffline),
        NULL, /* no invoker */
    },
    {
        "rotateLogs", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, rotateLogs),
        NULL, /* no invoker */
    },
    {
        "clearMemcache", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, clearMemcache),
        NULL, /* no invoker */
    },
    {
        "clearEnumCache", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, clearEnumCache),
        NULL, /* no invoker */
    },
    {
        "sysbusReconnect", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, sysbusReconnect),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.service */
const struct sbus_interface_meta mon_cli_iface_meta = {
    "org.freedesktop.sssd.service", /* name */
    mon_cli_iface__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};
