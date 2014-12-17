/* The following definitions are auto-generated from data_provider_iface.xml */

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_invokers.h"
#include "data_provider_iface_generated.h"

/* methods for org.freedesktop.sssd.dataprovider */
const struct sbus_method_meta data_provider_iface__methods[] = {
    {
        "RegisterService", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, RegisterService),
        NULL, /* no invoker */
    },
    {
        "pamHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, pamHandler),
        NULL, /* no invoker */
    },
    {
        "sudoHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, sudoHandler),
        NULL, /* no invoker */
    },
    {
        "autofsHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, autofsHandler),
        NULL, /* no invoker */
    },
    {
        "hostHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, hostHandler),
        NULL, /* no invoker */
    },
    {
        "getDomains", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, getDomains),
        NULL, /* no invoker */
    },
    {
        "getAccountInfo", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, getAccountInfo),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.dataprovider */
const struct sbus_interface_meta data_provider_iface_meta = {
    "org.freedesktop.sssd.dataprovider", /* name */
    data_provider_iface__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* methods for org.freedesktop.sssd.dataprovider_rev */
const struct sbus_method_meta data_provider_rev_iface__methods[] = {
    {
        "updateCache", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_rev_iface, updateCache),
        NULL, /* no invoker */
    },
    {
        "initgrCheck", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_rev_iface, initgrCheck),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.dataprovider_rev */
const struct sbus_interface_meta data_provider_rev_iface_meta = {
    "org.freedesktop.sssd.dataprovider_rev", /* name */
    data_provider_rev_iface__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};
