/* The following definitions are auto-generated from ifp_iface.xml */

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "ifp_iface_generated.h"

/* arguments for org.freedesktop.sssd.infopipe.GetUserAttr */
const struct sbus_arg_meta infopipe_iface_GetUserAttr__in[] = {
    { "user", "s" },
    { "attr", "as" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.GetUserAttr */
const struct sbus_arg_meta infopipe_iface_GetUserAttr__out[] = {
    { "values", "a{sv}" },
    { NULL, }
};

/* methods for org.freedesktop.sssd.infopipe */
const struct sbus_method_meta infopipe_iface__methods[] = {
    {
        "Ping", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct infopipe_iface, Ping),
        NULL, /* no invoker */
    },
    {
        "GetUserAttr", /* name */
        infopipe_iface_GetUserAttr__in,
        infopipe_iface_GetUserAttr__out,
        offsetof(struct infopipe_iface, GetUserAttr),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe */
const struct sbus_interface_meta infopipe_iface_meta = {
    "org.freedesktop.sssd.infopipe", /* name */
    infopipe_iface__methods,
    NULL, /* no signals */
    NULL, /* no propetries */
};
