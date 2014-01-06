/* The following definitions are auto-generated from ifp_iface.xml */

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "ifp_iface_generated.h"

/* methods for org.freedesktop.sssd.infopipe */
const struct sbus_method_meta infopipe_iface__methods[] = {
    {
        "Ping", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct infopipe_iface, Ping),
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
