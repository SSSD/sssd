/* The following definitions are auto-generated from proxy_iface.xml */

#include <stddef.h>

#include "dbus/dbus-protocol.h"
#include "util/util_errors.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_invokers.h"
#include "proxy_iface_generated.h"

/* invokes a handler with a 'u' DBus signature */
static int invoke_u_method(struct sbus_request *dbus_req, void *function_ptr);

/* arguments for org.freedesktop.sssd.ProxyChild.Client.Register */
const struct sbus_arg_meta iface_proxy_client_Register__in[] = {
    { "ID", "u" },
    { NULL, }
};

int iface_proxy_client_Register_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.ProxyChild.Client */
const struct sbus_method_meta iface_proxy_client__methods[] = {
    {
        "Register", /* name */
        iface_proxy_client_Register__in,
        NULL, /* no out_args */
        offsetof(struct iface_proxy_client, Register),
        invoke_u_method,
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.ProxyChild.Client */
const struct sbus_interface_meta iface_proxy_client_meta = {
    "org.freedesktop.sssd.ProxyChild.Client", /* name */
    iface_proxy_client__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* methods for org.freedesktop.sssd.ProxyChild.Auth */
const struct sbus_method_meta iface_proxy_auth__methods[] = {
    {
        "PAM", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_proxy_auth, PAM),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.ProxyChild.Auth */
const struct sbus_interface_meta iface_proxy_auth_meta = {
    "org.freedesktop.sssd.ProxyChild.Auth", /* name */
    iface_proxy_auth__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* invokes a handler with a 'u' DBus signature */
static int invoke_u_method(struct sbus_request *dbus_req, void *function_ptr)
{
    uint32_t arg_0;
    int (*handler)(struct sbus_request *, void *, uint32_t) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_UINT32, &arg_0,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0);
}
