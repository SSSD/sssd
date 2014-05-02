/* The following definitions are auto-generated from ifp_iface.xml */

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "ifp_iface_generated.h"

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr);

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

/* arguments for org.freedesktop.sssd.infopipe.GetUserGroups */
const struct sbus_arg_meta infopipe_iface_GetUserGroups__in[] = {
    { "user", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.GetUserGroups */
const struct sbus_arg_meta infopipe_iface_GetUserGroups__out[] = {
    { "values", "as" },
    { NULL, }
};

int infopipe_iface_GetUserGroups_finish(struct sbus_request *req, const char *arg_values[], int len_values)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &arg_values, len_values,
                                         DBUS_TYPE_INVALID);
}

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
    {
        "GetUserGroups", /* name */
        infopipe_iface_GetUserGroups__in,
        infopipe_iface_GetUserGroups__out,
        offsetof(struct infopipe_iface, GetUserGroups),
        invoke_s_method,
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

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr)
{
    const char * arg_0;
    int (*handler)(struct sbus_request *, void *, const char *) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_STRING, &arg_0,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->instance_data,
                     arg_0);
}
