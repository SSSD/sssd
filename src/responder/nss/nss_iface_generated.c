/* The following definitions are auto-generated from nss_iface.xml */

#include <stddef.h>

#include "dbus/dbus-protocol.h"
#include "util/util_errors.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_invokers.h"
#include "nss_iface_generated.h"

/* invokes a handler with a 'ssau' DBus signature */
static int invoke_ssau_method(struct sbus_request *dbus_req, void *function_ptr);

/* arguments for org.freedesktop.sssd.nss.MemoryCache.UpdateInitgroups */
const struct sbus_arg_meta iface_nss_memorycache_UpdateInitgroups__in[] = {
    { "user", "s" },
    { "domain", "s" },
    { "groups", "au" },
    { NULL, }
};

int iface_nss_memorycache_UpdateInitgroups_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

int iface_nss_memorycache_InvalidateAllUsers_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

int iface_nss_memorycache_InvalidateAllGroups_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

int iface_nss_memorycache_InvalidateAllInitgroups_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.nss.MemoryCache */
const struct sbus_method_meta iface_nss_memorycache__methods[] = {
    {
        "UpdateInitgroups", /* name */
        iface_nss_memorycache_UpdateInitgroups__in,
        NULL, /* no out_args */
        offsetof(struct iface_nss_memorycache, UpdateInitgroups),
        invoke_ssau_method,
    },
    {
        "InvalidateAllUsers", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_nss_memorycache, InvalidateAllUsers),
        NULL, /* no invoker */
    },
    {
        "InvalidateAllGroups", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_nss_memorycache, InvalidateAllGroups),
        NULL, /* no invoker */
    },
    {
        "InvalidateAllInitgroups", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_nss_memorycache, InvalidateAllInitgroups),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.nss.MemoryCache */
const struct sbus_interface_meta iface_nss_memorycache_meta = {
    "org.freedesktop.sssd.nss.MemoryCache", /* name */
    iface_nss_memorycache__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* invokes a handler with a 'ssau' DBus signature */
static int invoke_ssau_method(struct sbus_request *dbus_req, void *function_ptr)
{
    const char * arg_0;
    const char * arg_1;
    uint32_t *arg_2;
    int len_2;
    int (*handler)(struct sbus_request *, void *, const char *, const char *, uint32_t[], int) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_STRING, &arg_0,
                               DBUS_TYPE_STRING, &arg_1,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &arg_2, &len_2,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0,
                     arg_1,
                     arg_2,
                     len_2);
}
