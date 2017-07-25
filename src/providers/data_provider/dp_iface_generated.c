/* The following definitions are auto-generated from dp_iface.xml */

#include <stddef.h>

#include "dbus/dbus-protocol.h"
#include "util/util_errors.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_invokers.h"
#include "dp_iface_generated.h"

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 'us' DBus signature */
static int invoke_us_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 'uss' DBus signature */
static int invoke_uss_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 'uusss' DBus signature */
static int invoke_uusss_method(struct sbus_request *dbus_req, void *function_ptr);

/* arguments for org.freedesktop.sssd.DataProvider.Client.Register */
const struct sbus_arg_meta iface_dp_client_Register__in[] = {
    { "Name", "s" },
    { NULL, }
};

int iface_dp_client_Register_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.DataProvider.Client */
const struct sbus_method_meta iface_dp_client__methods[] = {
    {
        "Register", /* name */
        iface_dp_client_Register__in,
        NULL, /* no out_args */
        offsetof(struct iface_dp_client, Register),
        invoke_s_method,
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.DataProvider.Client */
const struct sbus_interface_meta iface_dp_client_meta = {
    "org.freedesktop.sssd.DataProvider.Client", /* name */
    iface_dp_client__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* arguments for org.freedesktop.sssd.DataProvider.Backend.IsOnline */
const struct sbus_arg_meta iface_dp_backend_IsOnline__in[] = {
    { "domain_name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.DataProvider.Backend.IsOnline */
const struct sbus_arg_meta iface_dp_backend_IsOnline__out[] = {
    { "status", "b" },
    { NULL, }
};

int iface_dp_backend_IsOnline_finish(struct sbus_request *req, bool arg_status)
{
    dbus_bool_t cast_status = arg_status;
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_BOOLEAN, &cast_status,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.DataProvider.Backend */
const struct sbus_method_meta iface_dp_backend__methods[] = {
    {
        "IsOnline", /* name */
        iface_dp_backend_IsOnline__in,
        iface_dp_backend_IsOnline__out,
        offsetof(struct iface_dp_backend, IsOnline),
        invoke_s_method,
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.DataProvider.Backend */
const struct sbus_interface_meta iface_dp_backend_meta = {
    "org.freedesktop.sssd.DataProvider.Backend", /* name */
    iface_dp_backend__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* arguments for org.freedesktop.sssd.DataProvider.Failover.ListServices */
const struct sbus_arg_meta iface_dp_failover_ListServices__in[] = {
    { "domain_name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.DataProvider.Failover.ListServices */
const struct sbus_arg_meta iface_dp_failover_ListServices__out[] = {
    { "services", "as" },
    { NULL, }
};

int iface_dp_failover_ListServices_finish(struct sbus_request *req, const char *arg_services[], int len_services)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &arg_services, len_services,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.DataProvider.Failover.ActiveServer */
const struct sbus_arg_meta iface_dp_failover_ActiveServer__in[] = {
    { "service_name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.DataProvider.Failover.ActiveServer */
const struct sbus_arg_meta iface_dp_failover_ActiveServer__out[] = {
    { "server", "s" },
    { NULL, }
};

int iface_dp_failover_ActiveServer_finish(struct sbus_request *req, const char *arg_server)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_STRING, &arg_server,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.DataProvider.Failover.ListServers */
const struct sbus_arg_meta iface_dp_failover_ListServers__in[] = {
    { "service_name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.DataProvider.Failover.ListServers */
const struct sbus_arg_meta iface_dp_failover_ListServers__out[] = {
    { "servers", "as" },
    { NULL, }
};

int iface_dp_failover_ListServers_finish(struct sbus_request *req, const char *arg_servers[], int len_servers)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &arg_servers, len_servers,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.DataProvider.Failover */
const struct sbus_method_meta iface_dp_failover__methods[] = {
    {
        "ListServices", /* name */
        iface_dp_failover_ListServices__in,
        iface_dp_failover_ListServices__out,
        offsetof(struct iface_dp_failover, ListServices),
        invoke_s_method,
    },
    {
        "ActiveServer", /* name */
        iface_dp_failover_ActiveServer__in,
        iface_dp_failover_ActiveServer__out,
        offsetof(struct iface_dp_failover, ActiveServer),
        invoke_s_method,
    },
    {
        "ListServers", /* name */
        iface_dp_failover_ListServers__in,
        iface_dp_failover_ListServers__out,
        offsetof(struct iface_dp_failover, ListServers),
        invoke_s_method,
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.DataProvider.Failover */
const struct sbus_interface_meta iface_dp_failover_meta = {
    "org.freedesktop.sssd.DataProvider.Failover", /* name */
    iface_dp_failover__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* arguments for org.freedesktop.sssd.dataprovider.autofsHandler */
const struct sbus_arg_meta iface_dp_autofsHandler__in[] = {
    { "dp_flags", "u" },
    { "mapname", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.dataprovider.autofsHandler */
const struct sbus_arg_meta iface_dp_autofsHandler__out[] = {
    { "dp_error", "q" },
    { "error", "u" },
    { "error_message", "s" },
    { NULL, }
};

int iface_dp_autofsHandler_finish(struct sbus_request *req, uint16_t arg_dp_error, uint32_t arg_error, const char *arg_error_message)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_UINT16, &arg_dp_error,
                                         DBUS_TYPE_UINT32, &arg_error,
                                         DBUS_TYPE_STRING, &arg_error_message,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.dataprovider.hostHandler */
const struct sbus_arg_meta iface_dp_hostHandler__in[] = {
    { "dp_flags", "u" },
    { "name", "s" },
    { "alias", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.dataprovider.hostHandler */
const struct sbus_arg_meta iface_dp_hostHandler__out[] = {
    { "dp_error", "q" },
    { "error", "u" },
    { "error_message", "s" },
    { NULL, }
};

int iface_dp_hostHandler_finish(struct sbus_request *req, uint16_t arg_dp_error, uint32_t arg_error, const char *arg_error_message)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_UINT16, &arg_dp_error,
                                         DBUS_TYPE_UINT32, &arg_error,
                                         DBUS_TYPE_STRING, &arg_error_message,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.dataprovider.getDomains */
const struct sbus_arg_meta iface_dp_getDomains__in[] = {
    { "domain_hint", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.dataprovider.getDomains */
const struct sbus_arg_meta iface_dp_getDomains__out[] = {
    { "dp_error", "q" },
    { "error", "u" },
    { "error_message", "s" },
    { NULL, }
};

int iface_dp_getDomains_finish(struct sbus_request *req, uint16_t arg_dp_error, uint32_t arg_error, const char *arg_error_message)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_UINT16, &arg_dp_error,
                                         DBUS_TYPE_UINT32, &arg_error,
                                         DBUS_TYPE_STRING, &arg_error_message,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.dataprovider.getAccountInfo */
const struct sbus_arg_meta iface_dp_getAccountInfo__in[] = {
    { "dp_flags", "u" },
    { "entry_type", "u" },
    { "filter", "s" },
    { "domain", "s" },
    { "extra", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.dataprovider.getAccountInfo */
const struct sbus_arg_meta iface_dp_getAccountInfo__out[] = {
    { "dp_error", "q" },
    { "error", "u" },
    { "error_message", "s" },
    { NULL, }
};

int iface_dp_getAccountInfo_finish(struct sbus_request *req, uint16_t arg_dp_error, uint32_t arg_error, const char *arg_error_message)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_UINT16, &arg_dp_error,
                                         DBUS_TYPE_UINT32, &arg_error,
                                         DBUS_TYPE_STRING, &arg_error_message,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.dataprovider */
const struct sbus_method_meta iface_dp__methods[] = {
    {
        "pamHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_dp, pamHandler),
        NULL, /* no invoker */
    },
    {
        "sudoHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_dp, sudoHandler),
        NULL, /* no invoker */
    },
    {
        "autofsHandler", /* name */
        iface_dp_autofsHandler__in,
        iface_dp_autofsHandler__out,
        offsetof(struct iface_dp, autofsHandler),
        invoke_us_method,
    },
    {
        "hostHandler", /* name */
        iface_dp_hostHandler__in,
        iface_dp_hostHandler__out,
        offsetof(struct iface_dp, hostHandler),
        invoke_uss_method,
    },
    {
        "getDomains", /* name */
        iface_dp_getDomains__in,
        iface_dp_getDomains__out,
        offsetof(struct iface_dp, getDomains),
        invoke_s_method,
    },
    {
        "getAccountInfo", /* name */
        iface_dp_getAccountInfo__in,
        iface_dp_getAccountInfo__out,
        offsetof(struct iface_dp, getAccountInfo),
        invoke_uusss_method,
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.dataprovider */
const struct sbus_interface_meta iface_dp_meta = {
    "org.freedesktop.sssd.dataprovider", /* name */
    iface_dp__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
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

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0);
}

/* invokes a handler with a 'uss' DBus signature */
static int invoke_uss_method(struct sbus_request *dbus_req, void *function_ptr)
{
    uint32_t arg_0;
    const char * arg_1;
    const char * arg_2;
    int (*handler)(struct sbus_request *, void *, uint32_t, const char *, const char *) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_UINT32, &arg_0,
                               DBUS_TYPE_STRING, &arg_1,
                               DBUS_TYPE_STRING, &arg_2,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0,
                     arg_1,
                     arg_2);
}

/* invokes a handler with a 'uusss' DBus signature */
static int invoke_uusss_method(struct sbus_request *dbus_req, void *function_ptr)
{
    uint32_t arg_0;
    uint32_t arg_1;
    const char * arg_2;
    const char * arg_3;
    const char * arg_4;
    int (*handler)(struct sbus_request *, void *, uint32_t, uint32_t, const char *, const char *, const char *) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_UINT32, &arg_0,
                               DBUS_TYPE_UINT32, &arg_1,
                               DBUS_TYPE_STRING, &arg_2,
                               DBUS_TYPE_STRING, &arg_3,
                               DBUS_TYPE_STRING, &arg_4,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0,
                     arg_1,
                     arg_2,
                     arg_3,
                     arg_4);
}

/* invokes a handler with a 'us' DBus signature */
static int invoke_us_method(struct sbus_request *dbus_req, void *function_ptr)
{
    uint32_t arg_0;
    const char * arg_1;
    int (*handler)(struct sbus_request *, void *, uint32_t, const char *) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_UINT32, &arg_0,
                               DBUS_TYPE_STRING, &arg_1,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0,
                     arg_1);
}
