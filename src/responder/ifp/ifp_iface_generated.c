/* The following definitions are auto-generated from ifp_iface.xml */

#include <stddef.h>

#include "dbus/dbus-protocol.h"
#include "util/util_errors.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_invokers.h"
#include "ifp_iface_generated.h"

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 'u' DBus signature */
static int invoke_u_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 'su' DBus signature */
static int invoke_su_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 'ss' DBus signature */
static int invoke_ss_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 'ssu' DBus signature */
static int invoke_ssu_method(struct sbus_request *dbus_req, void *function_ptr);

/* arguments for org.freedesktop.sssd.infopipe.Ping */
const struct sbus_arg_meta iface_ifp_Ping__in[] = {
    { "ping", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Ping */
const struct sbus_arg_meta iface_ifp_Ping__out[] = {
    { "pong", "s" },
    { NULL, }
};

int iface_ifp_Ping_finish(struct sbus_request *req, const char *arg_pong)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_STRING, &arg_pong,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.ListComponents */
const struct sbus_arg_meta iface_ifp_ListComponents__out[] = {
    { "components", "ao" },
    { NULL, }
};

int iface_ifp_ListComponents_finish(struct sbus_request *req, const char *arg_components[], int len_components)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_components, len_components,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.ListResponders */
const struct sbus_arg_meta iface_ifp_ListResponders__out[] = {
    { "responders", "ao" },
    { NULL, }
};

int iface_ifp_ListResponders_finish(struct sbus_request *req, const char *arg_responders[], int len_responders)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_responders, len_responders,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.ListBackends */
const struct sbus_arg_meta iface_ifp_ListBackends__out[] = {
    { "backends", "ao" },
    { NULL, }
};

int iface_ifp_ListBackends_finish(struct sbus_request *req, const char *arg_backends[], int len_backends)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_backends, len_backends,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.FindMonitor */
const struct sbus_arg_meta iface_ifp_FindMonitor__out[] = {
    { "monitor", "o" },
    { NULL, }
};

int iface_ifp_FindMonitor_finish(struct sbus_request *req, const char *arg_monitor)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_monitor,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.FindResponderByName */
const struct sbus_arg_meta iface_ifp_FindResponderByName__in[] = {
    { "name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.FindResponderByName */
const struct sbus_arg_meta iface_ifp_FindResponderByName__out[] = {
    { "responder", "o" },
    { NULL, }
};

int iface_ifp_FindResponderByName_finish(struct sbus_request *req, const char *arg_responder)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_responder,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.FindBackendByName */
const struct sbus_arg_meta iface_ifp_FindBackendByName__in[] = {
    { "name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.FindBackendByName */
const struct sbus_arg_meta iface_ifp_FindBackendByName__out[] = {
    { "backend", "o" },
    { NULL, }
};

int iface_ifp_FindBackendByName_finish(struct sbus_request *req, const char *arg_backend)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_backend,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.GetUserAttr */
const struct sbus_arg_meta iface_ifp_GetUserAttr__in[] = {
    { "user", "s" },
    { "attr", "as" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.GetUserAttr */
const struct sbus_arg_meta iface_ifp_GetUserAttr__out[] = {
    { "values", "a{sv}" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.GetUserGroups */
const struct sbus_arg_meta iface_ifp_GetUserGroups__in[] = {
    { "user", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.GetUserGroups */
const struct sbus_arg_meta iface_ifp_GetUserGroups__out[] = {
    { "values", "as" },
    { NULL, }
};

int iface_ifp_GetUserGroups_finish(struct sbus_request *req, const char *arg_values[], int len_values)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &arg_values, len_values,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.FindDomainByName */
const struct sbus_arg_meta iface_ifp_FindDomainByName__in[] = {
    { "name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.FindDomainByName */
const struct sbus_arg_meta iface_ifp_FindDomainByName__out[] = {
    { "domain", "o" },
    { NULL, }
};

int iface_ifp_FindDomainByName_finish(struct sbus_request *req, const char *arg_domain)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_domain,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.ListDomains */
const struct sbus_arg_meta iface_ifp_ListDomains__out[] = {
    { "domain", "ao" },
    { NULL, }
};

int iface_ifp_ListDomains_finish(struct sbus_request *req, const char *arg_domain[], int len_domain)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_domain, len_domain,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.infopipe */
const struct sbus_method_meta iface_ifp__methods[] = {
    {
        "Ping", /* name */
        iface_ifp_Ping__in,
        iface_ifp_Ping__out,
        offsetof(struct iface_ifp, Ping),
        invoke_s_method,
    },
    {
        "ListComponents", /* name */
        NULL, /* no in_args */
        iface_ifp_ListComponents__out,
        offsetof(struct iface_ifp, ListComponents),
        NULL, /* no invoker */
    },
    {
        "ListResponders", /* name */
        NULL, /* no in_args */
        iface_ifp_ListResponders__out,
        offsetof(struct iface_ifp, ListResponders),
        NULL, /* no invoker */
    },
    {
        "ListBackends", /* name */
        NULL, /* no in_args */
        iface_ifp_ListBackends__out,
        offsetof(struct iface_ifp, ListBackends),
        NULL, /* no invoker */
    },
    {
        "FindMonitor", /* name */
        NULL, /* no in_args */
        iface_ifp_FindMonitor__out,
        offsetof(struct iface_ifp, FindMonitor),
        NULL, /* no invoker */
    },
    {
        "FindResponderByName", /* name */
        iface_ifp_FindResponderByName__in,
        iface_ifp_FindResponderByName__out,
        offsetof(struct iface_ifp, FindResponderByName),
        invoke_s_method,
    },
    {
        "FindBackendByName", /* name */
        iface_ifp_FindBackendByName__in,
        iface_ifp_FindBackendByName__out,
        offsetof(struct iface_ifp, FindBackendByName),
        invoke_s_method,
    },
    {
        "GetUserAttr", /* name */
        iface_ifp_GetUserAttr__in,
        iface_ifp_GetUserAttr__out,
        offsetof(struct iface_ifp, GetUserAttr),
        NULL, /* no invoker */
    },
    {
        "GetUserGroups", /* name */
        iface_ifp_GetUserGroups__in,
        iface_ifp_GetUserGroups__out,
        offsetof(struct iface_ifp, GetUserGroups),
        invoke_s_method,
    },
    {
        "FindDomainByName", /* name */
        iface_ifp_FindDomainByName__in,
        iface_ifp_FindDomainByName__out,
        offsetof(struct iface_ifp, FindDomainByName),
        invoke_s_method,
    },
    {
        "ListDomains", /* name */
        NULL, /* no in_args */
        iface_ifp_ListDomains__out,
        offsetof(struct iface_ifp, ListDomains),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe */
const struct sbus_interface_meta iface_ifp_meta = {
    "org.freedesktop.sssd.infopipe", /* name */
    iface_ifp__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* property info for org.freedesktop.sssd.infopipe.Components */
const struct sbus_property_meta iface_ifp_components__properties[] = {
    {
        "name", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_components, get_name),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "debug_level", /* name */
        "u", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_components, get_debug_level),
        sbus_invoke_get_u,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "enabled", /* name */
        "b", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_components, get_enabled),
        sbus_invoke_get_b,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "type", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_components, get_type),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "providers", /* name */
        "as", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_components, get_providers),
        sbus_invoke_get_as,
        0, /* not writable */
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe.Components */
const struct sbus_interface_meta iface_ifp_components_meta = {
    "org.freedesktop.sssd.infopipe.Components", /* name */
    NULL, /* no methods */
    NULL, /* no signals */
    iface_ifp_components__properties,
    sbus_invoke_get_all, /* GetAll invoker */
};

/* property info for org.freedesktop.sssd.infopipe.Domains */
const struct sbus_property_meta iface_ifp_domains__properties[] = {
    {
        "name", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_name),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "provider", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_provider),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "primary_servers", /* name */
        "as", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_primary_servers),
        sbus_invoke_get_as,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "backup_servers", /* name */
        "as", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_backup_servers),
        sbus_invoke_get_as,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "min_id", /* name */
        "u", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_min_id),
        sbus_invoke_get_u,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "max_id", /* name */
        "u", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_max_id),
        sbus_invoke_get_u,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "realm", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_realm),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "forest", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_forest),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "login_format", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_login_format),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "fully_qualified_name_format", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_fully_qualified_name_format),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "enumerable", /* name */
        "b", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_enumerable),
        sbus_invoke_get_b,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "use_fully_qualified_names", /* name */
        "b", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_use_fully_qualified_names),
        sbus_invoke_get_b,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "subdomain", /* name */
        "b", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_subdomain),
        sbus_invoke_get_b,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "parent_domain", /* name */
        "o", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_domains, get_parent_domain),
        sbus_invoke_get_o,
        0, /* not writable */
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe.Domains */
const struct sbus_interface_meta iface_ifp_domains_meta = {
    "org.freedesktop.sssd.infopipe.Domains", /* name */
    NULL, /* no methods */
    NULL, /* no signals */
    iface_ifp_domains__properties,
    sbus_invoke_get_all, /* GetAll invoker */
};

/* arguments for org.freedesktop.sssd.infopipe.Domains.Domain.IsOnline */
const struct sbus_arg_meta iface_ifp_domains_domain_IsOnline__out[] = {
    { "status", "b" },
    { NULL, }
};

int iface_ifp_domains_domain_IsOnline_finish(struct sbus_request *req, bool arg_status)
{
    dbus_bool_t cast_status = arg_status;
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_BOOLEAN, &cast_status,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Domains.Domain.ListServices */
const struct sbus_arg_meta iface_ifp_domains_domain_ListServices__out[] = {
    { "services", "as" },
    { NULL, }
};

int iface_ifp_domains_domain_ListServices_finish(struct sbus_request *req, const char *arg_services[], int len_services)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &arg_services, len_services,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Domains.Domain.ActiveServer */
const struct sbus_arg_meta iface_ifp_domains_domain_ActiveServer__in[] = {
    { "service", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Domains.Domain.ActiveServer */
const struct sbus_arg_meta iface_ifp_domains_domain_ActiveServer__out[] = {
    { "server", "s" },
    { NULL, }
};

int iface_ifp_domains_domain_ActiveServer_finish(struct sbus_request *req, const char *arg_server)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_STRING, &arg_server,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Domains.Domain.ListServers */
const struct sbus_arg_meta iface_ifp_domains_domain_ListServers__in[] = {
    { "service_name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Domains.Domain.ListServers */
const struct sbus_arg_meta iface_ifp_domains_domain_ListServers__out[] = {
    { "servers", "as" },
    { NULL, }
};

int iface_ifp_domains_domain_ListServers_finish(struct sbus_request *req, const char *arg_servers[], int len_servers)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &arg_servers, len_servers,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.infopipe.Domains.Domain */
const struct sbus_method_meta iface_ifp_domains_domain__methods[] = {
    {
        "IsOnline", /* name */
        NULL, /* no in_args */
        iface_ifp_domains_domain_IsOnline__out,
        offsetof(struct iface_ifp_domains_domain, IsOnline),
        NULL, /* no invoker */
    },
    {
        "ListServices", /* name */
        NULL, /* no in_args */
        iface_ifp_domains_domain_ListServices__out,
        offsetof(struct iface_ifp_domains_domain, ListServices),
        NULL, /* no invoker */
    },
    {
        "ActiveServer", /* name */
        iface_ifp_domains_domain_ActiveServer__in,
        iface_ifp_domains_domain_ActiveServer__out,
        offsetof(struct iface_ifp_domains_domain, ActiveServer),
        invoke_s_method,
    },
    {
        "ListServers", /* name */
        iface_ifp_domains_domain_ListServers__in,
        iface_ifp_domains_domain_ListServers__out,
        offsetof(struct iface_ifp_domains_domain, ListServers),
        invoke_s_method,
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe.Domains.Domain */
const struct sbus_interface_meta iface_ifp_domains_domain_meta = {
    "org.freedesktop.sssd.infopipe.Domains.Domain", /* name */
    iface_ifp_domains_domain__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* arguments for org.freedesktop.sssd.infopipe.Cache.List */
const struct sbus_arg_meta iface_ifp_cache_List__out[] = {
    { "result", "ao" },
    { NULL, }
};

int iface_ifp_cache_List_finish(struct sbus_request *req, const char *arg_result[], int len_result)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_result, len_result,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Cache.ListByDomain */
const struct sbus_arg_meta iface_ifp_cache_ListByDomain__in[] = {
    { "domain_name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Cache.ListByDomain */
const struct sbus_arg_meta iface_ifp_cache_ListByDomain__out[] = {
    { "result", "ao" },
    { NULL, }
};

int iface_ifp_cache_ListByDomain_finish(struct sbus_request *req, const char *arg_result[], int len_result)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_result, len_result,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.infopipe.Cache */
const struct sbus_method_meta iface_ifp_cache__methods[] = {
    {
        "List", /* name */
        NULL, /* no in_args */
        iface_ifp_cache_List__out,
        offsetof(struct iface_ifp_cache, List),
        NULL, /* no invoker */
    },
    {
        "ListByDomain", /* name */
        iface_ifp_cache_ListByDomain__in,
        iface_ifp_cache_ListByDomain__out,
        offsetof(struct iface_ifp_cache, ListByDomain),
        invoke_s_method,
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe.Cache */
const struct sbus_interface_meta iface_ifp_cache_meta = {
    "org.freedesktop.sssd.infopipe.Cache", /* name */
    iface_ifp_cache__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* arguments for org.freedesktop.sssd.infopipe.Cache.Object.Store */
const struct sbus_arg_meta iface_ifp_cache_object_Store__out[] = {
    { "result", "b" },
    { NULL, }
};

int iface_ifp_cache_object_Store_finish(struct sbus_request *req, bool arg_result)
{
    dbus_bool_t cast_result = arg_result;
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_BOOLEAN, &cast_result,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Cache.Object.Remove */
const struct sbus_arg_meta iface_ifp_cache_object_Remove__out[] = {
    { "result", "b" },
    { NULL, }
};

int iface_ifp_cache_object_Remove_finish(struct sbus_request *req, bool arg_result)
{
    dbus_bool_t cast_result = arg_result;
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_BOOLEAN, &cast_result,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.infopipe.Cache.Object */
const struct sbus_method_meta iface_ifp_cache_object__methods[] = {
    {
        "Store", /* name */
        NULL, /* no in_args */
        iface_ifp_cache_object_Store__out,
        offsetof(struct iface_ifp_cache_object, Store),
        NULL, /* no invoker */
    },
    {
        "Remove", /* name */
        NULL, /* no in_args */
        iface_ifp_cache_object_Remove__out,
        offsetof(struct iface_ifp_cache_object, Remove),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe.Cache.Object */
const struct sbus_interface_meta iface_ifp_cache_object_meta = {
    "org.freedesktop.sssd.infopipe.Cache.Object", /* name */
    iface_ifp_cache_object__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* arguments for org.freedesktop.sssd.infopipe.Users.FindByName */
const struct sbus_arg_meta iface_ifp_users_FindByName__in[] = {
    { "name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Users.FindByName */
const struct sbus_arg_meta iface_ifp_users_FindByName__out[] = {
    { "result", "o" },
    { NULL, }
};

int iface_ifp_users_FindByName_finish(struct sbus_request *req, const char *arg_result)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_result,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Users.FindByID */
const struct sbus_arg_meta iface_ifp_users_FindByID__in[] = {
    { "id", "u" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Users.FindByID */
const struct sbus_arg_meta iface_ifp_users_FindByID__out[] = {
    { "result", "o" },
    { NULL, }
};

int iface_ifp_users_FindByID_finish(struct sbus_request *req, const char *arg_result)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_result,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Users.FindByCertificate */
const struct sbus_arg_meta iface_ifp_users_FindByCertificate__in[] = {
    { "pem_cert", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Users.FindByCertificate */
const struct sbus_arg_meta iface_ifp_users_FindByCertificate__out[] = {
    { "result", "o" },
    { NULL, }
};

int iface_ifp_users_FindByCertificate_finish(struct sbus_request *req, const char *arg_result)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_result,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Users.ListByCertificate */
const struct sbus_arg_meta iface_ifp_users_ListByCertificate__in[] = {
    { "pem_cert", "s" },
    { "limit", "u" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Users.ListByCertificate */
const struct sbus_arg_meta iface_ifp_users_ListByCertificate__out[] = {
    { "result", "ao" },
    { NULL, }
};

int iface_ifp_users_ListByCertificate_finish(struct sbus_request *req, const char *arg_result[], int len_result)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_result, len_result,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Users.FindByNameAndCertificate */
const struct sbus_arg_meta iface_ifp_users_FindByNameAndCertificate__in[] = {
    { "name", "s" },
    { "pem_cert", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Users.FindByNameAndCertificate */
const struct sbus_arg_meta iface_ifp_users_FindByNameAndCertificate__out[] = {
    { "result", "o" },
    { NULL, }
};

int iface_ifp_users_FindByNameAndCertificate_finish(struct sbus_request *req, const char *arg_result)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_result,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Users.ListByName */
const struct sbus_arg_meta iface_ifp_users_ListByName__in[] = {
    { "name_filter", "s" },
    { "limit", "u" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Users.ListByName */
const struct sbus_arg_meta iface_ifp_users_ListByName__out[] = {
    { "result", "ao" },
    { NULL, }
};

int iface_ifp_users_ListByName_finish(struct sbus_request *req, const char *arg_result[], int len_result)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_result, len_result,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Users.ListByDomainAndName */
const struct sbus_arg_meta iface_ifp_users_ListByDomainAndName__in[] = {
    { "domain_name", "s" },
    { "name_filter", "s" },
    { "limit", "u" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Users.ListByDomainAndName */
const struct sbus_arg_meta iface_ifp_users_ListByDomainAndName__out[] = {
    { "result", "ao" },
    { NULL, }
};

int iface_ifp_users_ListByDomainAndName_finish(struct sbus_request *req, const char *arg_result[], int len_result)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_result, len_result,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.infopipe.Users */
const struct sbus_method_meta iface_ifp_users__methods[] = {
    {
        "FindByName", /* name */
        iface_ifp_users_FindByName__in,
        iface_ifp_users_FindByName__out,
        offsetof(struct iface_ifp_users, FindByName),
        invoke_s_method,
    },
    {
        "FindByID", /* name */
        iface_ifp_users_FindByID__in,
        iface_ifp_users_FindByID__out,
        offsetof(struct iface_ifp_users, FindByID),
        invoke_u_method,
    },
    {
        "FindByCertificate", /* name */
        iface_ifp_users_FindByCertificate__in,
        iface_ifp_users_FindByCertificate__out,
        offsetof(struct iface_ifp_users, FindByCertificate),
        invoke_s_method,
    },
    {
        "ListByCertificate", /* name */
        iface_ifp_users_ListByCertificate__in,
        iface_ifp_users_ListByCertificate__out,
        offsetof(struct iface_ifp_users, ListByCertificate),
        invoke_su_method,
    },
    {
        "FindByNameAndCertificate", /* name */
        iface_ifp_users_FindByNameAndCertificate__in,
        iface_ifp_users_FindByNameAndCertificate__out,
        offsetof(struct iface_ifp_users, FindByNameAndCertificate),
        invoke_ss_method,
    },
    {
        "ListByName", /* name */
        iface_ifp_users_ListByName__in,
        iface_ifp_users_ListByName__out,
        offsetof(struct iface_ifp_users, ListByName),
        invoke_su_method,
    },
    {
        "ListByDomainAndName", /* name */
        iface_ifp_users_ListByDomainAndName__in,
        iface_ifp_users_ListByDomainAndName__out,
        offsetof(struct iface_ifp_users, ListByDomainAndName),
        invoke_ssu_method,
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe.Users */
const struct sbus_interface_meta iface_ifp_users_meta = {
    "org.freedesktop.sssd.infopipe.Users", /* name */
    iface_ifp_users__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

int iface_ifp_users_user_UpdateGroupsList_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.infopipe.Users.User */
const struct sbus_method_meta iface_ifp_users_user__methods[] = {
    {
        "UpdateGroupsList", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_ifp_users_user, UpdateGroupsList),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* property info for org.freedesktop.sssd.infopipe.Users.User */
const struct sbus_property_meta iface_ifp_users_user__properties[] = {
    {
        "name", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_users_user, get_name),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "uidNumber", /* name */
        "u", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_users_user, get_uidNumber),
        sbus_invoke_get_u,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "gidNumber", /* name */
        "u", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_users_user, get_gidNumber),
        sbus_invoke_get_u,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "gecos", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_users_user, get_gecos),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "homeDirectory", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_users_user, get_homeDirectory),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "loginShell", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_users_user, get_loginShell),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "uniqueID", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_users_user, get_uniqueID),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "groups", /* name */
        "ao", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_users_user, get_groups),
        sbus_invoke_get_ao,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "domain", /* name */
        "o", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_users_user, get_domain),
        sbus_invoke_get_o,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "domainname", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_users_user, get_domainname),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "extraAttributes", /* name */
        "a{sas}", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_users_user, get_extraAttributes),
        sbus_invoke_get_aDOsasDE,
        0, /* not writable */
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe.Users.User */
const struct sbus_interface_meta iface_ifp_users_user_meta = {
    "org.freedesktop.sssd.infopipe.Users.User", /* name */
    iface_ifp_users_user__methods,
    NULL, /* no signals */
    iface_ifp_users_user__properties,
    sbus_invoke_get_all, /* GetAll invoker */
};

/* arguments for org.freedesktop.sssd.infopipe.Groups.FindByName */
const struct sbus_arg_meta iface_ifp_groups_FindByName__in[] = {
    { "name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Groups.FindByName */
const struct sbus_arg_meta iface_ifp_groups_FindByName__out[] = {
    { "result", "o" },
    { NULL, }
};

int iface_ifp_groups_FindByName_finish(struct sbus_request *req, const char *arg_result)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_result,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Groups.FindByID */
const struct sbus_arg_meta iface_ifp_groups_FindByID__in[] = {
    { "id", "u" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Groups.FindByID */
const struct sbus_arg_meta iface_ifp_groups_FindByID__out[] = {
    { "result", "o" },
    { NULL, }
};

int iface_ifp_groups_FindByID_finish(struct sbus_request *req, const char *arg_result)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_result,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Groups.ListByName */
const struct sbus_arg_meta iface_ifp_groups_ListByName__in[] = {
    { "name_filter", "s" },
    { "limit", "u" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Groups.ListByName */
const struct sbus_arg_meta iface_ifp_groups_ListByName__out[] = {
    { "result", "ao" },
    { NULL, }
};

int iface_ifp_groups_ListByName_finish(struct sbus_request *req, const char *arg_result[], int len_result)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_result, len_result,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Groups.ListByDomainAndName */
const struct sbus_arg_meta iface_ifp_groups_ListByDomainAndName__in[] = {
    { "domain_name", "s" },
    { "name_filter", "s" },
    { "limit", "u" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.Groups.ListByDomainAndName */
const struct sbus_arg_meta iface_ifp_groups_ListByDomainAndName__out[] = {
    { "result", "ao" },
    { NULL, }
};

int iface_ifp_groups_ListByDomainAndName_finish(struct sbus_request *req, const char *arg_result[], int len_result)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_result, len_result,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.infopipe.Groups */
const struct sbus_method_meta iface_ifp_groups__methods[] = {
    {
        "FindByName", /* name */
        iface_ifp_groups_FindByName__in,
        iface_ifp_groups_FindByName__out,
        offsetof(struct iface_ifp_groups, FindByName),
        invoke_s_method,
    },
    {
        "FindByID", /* name */
        iface_ifp_groups_FindByID__in,
        iface_ifp_groups_FindByID__out,
        offsetof(struct iface_ifp_groups, FindByID),
        invoke_u_method,
    },
    {
        "ListByName", /* name */
        iface_ifp_groups_ListByName__in,
        iface_ifp_groups_ListByName__out,
        offsetof(struct iface_ifp_groups, ListByName),
        invoke_su_method,
    },
    {
        "ListByDomainAndName", /* name */
        iface_ifp_groups_ListByDomainAndName__in,
        iface_ifp_groups_ListByDomainAndName__out,
        offsetof(struct iface_ifp_groups, ListByDomainAndName),
        invoke_ssu_method,
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe.Groups */
const struct sbus_interface_meta iface_ifp_groups_meta = {
    "org.freedesktop.sssd.infopipe.Groups", /* name */
    iface_ifp_groups__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

int iface_ifp_groups_group_UpdateMemberList_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.infopipe.Groups.Group */
const struct sbus_method_meta iface_ifp_groups_group__methods[] = {
    {
        "UpdateMemberList", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_ifp_groups_group, UpdateMemberList),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* property info for org.freedesktop.sssd.infopipe.Groups.Group */
const struct sbus_property_meta iface_ifp_groups_group__properties[] = {
    {
        "name", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_groups_group, get_name),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "gidNumber", /* name */
        "u", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_groups_group, get_gidNumber),
        sbus_invoke_get_u,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "uniqueID", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_groups_group, get_uniqueID),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "users", /* name */
        "ao", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_groups_group, get_users),
        sbus_invoke_get_ao,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "groups", /* name */
        "ao", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct iface_ifp_groups_group, get_groups),
        sbus_invoke_get_ao,
        0, /* not writable */
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe.Groups.Group */
const struct sbus_interface_meta iface_ifp_groups_group_meta = {
    "org.freedesktop.sssd.infopipe.Groups.Group", /* name */
    iface_ifp_groups_group__methods,
    NULL, /* no signals */
    iface_ifp_groups_group__properties,
    sbus_invoke_get_all, /* GetAll invoker */
};

/* invokes a handler with a 'ss' DBus signature */
static int invoke_ss_method(struct sbus_request *dbus_req, void *function_ptr)
{
    const char * arg_0;
    const char * arg_1;
    int (*handler)(struct sbus_request *, void *, const char *, const char *) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_STRING, &arg_0,
                               DBUS_TYPE_STRING, &arg_1,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0,
                     arg_1);
}

/* invokes a handler with a 'ssu' DBus signature */
static int invoke_ssu_method(struct sbus_request *dbus_req, void *function_ptr)
{
    const char * arg_0;
    const char * arg_1;
    uint32_t arg_2;
    int (*handler)(struct sbus_request *, void *, const char *, const char *, uint32_t) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_STRING, &arg_0,
                               DBUS_TYPE_STRING, &arg_1,
                               DBUS_TYPE_UINT32, &arg_2,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0,
                     arg_1,
                     arg_2);
}

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

/* invokes a handler with a 'su' DBus signature */
static int invoke_su_method(struct sbus_request *dbus_req, void *function_ptr)
{
    const char * arg_0;
    uint32_t arg_1;
    int (*handler)(struct sbus_request *, void *, const char *, uint32_t) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_STRING, &arg_0,
                               DBUS_TYPE_UINT32, &arg_1,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0,
                     arg_1);
}
