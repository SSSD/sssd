/* The following definitions are auto-generated from ifp_iface.xml */

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_invokers.h"
#include "ifp_iface_generated.h"

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 'u' DBus signature */
static int invoke_u_method(struct sbus_request *dbus_req, void *function_ptr);

/* arguments for org.freedesktop.sssd.infopipe.ListComponents */
const struct sbus_arg_meta infopipe_iface_ListComponents__out[] = {
    { "components", "ao" },
    { NULL, }
};

int infopipe_iface_ListComponents_finish(struct sbus_request *req, const char *arg_components[], int len_components)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_components, len_components,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.ListResponders */
const struct sbus_arg_meta infopipe_iface_ListResponders__out[] = {
    { "responders", "ao" },
    { NULL, }
};

int infopipe_iface_ListResponders_finish(struct sbus_request *req, const char *arg_responders[], int len_responders)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_responders, len_responders,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.ListBackends */
const struct sbus_arg_meta infopipe_iface_ListBackends__out[] = {
    { "backends", "ao" },
    { NULL, }
};

int infopipe_iface_ListBackends_finish(struct sbus_request *req, const char *arg_backends[], int len_backends)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_backends, len_backends,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.FindMonitor */
const struct sbus_arg_meta infopipe_iface_FindMonitor__out[] = {
    { "monitor", "o" },
    { NULL, }
};

int infopipe_iface_FindMonitor_finish(struct sbus_request *req, const char *arg_monitor)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_monitor,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.FindResponderByName */
const struct sbus_arg_meta infopipe_iface_FindResponderByName__in[] = {
    { "name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.FindResponderByName */
const struct sbus_arg_meta infopipe_iface_FindResponderByName__out[] = {
    { "responder", "o" },
    { NULL, }
};

int infopipe_iface_FindResponderByName_finish(struct sbus_request *req, const char *arg_responder)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_responder,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.FindBackendByName */
const struct sbus_arg_meta infopipe_iface_FindBackendByName__in[] = {
    { "name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.FindBackendByName */
const struct sbus_arg_meta infopipe_iface_FindBackendByName__out[] = {
    { "backend", "o" },
    { NULL, }
};

int infopipe_iface_FindBackendByName_finish(struct sbus_request *req, const char *arg_backend)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_backend,
                                         DBUS_TYPE_INVALID);
}

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

/* arguments for org.freedesktop.sssd.infopipe.FindDomainByName */
const struct sbus_arg_meta infopipe_iface_FindDomainByName__in[] = {
    { "name", "s" },
    { NULL, }
};

/* arguments for org.freedesktop.sssd.infopipe.FindDomainByName */
const struct sbus_arg_meta infopipe_iface_FindDomainByName__out[] = {
    { "domain", "o" },
    { NULL, }
};

int infopipe_iface_FindDomainByName_finish(struct sbus_request *req, const char *arg_domain)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_OBJECT_PATH, &arg_domain,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.ListDomains */
const struct sbus_arg_meta infopipe_iface_ListDomains__out[] = {
    { "domain", "ao" },
    { NULL, }
};

int infopipe_iface_ListDomains_finish(struct sbus_request *req, const char *arg_domain[], int len_domain)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH, &arg_domain, len_domain,
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
        "ListComponents", /* name */
        NULL, /* no in_args */
        infopipe_iface_ListComponents__out,
        offsetof(struct infopipe_iface, ListComponents),
        NULL, /* no invoker */
    },
    {
        "ListResponders", /* name */
        NULL, /* no in_args */
        infopipe_iface_ListResponders__out,
        offsetof(struct infopipe_iface, ListResponders),
        NULL, /* no invoker */
    },
    {
        "ListBackends", /* name */
        NULL, /* no in_args */
        infopipe_iface_ListBackends__out,
        offsetof(struct infopipe_iface, ListBackends),
        NULL, /* no invoker */
    },
    {
        "FindMonitor", /* name */
        NULL, /* no in_args */
        infopipe_iface_FindMonitor__out,
        offsetof(struct infopipe_iface, FindMonitor),
        NULL, /* no invoker */
    },
    {
        "FindResponderByName", /* name */
        infopipe_iface_FindResponderByName__in,
        infopipe_iface_FindResponderByName__out,
        offsetof(struct infopipe_iface, FindResponderByName),
        invoke_s_method,
    },
    {
        "FindBackendByName", /* name */
        infopipe_iface_FindBackendByName__in,
        infopipe_iface_FindBackendByName__out,
        offsetof(struct infopipe_iface, FindBackendByName),
        invoke_s_method,
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
    {
        "FindDomainByName", /* name */
        infopipe_iface_FindDomainByName__in,
        infopipe_iface_FindDomainByName__out,
        offsetof(struct infopipe_iface, FindDomainByName),
        invoke_s_method,
    },
    {
        "ListDomains", /* name */
        NULL, /* no in_args */
        infopipe_iface_ListDomains__out,
        offsetof(struct infopipe_iface, ListDomains),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe */
const struct sbus_interface_meta infopipe_iface_meta = {
    "org.freedesktop.sssd.infopipe", /* name */
    infopipe_iface__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

int infopipe_component_Enable_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

int infopipe_component_Disable_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Components.ChangeDebugLevel */
const struct sbus_arg_meta infopipe_component_ChangeDebugLevel__in[] = {
    { "new_level", "u" },
    { NULL, }
};

int infopipe_component_ChangeDebugLevel_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.infopipe.Components.ChangeDebugLevelTemporarily */
const struct sbus_arg_meta infopipe_component_ChangeDebugLevelTemporarily__in[] = {
    { "new_level", "u" },
    { NULL, }
};

int infopipe_component_ChangeDebugLevelTemporarily_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.infopipe.Components */
const struct sbus_method_meta infopipe_component__methods[] = {
    {
        "Enable", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct infopipe_component, Enable),
        NULL, /* no invoker */
    },
    {
        "Disable", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct infopipe_component, Disable),
        NULL, /* no invoker */
    },
    {
        "ChangeDebugLevel", /* name */
        infopipe_component_ChangeDebugLevel__in,
        NULL, /* no out_args */
        offsetof(struct infopipe_component, ChangeDebugLevel),
        invoke_u_method,
    },
    {
        "ChangeDebugLevelTemporarily", /* name */
        infopipe_component_ChangeDebugLevelTemporarily__in,
        NULL, /* no out_args */
        offsetof(struct infopipe_component, ChangeDebugLevelTemporarily),
        invoke_u_method,
    },
    { NULL, }
};

/* property info for org.freedesktop.sssd.infopipe.Components */
const struct sbus_property_meta infopipe_component__properties[] = {
    {
        "name", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_component, infopipe_component_get_name),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "debug_level", /* name */
        "u", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_component, infopipe_component_get_debug_level),
        sbus_invoke_get_u,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "enabled", /* name */
        "b", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_component, infopipe_component_get_enabled),
        sbus_invoke_get_b,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "type", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_component, infopipe_component_get_type),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "providers", /* name */
        "as", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_component, infopipe_component_get_providers),
        sbus_invoke_get_as,
        0, /* not writable */
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe.Components */
const struct sbus_interface_meta infopipe_component_meta = {
    "org.freedesktop.sssd.infopipe.Components", /* name */
    infopipe_component__methods,
    NULL, /* no signals */
    infopipe_component__properties,
    sbus_invoke_get_all, /* GetAll invoker */
};

/* property info for org.freedesktop.sssd.infopipe.Domains */
const struct sbus_property_meta infopipe_domain__properties[] = {
    {
        "name", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_name),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "provider", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_provider),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "primary_servers", /* name */
        "as", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_primary_servers),
        sbus_invoke_get_as,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "backup_servers", /* name */
        "as", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_backup_servers),
        sbus_invoke_get_as,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "min_id", /* name */
        "u", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_min_id),
        sbus_invoke_get_u,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "max_id", /* name */
        "u", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_max_id),
        sbus_invoke_get_u,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "realm", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_realm),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "forest", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_forest),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "login_format", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_login_format),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "fully_qualified_name_format", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_fully_qualified_name_format),
        sbus_invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "enumerable", /* name */
        "b", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_enumerable),
        sbus_invoke_get_b,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "use_fully_qualified_names", /* name */
        "b", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_use_fully_qualified_names),
        sbus_invoke_get_b,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "subdomain", /* name */
        "b", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_subdomain),
        sbus_invoke_get_b,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "parent_domain", /* name */
        "o", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_parent_domain),
        sbus_invoke_get_o,
        0, /* not writable */
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.infopipe.Domains */
const struct sbus_interface_meta infopipe_domain_meta = {
    "org.freedesktop.sssd.infopipe.Domains", /* name */
    NULL, /* no methods */
    NULL, /* no signals */
    infopipe_domain__properties,
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
