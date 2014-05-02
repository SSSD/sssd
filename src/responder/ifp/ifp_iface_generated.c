/* The following definitions are auto-generated from ifp_iface.xml */

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "ifp_iface_generated.h"

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr);

/* invokes a handler with a 'u' DBus signature */
static int invoke_u_method(struct sbus_request *dbus_req, void *function_ptr);
static int invoke_get_s(struct sbus_request *dbus_req, void *function_ptr);
static int invoke_get_u(struct sbus_request *dbus_req, void *function_ptr);
static int invoke_get_b(struct sbus_request *dbus_req, void *function_ptr);
static int invoke_get_as(struct sbus_request *dbus_req, void *function_ptr);
static int invoke_get_o(struct sbus_request *dbus_req, void *function_ptr);

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

/* invokes GetAll for the 'org.freedesktop.sssd.infopipe' interface */
static int invoke_infopipe_iface_get_all(struct sbus_request *dbus_req, void *function_ptr)
{
    DBusMessage *reply;
    dbus_bool_t dbret;
    DBusMessageIter iter;
    DBusMessageIter iter_dict;

    reply = dbus_message_new_method_return(dbus_req->message);
    if (!reply) return ENOMEM;
    dbus_message_iter_init_append(reply, &iter);
    dbret = dbus_message_iter_open_container(
                                     &iter, DBUS_TYPE_ARRAY,
                                     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                     DBUS_TYPE_STRING_AS_STRING
                                     DBUS_TYPE_VARIANT_AS_STRING
                                     DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                     &iter_dict);
    if (!dbret) return ENOMEM;

    dbret = dbus_message_iter_close_container(&iter, &iter_dict);
    if (!dbret) return ENOMEM;

    return sbus_request_finish(dbus_req, reply);
}

/* interface info for org.freedesktop.sssd.infopipe */
const struct sbus_interface_meta infopipe_iface_meta = {
    "org.freedesktop.sssd.infopipe", /* name */
    infopipe_iface__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    invoke_infopipe_iface_get_all, /* GetAll invoker */
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

/* invokes GetAll for the 'org.freedesktop.sssd.infopipe.Components' interface */
static int invoke_infopipe_component_get_all(struct sbus_request *dbus_req, void *function_ptr)
{
    struct sbus_interface *intf = dbus_req->intf;
    const struct sbus_property_meta *property;
    DBusMessage *reply;
    dbus_bool_t dbret;
    DBusMessageIter iter;
    DBusMessageIter iter_dict;
    int ret;
    const char * s_prop_val;
    const char * s_out_val;
    void (*s_handler)(struct sbus_request *, void *data, const char * *);
    bool b_prop_val;
    dbus_bool_t b_out_val;
    void (*b_handler)(struct sbus_request *, void *data, bool *);
    uint32_t u_prop_val;
    uint32_t u_out_val;
    void (*u_handler)(struct sbus_request *, void *data, uint32_t *);
    const char * *as_prop_val;
    int as_prop_len;
    const char * *as_out_val;
    void (*as_handler)(struct sbus_request *, void *data, const char * * *, int *);

    reply = dbus_message_new_method_return(dbus_req->message);
    if (!reply) return ENOMEM;
    dbus_message_iter_init_append(reply, &iter);
    dbret = dbus_message_iter_open_container(
                                     &iter, DBUS_TYPE_ARRAY,
                                     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                     DBUS_TYPE_STRING_AS_STRING
                                     DBUS_TYPE_VARIANT_AS_STRING
                                     DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                     &iter_dict);
    if (!dbret) return ENOMEM;

    property = sbus_meta_find_property(intf->vtable->meta, "name");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        s_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (s_handler) {
            (s_handler)(dbus_req, dbus_req->intf->instance_data, &s_prop_val);
            s_out_val = s_prop_val == NULL ? "" : s_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "name", DBUS_TYPE_STRING, &s_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "debug_level");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        u_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (u_handler) {
            (u_handler)(dbus_req, dbus_req->intf->instance_data, &u_prop_val);
            u_out_val = u_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "debug_level", DBUS_TYPE_UINT32, &u_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "enabled");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        b_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (b_handler) {
            (b_handler)(dbus_req, dbus_req->intf->instance_data, &b_prop_val);
            b_out_val = b_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "enabled", DBUS_TYPE_BOOLEAN, &b_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "type");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        s_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (s_handler) {
            (s_handler)(dbus_req, dbus_req->intf->instance_data, &s_prop_val);
            s_out_val = s_prop_val == NULL ? "" : s_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "type", DBUS_TYPE_STRING, &s_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "providers");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        as_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (as_handler) {
            (as_handler)(dbus_req, dbus_req->intf->instance_data, &as_prop_val, &as_prop_len);
            as_out_val = as_prop_val;
            ret = sbus_add_array_as_variant_to_dict(&iter_dict, "providers", DBUS_TYPE_STRING, (uint8_t*)as_out_val, as_prop_len, sizeof(const char *));
            if (ret != EOK) return ret;
        }
    }

    dbret = dbus_message_iter_close_container(&iter, &iter_dict);
    if (!dbret) return ENOMEM;

    return sbus_request_finish(dbus_req, reply);
}

/* property info for org.freedesktop.sssd.infopipe.Components */
const struct sbus_property_meta infopipe_component__properties[] = {
    {
        "name", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_component, infopipe_component_get_name),
        invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "debug_level", /* name */
        "u", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_component, infopipe_component_get_debug_level),
        invoke_get_u,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "enabled", /* name */
        "b", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_component, infopipe_component_get_enabled),
        invoke_get_b,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "type", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_component, infopipe_component_get_type),
        invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "providers", /* name */
        "as", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_component, infopipe_component_get_providers),
        invoke_get_as,
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
    invoke_infopipe_component_get_all, /* GetAll invoker */
};

/* invokes GetAll for the 'org.freedesktop.sssd.infopipe.Domains' interface */
static int invoke_infopipe_domain_get_all(struct sbus_request *dbus_req, void *function_ptr)
{
    struct sbus_interface *intf = dbus_req->intf;
    const struct sbus_property_meta *property;
    DBusMessage *reply;
    dbus_bool_t dbret;
    DBusMessageIter iter;
    DBusMessageIter iter_dict;
    int ret;
    const char * s_prop_val;
    const char * s_out_val;
    void (*s_handler)(struct sbus_request *, void *data, const char * *);
    bool b_prop_val;
    dbus_bool_t b_out_val;
    void (*b_handler)(struct sbus_request *, void *data, bool *);
    uint32_t u_prop_val;
    uint32_t u_out_val;
    void (*u_handler)(struct sbus_request *, void *data, uint32_t *);
    const char * *as_prop_val;
    int as_prop_len;
    const char * *as_out_val;
    void (*as_handler)(struct sbus_request *, void *data, const char * * *, int *);
    const char * o_prop_val;
    const char * o_out_val;
    void (*o_handler)(struct sbus_request *, void *data, const char * *);

    reply = dbus_message_new_method_return(dbus_req->message);
    if (!reply) return ENOMEM;
    dbus_message_iter_init_append(reply, &iter);
    dbret = dbus_message_iter_open_container(
                                     &iter, DBUS_TYPE_ARRAY,
                                     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                     DBUS_TYPE_STRING_AS_STRING
                                     DBUS_TYPE_VARIANT_AS_STRING
                                     DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                     &iter_dict);
    if (!dbret) return ENOMEM;

    property = sbus_meta_find_property(intf->vtable->meta, "name");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        s_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (s_handler) {
            (s_handler)(dbus_req, dbus_req->intf->instance_data, &s_prop_val);
            s_out_val = s_prop_val == NULL ? "" : s_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "name", DBUS_TYPE_STRING, &s_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "provider");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        s_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (s_handler) {
            (s_handler)(dbus_req, dbus_req->intf->instance_data, &s_prop_val);
            s_out_val = s_prop_val == NULL ? "" : s_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "provider", DBUS_TYPE_STRING, &s_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "primary_servers");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        as_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (as_handler) {
            (as_handler)(dbus_req, dbus_req->intf->instance_data, &as_prop_val, &as_prop_len);
            as_out_val = as_prop_val;
            ret = sbus_add_array_as_variant_to_dict(&iter_dict, "primary_servers", DBUS_TYPE_STRING, (uint8_t*)as_out_val, as_prop_len, sizeof(const char *));
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "backup_servers");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        as_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (as_handler) {
            (as_handler)(dbus_req, dbus_req->intf->instance_data, &as_prop_val, &as_prop_len);
            as_out_val = as_prop_val;
            ret = sbus_add_array_as_variant_to_dict(&iter_dict, "backup_servers", DBUS_TYPE_STRING, (uint8_t*)as_out_val, as_prop_len, sizeof(const char *));
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "min_id");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        u_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (u_handler) {
            (u_handler)(dbus_req, dbus_req->intf->instance_data, &u_prop_val);
            u_out_val = u_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "min_id", DBUS_TYPE_UINT32, &u_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "max_id");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        u_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (u_handler) {
            (u_handler)(dbus_req, dbus_req->intf->instance_data, &u_prop_val);
            u_out_val = u_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "max_id", DBUS_TYPE_UINT32, &u_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "realm");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        s_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (s_handler) {
            (s_handler)(dbus_req, dbus_req->intf->instance_data, &s_prop_val);
            s_out_val = s_prop_val == NULL ? "" : s_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "realm", DBUS_TYPE_STRING, &s_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "forest");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        s_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (s_handler) {
            (s_handler)(dbus_req, dbus_req->intf->instance_data, &s_prop_val);
            s_out_val = s_prop_val == NULL ? "" : s_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "forest", DBUS_TYPE_STRING, &s_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "login_format");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        s_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (s_handler) {
            (s_handler)(dbus_req, dbus_req->intf->instance_data, &s_prop_val);
            s_out_val = s_prop_val == NULL ? "" : s_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "login_format", DBUS_TYPE_STRING, &s_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "fully_qualified_name_format");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        s_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (s_handler) {
            (s_handler)(dbus_req, dbus_req->intf->instance_data, &s_prop_val);
            s_out_val = s_prop_val == NULL ? "" : s_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "fully_qualified_name_format", DBUS_TYPE_STRING, &s_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "enumerable");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        b_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (b_handler) {
            (b_handler)(dbus_req, dbus_req->intf->instance_data, &b_prop_val);
            b_out_val = b_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "enumerable", DBUS_TYPE_BOOLEAN, &b_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "use_fully_qualified_names");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        b_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (b_handler) {
            (b_handler)(dbus_req, dbus_req->intf->instance_data, &b_prop_val);
            b_out_val = b_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "use_fully_qualified_names", DBUS_TYPE_BOOLEAN, &b_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "subdomain");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        b_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (b_handler) {
            (b_handler)(dbus_req, dbus_req->intf->instance_data, &b_prop_val);
            b_out_val = b_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "subdomain", DBUS_TYPE_BOOLEAN, &b_out_val);
            if (ret != EOK) return ret;
        }
    }

    property = sbus_meta_find_property(intf->vtable->meta, "parent_domain");
    if (property != NULL && property->flags & SBUS_PROPERTY_READABLE) {
        o_handler = VTABLE_FUNC(intf->vtable, property->vtable_offset_get);
        if (o_handler) {
            (o_handler)(dbus_req, dbus_req->intf->instance_data, &o_prop_val);
            o_out_val = o_prop_val == NULL ? "/" : o_prop_val;
            ret = sbus_add_variant_to_dict(&iter_dict, "parent_domain", DBUS_TYPE_OBJECT_PATH, &o_out_val);
            if (ret != EOK) return ret;
        }
    }

    dbret = dbus_message_iter_close_container(&iter, &iter_dict);
    if (!dbret) return ENOMEM;

    return sbus_request_finish(dbus_req, reply);
}

/* property info for org.freedesktop.sssd.infopipe.Domains */
const struct sbus_property_meta infopipe_domain__properties[] = {
    {
        "name", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_name),
        invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "provider", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_provider),
        invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "primary_servers", /* name */
        "as", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_primary_servers),
        invoke_get_as,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "backup_servers", /* name */
        "as", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_backup_servers),
        invoke_get_as,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "min_id", /* name */
        "u", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_min_id),
        invoke_get_u,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "max_id", /* name */
        "u", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_max_id),
        invoke_get_u,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "realm", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_realm),
        invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "forest", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_forest),
        invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "login_format", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_login_format),
        invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "fully_qualified_name_format", /* name */
        "s", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_fully_qualified_name_format),
        invoke_get_s,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "enumerable", /* name */
        "b", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_enumerable),
        invoke_get_b,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "use_fully_qualified_names", /* name */
        "b", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_use_fully_qualified_names),
        invoke_get_b,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "subdomain", /* name */
        "b", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_subdomain),
        invoke_get_b,
        0, /* not writable */
        NULL, /* no invoker */
    },
    {
        "parent_domain", /* name */
        "o", /* type */
        SBUS_PROPERTY_READABLE,
        offsetof(struct infopipe_domain, infopipe_domain_get_parent_domain),
        invoke_get_o,
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
    invoke_infopipe_domain_get_all, /* GetAll invoker */
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

    return (handler)(dbus_req, dbus_req->intf->instance_data,
                     arg_0);
}

/* invokes a getter with a 'const char *' DBus type */
static int invoke_get_s(struct sbus_request *dbus_req, void *function_ptr)
{
    const char * prop_val;
    const char * out_val;

    void (*handler)(struct sbus_request *, void *data, const char * *) = function_ptr;

    (handler)(dbus_req, dbus_req->intf->instance_data, &prop_val);

    out_val = prop_val == NULL ? "" : prop_val;
    return sbus_request_return_as_variant(dbus_req, DBUS_TYPE_STRING, &out_val);
}

/* invokes a getter with a 'dbus_bool_t' DBus type */
static int invoke_get_b(struct sbus_request *dbus_req, void *function_ptr)
{
    bool prop_val;
    dbus_bool_t out_val;

    void (*handler)(struct sbus_request *, void *data, bool *) = function_ptr;

    (handler)(dbus_req, dbus_req->intf->instance_data, &prop_val);

    out_val = prop_val;
    return sbus_request_return_as_variant(dbus_req, DBUS_TYPE_BOOLEAN, &out_val);
}

/* invokes a getter with a 'uint32_t' DBus type */
static int invoke_get_u(struct sbus_request *dbus_req, void *function_ptr)
{
    uint32_t prop_val;
    uint32_t out_val;

    void (*handler)(struct sbus_request *, void *data, uint32_t *) = function_ptr;

    (handler)(dbus_req, dbus_req->intf->instance_data, &prop_val);

    out_val = prop_val;
    return sbus_request_return_as_variant(dbus_req, DBUS_TYPE_UINT32, &out_val);
}

/* invokes a getter with an array of 'const char *' DBus type */
static int invoke_get_as(struct sbus_request *dbus_req, void *function_ptr)
{
    const char * *prop_val;
    int prop_len;
    const char * *out_val;

    void (*handler)(struct sbus_request *, void *data, const char * * *, int *) = function_ptr;

    (handler)(dbus_req, dbus_req->intf->instance_data, &prop_val, &prop_len);

    out_val = prop_val;
    return sbus_request_return_array_as_variant(dbus_req, DBUS_TYPE_STRING, (uint8_t*)out_val, prop_len, sizeof(const char *));
}

/* invokes a getter with a 'const char *' DBus type */
static int invoke_get_o(struct sbus_request *dbus_req, void *function_ptr)
{
    const char * prop_val;
    const char * out_val;

    void (*handler)(struct sbus_request *, void *data, const char * *) = function_ptr;

    (handler)(dbus_req, dbus_req->intf->instance_data, &prop_val);

    out_val = prop_val == NULL ? "/" : prop_val;
    return sbus_request_return_as_variant(dbus_req, DBUS_TYPE_OBJECT_PATH, &out_val);
}
