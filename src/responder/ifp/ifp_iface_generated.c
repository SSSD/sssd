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
