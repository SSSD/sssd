/* The following definitions are auto-generated from data_provider_iface.xml */

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "data_provider_iface_generated.h"

/* methods for org.freedesktop.sssd.dataprovider */
const struct sbus_method_meta data_provider_iface__methods[] = {
    {
        "RegisterService", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, RegisterService),
        NULL, /* no invoker */
    },
    {
        "pamHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, pamHandler),
        NULL, /* no invoker */
    },
    {
        "sudoHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, sudoHandler),
        NULL, /* no invoker */
    },
    {
        "autofsHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, autofsHandler),
        NULL, /* no invoker */
    },
    {
        "hostHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, hostHandler),
        NULL, /* no invoker */
    },
    {
        "getDomains", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, getDomains),
        NULL, /* no invoker */
    },
    {
        "getAccountInfo", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_iface, getAccountInfo),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* invokes GetAll for the 'org.freedesktop.sssd.dataprovider' interface */
static int invoke_data_provider_iface_get_all(struct sbus_request *dbus_req, void *function_ptr)
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

/* interface info for org.freedesktop.sssd.dataprovider */
const struct sbus_interface_meta data_provider_iface_meta = {
    "org.freedesktop.sssd.dataprovider", /* name */
    data_provider_iface__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    invoke_data_provider_iface_get_all, /* GetAll invoker */
};

/* methods for org.freedesktop.sssd.dataprovider_rev */
const struct sbus_method_meta data_provider_rev_iface__methods[] = {
    {
        "updateCache", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_rev_iface, updateCache),
        NULL, /* no invoker */
    },
    {
        "initgrCheck", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct data_provider_rev_iface, initgrCheck),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* invokes GetAll for the 'org.freedesktop.sssd.dataprovider_rev' interface */
static int invoke_data_provider_rev_iface_get_all(struct sbus_request *dbus_req, void *function_ptr)
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

/* interface info for org.freedesktop.sssd.dataprovider_rev */
const struct sbus_interface_meta data_provider_rev_iface_meta = {
    "org.freedesktop.sssd.dataprovider_rev", /* name */
    data_provider_rev_iface__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    invoke_data_provider_rev_iface_get_all, /* GetAll invoker */
};
