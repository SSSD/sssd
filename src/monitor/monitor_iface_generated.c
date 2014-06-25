/* The following definitions are auto-generated from monitor_iface.xml */

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "monitor_iface_generated.h"

/* methods for org.freedesktop.sssd.monitor */
const struct sbus_method_meta mon_srv_iface__methods[] = {
    {
        "getVersion", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_srv_iface, getVersion),
        NULL, /* no invoker */
    },
    {
        "RegisterService", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_srv_iface, RegisterService),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* invokes GetAll for the 'org.freedesktop.sssd.monitor' interface */
static int invoke_mon_srv_iface_get_all(struct sbus_request *dbus_req, void *function_ptr)
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

/* interface info for org.freedesktop.sssd.monitor */
const struct sbus_interface_meta mon_srv_iface_meta = {
    "org.freedesktop.sssd.monitor", /* name */
    mon_srv_iface__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    invoke_mon_srv_iface_get_all, /* GetAll invoker */
};

/* methods for org.freedesktop.sssd.service */
const struct sbus_method_meta mon_cli_iface__methods[] = {
    {
        "ping", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, ping),
        NULL, /* no invoker */
    },
    {
        "resInit", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, resInit),
        NULL, /* no invoker */
    },
    {
        "shutDown", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, shutDown),
        NULL, /* no invoker */
    },
    {
        "goOffline", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, goOffline),
        NULL, /* no invoker */
    },
    {
        "resetOffline", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, resetOffline),
        NULL, /* no invoker */
    },
    {
        "rotateLogs", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, rotateLogs),
        NULL, /* no invoker */
    },
    {
        "clearMemcache", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, clearMemcache),
        NULL, /* no invoker */
    },
    {
        "clearEnumCache", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, clearEnumCache),
        NULL, /* no invoker */
    },
    {
        "sysbusReconnect", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct mon_cli_iface, sysbusReconnect),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* invokes GetAll for the 'org.freedesktop.sssd.service' interface */
static int invoke_mon_cli_iface_get_all(struct sbus_request *dbus_req, void *function_ptr)
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

/* interface info for org.freedesktop.sssd.service */
const struct sbus_interface_meta mon_cli_iface_meta = {
    "org.freedesktop.sssd.service", /* name */
    mon_cli_iface__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    invoke_mon_cli_iface_get_all, /* GetAll invoker */
};
