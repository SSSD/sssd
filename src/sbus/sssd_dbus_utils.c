/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <talloc.h>

#include "sbus/sssd_dbus.h"
#include "util/util.h"

struct sbus_talloc_msg {
    DBusMessage *msg;
};

static int sbus_talloc_msg_destructor(struct sbus_talloc_msg *talloc_msg)
{
    if (talloc_msg->msg == NULL) {
        return 0;
    }

    dbus_message_unref(talloc_msg->msg);
    return 0;
}

errno_t sbus_talloc_bound_message(TALLOC_CTX *mem_ctx, DBusMessage *msg)
{
    struct sbus_talloc_msg *talloc_msg;

    talloc_msg = talloc(mem_ctx, struct sbus_talloc_msg);
    if (talloc_msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to bound D-Bus message with talloc context!\n");
        return ENOMEM;
    }

    talloc_msg->msg = msg;

    talloc_set_destructor(talloc_msg, sbus_talloc_msg_destructor);

    return EOK;
}

errno_t sbus_error_to_errno(DBusError *error)
{
    static struct {
        const char *name;
        errno_t ret;
    } list[] = { { SBUS_ERROR_INTERNAL, ERR_INTERNAL },
                 { SBUS_ERROR_NOT_FOUND, ENOENT },
                 { SBUS_ERROR_UNKNOWN_DOMAIN, ERR_DOMAIN_NOT_FOUND },
                 { SBUS_ERROR_DP_FATAL, ERR_TERMINATED },
                 { SBUS_ERROR_DP_OFFLINE, ERR_OFFLINE },
                 { SBUS_ERROR_DP_NOTSUP, ENOTSUP },
                 { NULL, ERR_INTERNAL } };
    int i;

    if (!dbus_error_is_set(error)) {
        return EOK;
    }

    for (i = 0; list[i].name != NULL; i++) {
        if (dbus_error_has_name(error, list[i].name)) {
            return list[i].ret;
        }
    }

    return EIO;
}

errno_t sbus_check_reply(DBusMessage *reply)
{
    dbus_bool_t bret;
    DBusError error;
    errno_t ret;

    dbus_error_init(&error);

    switch (dbus_message_get_type(reply)) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        ret = EOK;
        goto done;

    case DBUS_MESSAGE_TYPE_ERROR:
        bret = dbus_set_error_from_message(&error, reply);
        if (bret == false) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read error from message\n");
            ret = EIO;
            goto done;
        }

        DEBUG(SSSDBG_CRIT_FAILURE, "D-Bus error [%s]: %s\n",
              error.name, (error.message == NULL ? "(null)" : error.message));
        ret = sbus_error_to_errno(&error);
        goto done;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected D-Bus message type?\n");
        ret = ERR_INTERNAL;
        goto done;
    }

done:
    dbus_error_free(&error);

    return ret;
}

DBusMessage *sbus_create_message_valist(TALLOC_CTX *mem_ctx,
                                        const char *bus,
                                        const char *path,
                                        const char *iface,
                                        const char *method,
                                        int first_arg_type,
                                        va_list va)
{
    DBusMessage *msg;
    dbus_bool_t bret;
    errno_t ret;

    msg = dbus_message_new_method_call(bus, path, iface, method);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create message\n");
        return NULL;
    }

    bret = dbus_message_append_args_valist(msg, first_arg_type, va);
    if (!bret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build message\n");
        ret = EIO;
        goto done;
    }

    ret = sbus_talloc_bound_message(mem_ctx, msg);

done:
    if (ret != EOK) {
        dbus_message_unref(msg);
    }

    return msg;
}

DBusMessage *_sbus_create_message(TALLOC_CTX *mem_ctx,
                                  const char *bus,
                                  const char *path,
                                  const char *iface,
                                  const char *method,
                                  int first_arg_type,
                                  ...)
{
    DBusMessage *msg;
    va_list va;

    va_start(va, first_arg_type);
    msg = sbus_create_message_valist(mem_ctx, bus, path, iface, method,
                                     first_arg_type, va);
    va_end(va);

    return msg;
}

errno_t sbus_parse_message_valist(DBusMessage *msg,
                                  bool check_reply,
                                  int first_arg_type,
                                  va_list va)
{
    DBusError error;
    dbus_bool_t bret;
    errno_t ret;

    if (check_reply) {
        ret = sbus_check_reply(msg);
        if (ret != EOK) {
            return ret;
        }
    }

    dbus_error_init(&error);

    bret = dbus_message_get_args_valist(msg, &error, first_arg_type, va);
    if (bret == false) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse D-Bus message\n");
        ret = EIO;
        goto done;
    }

    ret = sbus_error_to_errno(&error);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse D-Bus message [%s]: %s\n",
              error.name, error.message);
        goto done;
    }

done:
    dbus_error_free(&error);
    return ret;
}

errno_t _sbus_parse_message(DBusMessage *msg,
                            bool check_reply,
                            int first_arg_type,
                            ...)
{
    errno_t ret;
    va_list va;

    va_start(va, first_arg_type);
    ret = sbus_parse_message_valist(msg, check_reply, first_arg_type, va);
    va_end(va);

    return ret;
}
