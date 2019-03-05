/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include <errno.h>
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sbus_errors.h"
#include "sbus/sbus_message.h"
#include "sbus/sbus_sync_private.h"
#include "sbus/interface/sbus_iterator_writers.h"

/* Data slot that is used for message data. The slot is shared for all
 * messages, i.e. when a data slot is allocated all messages have the
 * slot available. */
dbus_int32_t global_data_slot = -1;

struct sbus_talloc_msg {
    DBusMessage *msg;
    bool in_talloc_destructor;
};

static int sbus_talloc_msg_destructor(struct sbus_talloc_msg *talloc_msg)
{
    talloc_msg->in_talloc_destructor = true;

    if (talloc_msg->msg == NULL) {
        return 0;
    }

    /* There may exist more references to this message but this talloc
     * context is no longer valid. We remove dbus message data to invoke
     * dbus destructor now. */
    dbus_message_set_data(talloc_msg->msg, global_data_slot, NULL, NULL);
    dbus_message_unref(talloc_msg->msg);
    return 0;
}

static void sbus_msg_data_destructor(void *ctx)
{
    struct sbus_talloc_msg *talloc_msg;

    talloc_msg = talloc_get_type(ctx, struct sbus_talloc_msg);

    /* Decrement ref counter on data slot. */
    dbus_message_free_data_slot(&global_data_slot);

    if (!talloc_msg->in_talloc_destructor) {
        /* References to this message dropped to zero but through
         * dbus_message_unref(), not by calling talloc_free(). We need to free
         * the talloc context and avoid running talloc destructor. */
        talloc_set_destructor(talloc_msg, NULL);
        talloc_free(talloc_msg);
    }
}

errno_t
sbus_message_bound(TALLOC_CTX *mem_ctx, DBusMessage *msg)
{
    struct sbus_talloc_msg *talloc_msg;
    DBusFreeFunction free_fn;
    dbus_bool_t bret;

    if (mem_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Warning: bounding to NULL context!\n");
        return EINVAL;
    }

    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Message can not be NULL!\n");
        return EINVAL;
    }

    /* Create a talloc context that will unreference this message when
     * the parent context is freed. */
    talloc_msg = talloc(mem_ctx, struct sbus_talloc_msg);
    if (talloc_msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to bound D-Bus message with talloc context!\n");
        return ENOMEM;
    }

    /* Allocate a dbus message data slot that will contain pointer to the
     * talloc context so we can pick up cases when the dbus message is
     * freed through dbus api. */

    bret = dbus_message_allocate_data_slot(&global_data_slot);
    if (!bret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to allocate data slot!\n");
        talloc_free(talloc_msg);
        return ENOMEM;
    }

    free_fn = sbus_msg_data_destructor;
    bret = dbus_message_set_data(msg, global_data_slot, talloc_msg, free_fn);
    if (!bret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set message data!\n");
        talloc_free(talloc_msg);
        dbus_message_free_data_slot(&global_data_slot);
        return ENOMEM;
    }

    talloc_msg->msg = msg;
    talloc_msg->in_talloc_destructor = false;

    talloc_set_destructor(talloc_msg, sbus_talloc_msg_destructor);

    return EOK;
}

errno_t
sbus_message_bound_steal(TALLOC_CTX *mem_ctx, DBusMessage *msg)
{
    struct sbus_talloc_msg *talloc_msg;
    void *data;

    if (mem_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Warning: bounding to NULL context!\n");
        return EINVAL;
    }

    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Message can not be NULL!\n");
        return EINVAL;
    }

    if (global_data_slot < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "This message is not talloc-bound! "
              "(data slot < 0)\n");
        return ERR_INTERNAL;
    }

    data = dbus_message_get_data(msg, global_data_slot);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "This message is not talloc-bound! "
              "(returned data is NULL)\n");
        return ERR_INTERNAL;
    }

    talloc_msg = talloc_get_type(data, struct sbus_talloc_msg);
    if (talloc_msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "This message is not talloc-bound! "
              "(invalid data)\n");
        return ERR_INTERNAL;
    }

    talloc_steal(mem_ctx, talloc_msg);

    return EOK;
}

DBusMessage *
sbus_method_create_empty(TALLOC_CTX *mem_ctx,
                         const char *bus,
                         const char *path,
                         const char *iface,
                         const char *method)
{
    DBusMessage *msg;
    errno_t ret;

    msg = dbus_message_new_method_call(bus, path, iface, method);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create message\n");
        return NULL;
    }

    if (mem_ctx != NULL) {
        ret = sbus_message_bound(mem_ctx, msg);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unable to bound message with talloc context!\n");
            dbus_message_unref(msg);
            return NULL;
        }
    }

    return msg;
}

static DBusMessage *
sbus_method_create_valist(TALLOC_CTX *mem_ctx,
                          const char *bus,
                          const char *path,
                          const char *iface,
                          const char *method,
                          int first_arg_type,
                          va_list va)
{
    DBusMessage *msg;
    dbus_bool_t bret;

    msg = sbus_method_create_empty(mem_ctx, bus, path, iface, method);
    if (msg == NULL) {
        return NULL;
    }

    bret = dbus_message_append_args_valist(msg, first_arg_type, va);
    if (!bret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build message\n");
        dbus_message_unref(msg);
        return NULL;
    }

    return msg;
}

DBusMessage *
_sbus_method_create(TALLOC_CTX *mem_ctx,
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
    msg = sbus_method_create_valist(mem_ctx, bus, path, iface, method,
                                    first_arg_type, va);
    va_end(va);

    return msg;
}

DBusMessage *
sbus_signal_create_empty(TALLOC_CTX *mem_ctx,
                         const char *path,
                         const char *iface,
                         const char *signame)
{
    DBusMessage *msg;
    errno_t ret;

    msg = dbus_message_new_signal(path, iface, signame);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create message\n");
        return NULL;
    }

    if (mem_ctx != NULL) {
        ret = sbus_message_bound(mem_ctx, msg);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unable to bound message with talloc context!\n");
            dbus_message_unref(msg);
            return NULL;
        }
    }

    return msg;
}

static DBusMessage *
sbus_signal_create_valist(TALLOC_CTX *mem_ctx,
                          const char *path,
                          const char *iface,
                          const char *signame,
                          int first_arg_type,
                          va_list va)
{
    DBusMessage *msg;
    dbus_bool_t bret;

    msg = sbus_signal_create_empty(mem_ctx, path, iface, signame);
    if (msg == NULL) {
        return NULL;
    }

    bret = dbus_message_append_args_valist(msg, first_arg_type, va);
    if (!bret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build message\n");
        dbus_message_unref(msg);
        return NULL;
    }

    return msg;
}

DBusMessage *
_sbus_signal_create(TALLOC_CTX *mem_ctx,
                    const char *path,
                    const char *iface,
                    const char *method,
                    int first_arg_type,
                    ...)
{
    DBusMessage *msg;
    va_list va;

    va_start(va, first_arg_type);
    msg = sbus_signal_create_valist(mem_ctx, path, iface, method,
                                    first_arg_type, va);
    va_end(va);

    return msg;
}

static errno_t
sbus_message_parse_valist(DBusMessage *msg,
                          int first_arg_type,
                          va_list va)
{
    DBusError error;
    dbus_bool_t bret;
    errno_t ret;

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

errno_t
_sbus_reply_parse(DBusMessage *msg,
                  int first_arg_type,
                  ...)
{
    errno_t ret;
    va_list va;

    ret = sbus_reply_check(msg);
    if (ret != EOK) {
        return ret;
    }

    va_start(va, first_arg_type);
    ret = sbus_message_parse_valist(msg, first_arg_type, va);
    va_end(va);

    return ret;
}

errno_t
sbus_reply_check(DBusMessage *reply)
{
    dbus_bool_t bret;
    DBusError error;
    errno_t ret;
    int type;

    dbus_error_init(&error);

    type = dbus_message_get_type(reply);
    switch (type) {
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

        DEBUG(SSSDBG_TRACE_ALL, "D-Bus error [%s]: %s\n", error.name,
              (error.message == NULL ? "<no-message>" : error.message));
        ret = sbus_error_to_errno(&error);
        goto done;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected D-Bus message type [%d]\n",
              type);
        ret = ERR_INTERNAL;
        goto done;
    }

done:
    dbus_error_free(&error);

    return ret;
}

errno_t
sbus_write_input(DBusMessage *msg,
                 sbus_invoker_writer_fn writer,
                 void *input)
{
    DBusMessageIter write_iterator;
    errno_t ret;

    if (writer == NULL) {
        return EOK;
    }

    dbus_message_iter_init_append(msg, &write_iterator);

    ret = writer(&write_iterator, input);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to write message data [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return ret;
}

errno_t
sbus_read_output(TALLOC_CTX *mem_ctx,
                 DBusMessage *msg,
                 sbus_invoker_reader_fn reader,
                 void *output)
{
    DBusMessageIter read_iterator;
    errno_t ret;

    if (reader == NULL) {
        return EOK;
    }

    dbus_message_iter_init(msg, &read_iterator);

    ret = reader(mem_ctx, &read_iterator, output);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read message data [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return ret;
}

DBusMessage *
sbus_create_method_call(TALLOC_CTX *mem_ctx,
                        DBusMessage *raw_message,
                        sbus_invoker_writer_fn writer,
                        const char *bus,
                        const char *path,
                        const char *iface,
                        const char *method,
                        void *input)
{
    DBusMessage *msg;
    errno_t ret;

    if (raw_message != NULL) {
        return raw_message;
    }

    msg = sbus_method_create_empty(mem_ctx, bus, path, iface, method);
    if (msg == NULL) {
        return NULL;
    }

    ret = sbus_write_input(msg, writer, input);
    if (ret != EOK)  {
        dbus_message_unref(msg);
        return NULL;
    }

    return msg;
}

DBusMessage *
sbus_create_signal_call(TALLOC_CTX *mem_ctx,
                        DBusMessage *raw_message,
                        sbus_invoker_writer_fn writer,
                        const char *path,
                        const char *iface,
                        const char *signal_name,
                        void *input)
{
    DBusMessage *msg;
    errno_t ret;

    if (raw_message != NULL) {
        return raw_message;
    }

    msg = sbus_signal_create_empty(mem_ctx, path, iface, signal_name);
    if (msg == NULL) {
        return NULL;
    }

    ret = sbus_write_input(msg, writer, input);
    if (ret != EOK)  {
        dbus_message_unref(msg);
        return NULL;
    }

    return msg;
}

DBusMessage *
sbus_create_set_call(TALLOC_CTX *mem_ctx,
                     sbus_invoker_writer_fn writer,
                     const char *bus,
                     const char *path,
                     const char *iface,
                     const char *property,
                     const char *type,
                     void *input)
{
    DBusMessageIter iter;
    DBusMessageIter variant;
    DBusMessage *msg;
    dbus_bool_t dbret;
    errno_t ret;

    if (writer == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: writer cannot be NULL\n");
        return NULL;
    }

    msg = sbus_method_create_empty(mem_ctx, bus, path,
                                   DBUS_INTERFACE_PROPERTIES, "Set");
    if (msg == NULL) {
        return NULL;
    }

    dbus_message_iter_init_append(msg, &iter);

    ret = sbus_iterator_write_s(&iter, iface);
    if (ret != EOK) {
        dbus_message_unref(msg);
        return NULL;
    }

    ret = sbus_iterator_write_s(&iter, property);
    if (ret != EOK) {
        dbus_message_unref(msg);
        return NULL;
    }

    dbret = dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
                                             type, &variant);
    if (!dbret) {
        dbus_message_unref(msg);
        return NULL;
    }

    ret = writer(&variant, input);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to write message data [%d]: %s\n",
              ret, sss_strerror(ret));
        dbus_message_iter_abandon_container(&iter, &variant);
        dbus_message_unref(msg);
        return NULL;
    }

    dbret = dbus_message_iter_close_container(&iter, &variant);
    if (!dbret) {
        dbus_message_iter_abandon_container(&iter, &variant);
        dbus_message_unref(msg);
        return NULL;
    }

    return msg;
}
