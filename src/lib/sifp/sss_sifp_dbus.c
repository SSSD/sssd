/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include <dbus/dbus.h>
#include <stdlib.h>
#include <string.h>

#include "lib/sifp/sss_sifp.h"
#include "lib/sifp/sss_sifp_dbus.h"
#include "lib/sifp/sss_sifp_private.h"

static sss_sifp_error sss_sifp_ifp_call(sss_sifp_ctx *ctx,
                                        const char *method,
                                        int first_arg_type,
                                        va_list ap,
                                        DBusMessage **_reply)
{
   DBusMessage *msg = NULL;
   sss_sifp_error ret;

   msg = sss_sifp_create_message(SSS_SIFP_PATH_IFP, SSS_SIFP_IFACE_IFP, method);
   if (msg == NULL) {
       ret = SSS_SIFP_OUT_OF_MEMORY;
       goto done;
   }

   if (first_arg_type != DBUS_TYPE_INVALID) {
       dbus_message_append_args_valist(msg, first_arg_type, ap);
   }

   ret = sss_sifp_send_message(ctx, msg, _reply);

done:
   if (msg != NULL) {
       dbus_message_unref(msg);
   }

   return ret;
}

DBusMessage *
sss_sifp_create_message(const char *object_path,
                        const char *interface,
                        const char *method)
{
    return dbus_message_new_method_call(SSS_SIFP_IFP, object_path,
                                        interface, method);
}

sss_sifp_error
sss_sifp_send_message(sss_sifp_ctx *ctx,
                      DBusMessage *msg,
                      DBusMessage **_reply)
{
    return sss_sifp_send_message_ex(ctx, msg, 5000, _reply);
}

sss_sifp_error
sss_sifp_send_message_ex(sss_sifp_ctx *ctx,
                         DBusMessage *msg,
                         int timeout,
                         DBusMessage **_reply)
{
    DBusMessage *reply = NULL;
    DBusError dbus_error;
    sss_sifp_error ret;

    if (ctx == NULL || msg == NULL) {
        return SSS_SIFP_INVALID_ARGUMENT;
    }

    dbus_error_init(&dbus_error);

    reply = dbus_connection_send_with_reply_and_block(ctx->conn, msg,
                                                      timeout, &dbus_error);
    if (dbus_error_is_set(&dbus_error)) {
        sss_sifp_set_io_error(ctx, &dbus_error);
        ret = SSS_SIFP_IO_ERROR;
        goto done;
    }

    if (_reply == NULL) {
        dbus_message_unref(reply);
    } else {
        *_reply = reply;
    }

    ret = SSS_SIFP_OK;

done:
    dbus_error_free(&dbus_error);
    return ret;
}

sss_sifp_error
sss_sifp_invoke_list(sss_sifp_ctx *ctx,
                     const char *method,
                     char ***_object_paths,
                     int first_arg_type,
                     ...)
{
    DBusMessage *reply = NULL;
    char *dbus_method = NULL;
    sss_sifp_error ret;
    va_list ap;

    if (ctx == NULL || method == NULL || _object_paths == NULL) {
        return SSS_SIFP_INVALID_ARGUMENT;
    }

    dbus_method = sss_sifp_strcat(ctx, "List", method);
    if (dbus_method == NULL) {
        ret = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    va_start(ap, first_arg_type);
    ret = sss_sifp_ifp_call(ctx, dbus_method, first_arg_type, ap, &reply);
    va_end(ap);
    if (ret != SSS_SIFP_OK) {
        goto done;
    }

    ret = sss_sifp_parse_object_path_list(ctx, reply, _object_paths);

done:
    sss_sifp_free_string(ctx, &dbus_method);

    if (reply != NULL) {
        dbus_message_unref(reply);
    }

    return ret;
}

sss_sifp_error
sss_sifp_invoke_find(sss_sifp_ctx *ctx,
                     const char *method,
                     char **_object_path,
                     int first_arg_type,
                     ...)
{
   DBusMessage *reply = NULL;
   char *dbus_method = NULL;
   sss_sifp_error ret;
   va_list ap;

   if (ctx == NULL || method == NULL || _object_path == NULL) {
       return SSS_SIFP_INVALID_ARGUMENT;
   }

   dbus_method = sss_sifp_strcat(ctx, "Find", method);
   if (dbus_method == NULL) {
       ret = SSS_SIFP_OUT_OF_MEMORY;
       goto done;
   }

   va_start(ap, first_arg_type);
   ret = sss_sifp_ifp_call(ctx, dbus_method, first_arg_type, ap, &reply);
   va_end(ap);
   if (ret != SSS_SIFP_OK) {
       goto done;
   }

   ret = sss_sifp_parse_object_path(ctx, reply, _object_path);

done:
    sss_sifp_free_string(ctx, &dbus_method);

   if (reply != NULL) {
       dbus_message_unref(reply);
   }

   return ret;
}
