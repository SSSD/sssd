/*
    Authors:
        Stef Walter <stefw@redhat.com>

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

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_private.h"

#include <sys/time.h>
#include <dbus/dbus.h>

static const DBusError error_internal = { DBUS_ERROR_FAILED, "Internal Error" };

static int sbus_request_destructor(struct sbus_request *dbus_req)
{
    dbus_message_unref(dbus_req->message);
    return 0;
}

struct sbus_request *
sbus_new_request(struct sbus_connection *conn,
                 struct sbus_interface *intf,
                 DBusMessage *message)
{
    struct sbus_request *dbus_req;

    dbus_req = talloc_zero(conn, struct sbus_request);
    if (!dbus_req) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory allocating DBus request\n");
        return NULL;
    }

    dbus_req->intf = intf;
    dbus_req->conn = conn;
    dbus_req->message = dbus_message_ref(message);
    talloc_set_destructor(dbus_req, sbus_request_destructor);

    return dbus_req;
}

void
sbus_request_invoke_or_finish(struct sbus_request *dbus_req,
                              sbus_msg_handler_fn handler_fn,
                              void *handler_data,
                              sbus_method_invoker_fn invoker_fn)
{
    int ret;

    if (invoker_fn) {
        ret = invoker_fn(dbus_req, handler_fn);
    } else {
        ret = handler_fn(dbus_req, handler_data);
    }

    switch(ret) {
    case EOK:
        return;
    case ENOMEM:
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory handling DBus message\n");
        sbus_request_finish(dbus_req, NULL);
        break;
    default:
        sbus_request_fail_and_finish(dbus_req, &error_internal);
        break;
    }
}

int sbus_request_finish(struct sbus_request *dbus_req,
                        DBusMessage *reply)
{
    if (reply) {
        sbus_conn_send_reply(dbus_req->conn, reply);
    }
    return talloc_free(dbus_req);
}

int sbus_request_return_and_finish(struct sbus_request *dbus_req,
                                   int first_arg_type,
                                   ...)
{
    DBusMessage *reply;
    dbus_bool_t dbret;
    va_list va;
    int ret;

    reply = dbus_message_new_method_return(dbus_req->message);
    if (!reply) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory allocating DBus message\n");
        sbus_request_finish(dbus_req, NULL);
        return ENOMEM;
    }

    va_start(va, first_arg_type);
    dbret = dbus_message_append_args_valist(reply, first_arg_type, va);
    va_end(va);

    if (dbret) {
        ret = sbus_request_finish(dbus_req, reply);

    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Couldn't build DBus message\n");
        sbus_request_finish(dbus_req, NULL);
        ret = EINVAL;
    }

    dbus_message_unref(reply);
    return ret;
}

int sbus_request_fail_and_finish(struct sbus_request *dbus_req,
                                 const DBusError *error)
{
    DBusMessage *reply;
    int ret;

    reply = dbus_message_new_error(dbus_req->message, error->name, error->message);
    if (!reply) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory allocating DBus message\n");
        sbus_request_finish(dbus_req, NULL);
        return ENOMEM;
    }

    ret = sbus_request_finish(dbus_req, reply);
    dbus_message_unref(reply);
    return ret;
}

struct array_arg {
    char **dbus_array;
};

static int array_arg_destructor(struct array_arg *arg)
{
    dbus_free_string_array(arg->dbus_array);
    return 0;
}

static bool
parent_dbus_string_arrays(struct sbus_request *request, int first_arg_type,
                          va_list va)
{
    struct array_arg *array_arg;
    int arg_type;
    void **arg_ptr;

    /*
     * Here we iterate through the entire thing again and look for
     * things we need to fix allocation for. Normally certain types
     * returned from dbus_message_get_args() and friends require
     * later freeing. We tie those to the talloc context here.
     *
     * The list of argument has already been validated by the previous
     * dbus_message_get_args() call, so we can be cheap.
     */

    arg_type = first_arg_type;
    while (arg_type != DBUS_TYPE_INVALID) {

        if (arg_type == DBUS_TYPE_ARRAY) {
            arg_type = va_arg(va, int);     /* the array element type */
            arg_ptr = va_arg(va, void **);  /* the array elements */
            va_arg(va, int *);              /* the array length */

            /* Arrays of these things need to be freed */
            if (arg_type == DBUS_TYPE_STRING ||
                arg_type == DBUS_TYPE_OBJECT_PATH ||
                arg_type == DBUS_TYPE_SIGNATURE) {

                array_arg = talloc_zero(request, struct array_arg);
                if(array_arg == NULL) {
                    /* no kidding ... */
                    DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory while trying not to leak memory\n");
                    return false;
                }

                array_arg->dbus_array = *arg_ptr;
                talloc_set_destructor(array_arg, array_arg_destructor);
            }

        /* A non array argument */
        } else {
            arg_ptr = va_arg(va, void**);
        }

        /* The next type */
        arg_type = va_arg(va, int);
    }

    return true;
}

bool
sbus_request_parse_or_finish(struct sbus_request *request,
                             int first_arg_type,
                             ...)
{
    DBusError error = DBUS_ERROR_INIT;
    bool ret = true;
    va_list va2;
    va_list va;

    va_start(va, first_arg_type);
    va_copy(va2, va);

    if (dbus_message_get_args_valist(request->message, &error,
                                     first_arg_type, va)) {
        ret = parent_dbus_string_arrays (request, first_arg_type, va2);

    } else {
        /* Trying to send the error back to the caller in this case is a joke */
        if (!dbus_error_is_set(&error) || dbus_error_has_name(&error, DBUS_ERROR_NO_MEMORY)) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory parsing DBus message\n");
            sbus_request_finish(request, NULL);

        /* Log other errors and send them back, this include o.f.d.InvalidArgs */
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "Couldn't parse DBus message %s.%s: %s\n",
                  dbus_message_get_interface(request->message),
                  dbus_message_get_member(request->message),
                  error.message);
            sbus_request_fail_and_finish(request, &error);
        }

        dbus_error_free(&error);
        ret = false;
    }

    va_end(va2);
    va_end(va);

    return ret;
}
