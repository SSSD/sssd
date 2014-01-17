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

#include <sys/time.h>
#include <dbus/dbus.h>

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
