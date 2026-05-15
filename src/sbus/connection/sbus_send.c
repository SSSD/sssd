/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>
        Simo Sorce <ssorce@redhat.com>

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
#include <tevent.h>
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sbus_private.h"

static errno_t
sbus_pending_call_create(DBusConnection *conn,
                         DBusMessage *msg,
                         DBusPendingCallNotifyFunction notify_fn,
                         void *notify_data,
                         int timeout_ms,
                         DBusPendingCall **_pending_call)
{
    DBusPendingCall *pending;
    dbus_bool_t dbret;

    dbret = dbus_connection_send_with_reply(conn, msg, &pending, timeout_ms);
    if (!dbret) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to create pending call!\n");
        return ENOMEM;
    }

    if (pending == NULL) {
        /* Connection may have been disconnected. */
        return ERR_OFFLINE;
    }

    dbret = dbus_pending_call_set_notify(pending, notify_fn, notify_data, NULL);
    if (!dbret) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to setup callback for pending reply!\n");
        dbus_pending_call_cancel(pending);
        dbus_pending_call_unref(pending);
        return ENOMEM;
    }

    *_pending_call = pending;

    return EOK;
}

static errno_t
sbus_pending_call_process(DBusPendingCall *pending,
                          DBusMessage **_reply)
{
    DBusMessage *reply;
    DBusError error;
    errno_t ret;

    dbus_error_init(&error);

    reply = dbus_pending_call_steal_reply(pending);
    if (reply == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Severe error. A reply callback was "
              "called but no reply was received and no timeout occurred\n");
        ret = EFAULT;
        goto done;
    }

    ret = sbus_reply_check(reply);
    if (ret != EOK) {
        dbus_message_unref(reply);
        goto done;
    }

    *_reply = reply;

done:
    dbus_pending_call_unref(pending);
    dbus_error_free(&error);

    return ret;
}

struct sbus_message_state {
    DBusPendingCall *pending;
    DBusMessage *reply;
};

static int sbus_message_destructor(struct sbus_message_state *state)
{
    if (state->pending == NULL) {
        return 0;
    }

    /* This request was interrupted before the pending call has finished. */
    dbus_pending_call_cancel(state->pending);
    dbus_pending_call_unref(state->pending);
    state->pending = NULL;

    return 0;
}

static void sbus_message_done(DBusPendingCall *pending,
                              void *pvt);

struct tevent_req *
sbus_message_send(TALLOC_CTX *mem_ctx,
                  struct sbus_connection *conn,
                  DBusMessage *msg,
                  int timeout_ms)
{
    struct sbus_message_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sbus_message_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    if (conn->disconnecting) {
        ret = ERR_TERMINATED;
        goto done;
    }

    ret = sbus_pending_call_create(conn->connection, msg, sbus_message_done,
                                   req, timeout_ms, &state->pending);
    if (ret != EOK) {
        goto done;
    }

    talloc_set_destructor(state, sbus_message_destructor);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, conn->ev);
    }

    return req;
}

static void
sbus_message_done(DBusPendingCall *pending,
                  void *pvt)
{
    struct sbus_message_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = talloc_get_type(pvt, struct tevent_req);
    state = tevent_req_data(req, struct sbus_message_state);

    /* The pending call has finished. Remove the destructor. */
    state->pending = NULL;
    talloc_set_destructor(state, NULL);

    ret = sbus_pending_call_process(pending, &state->reply);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
sbus_message_recv(TALLOC_CTX *mem_ctx,
                  struct tevent_req *req,
                  DBusMessage **_reply)
{
    struct sbus_message_state *state;
    errno_t ret;

    state = tevent_req_data(req, struct sbus_message_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    ret = sbus_message_bound(mem_ctx, state->reply);
    if (ret != EOK) {
        return ret;
    }

    *_reply = state->reply;

    return EOK;
}

void sbus_reply(struct sbus_connection *conn,
                DBusMessage *reply)
{
    if (conn->disconnecting) {
        dbus_message_unref(reply);
        return;
    }

    dbus_connection_send(conn->connection, reply, NULL);
    dbus_message_unref(reply);
}

void sbus_reply_error(struct sbus_connection *conn,
                      DBusMessage *reply_to,
                      const char *error_name,
                      const char *error_message)
{
    DBusMessage *reply;

    /* We can|t really send reply to a signal. */
    if (dbus_message_get_type(reply_to) == DBUS_MESSAGE_TYPE_SIGNAL) {
        return;
    }

    reply = dbus_message_new_error(reply_to, error_name, error_message);
    if (reply == NULL) {
        /* There is really nothing we can do. */
        return;
    }

    sbus_reply(conn, reply);
}

void sbus_emit_signal(struct sbus_connection *conn,
                      DBusMessage *msg)
{
    sbus_reply(conn, msg);
}
