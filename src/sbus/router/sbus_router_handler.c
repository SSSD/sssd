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

#include <string.h>
#include <talloc.h>
#include <tevent.h>
#include <sys/types.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/dlinklist.h"
#include "util/sss_chain_id.h"
#include "sbus/sbus_private.h"

struct sbus_message_meta {
    int type;
    const char *destination;
    const char *interface;
    const char *member;
    const char *sender;
    const char *path;
};

static void
sbus_message_meta_read(DBusMessage *message,
                       struct sbus_message_meta *meta)
{
    meta->type = dbus_message_get_type(message);
    meta->destination = dbus_message_get_destination(message);
    meta->interface = dbus_message_get_interface(message);
    meta->member = dbus_message_get_member(message);
    meta->sender = dbus_message_get_sender(message);
    meta->path = dbus_message_get_path(message);
}

struct sbus_issue_request_state {
    struct sbus_connection *conn;
    DBusMessageIter message_iter;
    DBusMessage *message;
    enum sbus_request_type type;
};

static void sbus_issue_request_done(struct tevent_req *subreq);

static errno_t
sbus_issue_request(TALLOC_CTX *mem_ctx,
                   struct sbus_message_meta *meta,
                   struct sbus_connection *conn,
                   DBusMessage *message,
                   enum sbus_request_type type,
                   const struct sbus_invoker *invoker,
                   const struct sbus_handler *handler)
{
    struct sbus_issue_request_state *state;
    struct sbus_request *request;
    struct tevent_req *subreq;
    errno_t ret;

    state = talloc_zero(mem_ctx, struct sbus_issue_request_state);
    if (state == NULL) {
        return ENOMEM;
    }

    state->conn = conn;
    state->message = dbus_message_ref(message);
    state->type = type;

    ret = sbus_message_bound(state, state->message);
    if (ret != EOK) {
        dbus_message_unref(state->message);
        goto done;
    }

    dbus_message_iter_init(message, &state->message_iter);

    request = sbus_request_create(state, conn, type, meta->destination,
                                  meta->interface, meta->member, meta->path);
    if (request == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create request data!\n");
        ret = ENOMEM;
        goto done;
    }

    subreq = sbus_incoming_request_send(state, conn->ev, conn, request,
                                        invoker, handler, meta->sender,
                                        &state->message_iter, message);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sbus_issue_request_done, state);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(state);
    }

    return ret;
}

static void sbus_issue_request_done(struct tevent_req *subreq)
{
    struct sbus_issue_request_state *state;
    struct sbus_message_meta meta;
    const char *error_name;
    const char *error_msg;
    uint64_t old_chain_id;
    DBusMessage *reply;
    errno_t ret;

    /* This is a top level request and a place where we loose tracking of the
     * correct chain id. We got here from sbus_incoming_request_done
     * which may finish multiple identical requests at once but we know chain
     * id only of the one requests that actually run its handler.
     *
     * Therefore we need to set the id to 0 since it is not known at this
     * moment, but it is ok. */
    old_chain_id = sss_chain_id_set(0);

    state = tevent_req_callback_data(subreq, struct sbus_issue_request_state);
    sbus_message_meta_read(state->message, &meta);

    ret = sbus_incoming_request_recv(state, subreq, &reply);
    talloc_zfree(subreq);

    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "%s.%s on %s from %s: Success\n",
              meta.interface, meta.member, meta.path, meta.sender);
    } else {
        int msg_level = SSSDBG_OP_FAILURE;
        if (ret == ERR_MISSING_DP_TARGET) msg_level = SSSDBG_FUNC_DATA;
        DEBUG(msg_level, "%s.%s: Error [%d]: %s\n",
              meta.interface, meta.member, ret, sss_strerror(ret));
    }

    /* Signals do not send a reply. */
    if (state->type == SBUS_REQUEST_SIGNAL) {
        goto done;
    }

    if (ret == EOK) {
        /* sbus_reply decreases the refcount of @reply. This usuall means that
         * refcount drops to zero and the message is freed. However, under
         * special circumstances the refcount is increased inside libdbus,
         * the refcount will be 1 when we leave the function and we drop it
         * to zero in talloc_free(state) later in this function. This will
         * leave an invalid message to be send inside dbus connection and
         * eventually crash.
         *
         * Increasing the refcount here makes sure that the refcount is always
         * correct. */
        dbus_message_ref(reply);
        sbus_reply(state->conn, reply);
    } else {
        sbus_errno_to_error(state, ret, &error_name, &error_msg);
        sbus_reply_error(state->conn, state->message, error_name, error_msg);
    }

done:
    if (ret == ERR_SBUS_KILL_CONNECTION) {
        DEBUG(SSSDBG_TRACE_FUNC, "Handler requested to kill the connection!\n");
        sbus_connection_free(state->conn);
    }

    talloc_free(state);

    sss_chain_id_set(old_chain_id);
}

DBusHandlerResult
sbus_method_handler(struct sbus_connection *conn,
                    struct sbus_router *router,
                    struct sbus_message_meta *meta,
                    DBusMessage *message)
{
    const struct sbus_method *method;
    struct sbus_interface *iface;
    TALLOC_CTX *error_ctx;
    const char *error_name;
    const char *error_msg;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Received D-Bus method %s.%s on %s from %s\n",
          meta->interface, meta->member, meta->path, meta->sender);

    /* Mark this connection as active. */
    sbus_connection_mark_active(conn);

    iface = sbus_router_paths_lookup(router->paths, meta->path,
                                     meta->interface);
    if (iface == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown interface!\n");
        sbus_reply_error(conn, message, DBUS_ERROR_UNKNOWN_INTERFACE,
                         meta->interface);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    method = sbus_interface_find_method(iface, meta->member);
    if (method == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown method!\n");
        sbus_reply_error(conn, message, DBUS_ERROR_UNKNOWN_METHOD,
                         meta->member);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    sbus_annotation_warn(iface, method);

    ret = sbus_issue_request(conn, meta, conn, message, SBUS_REQUEST_METHOD,
                             &method->invoker, &method->handler);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to issue request [%d]: %s\n",
              ret, sss_strerror(ret));
        if (ret == ENOMEM) {
            return DBUS_HANDLER_RESULT_NEED_MEMORY;
        }

        error_ctx = talloc_new(NULL);
        if (error_ctx == NULL) {
            return DBUS_HANDLER_RESULT_NEED_MEMORY;
        }

        sbus_errno_to_error(error_ctx, ret, &error_name, &error_msg);
        sbus_reply_error(conn, message, error_name, error_msg);
        talloc_free(error_ctx);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult
sbus_signal_handler(struct sbus_connection *conn,
                    struct sbus_router *router,
                    struct sbus_message_meta *meta,
                    DBusMessage *message)
{
    struct sbus_listener_list *list;
    struct sbus_listener_list *item;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Received D-Bus signal %s.%s on %s from %s\n",
          meta->interface, meta->member, meta->path, meta->sender);

    list = sbus_router_listeners_lookup(router->listeners, meta->interface,
                                        meta->member);
    if (list == NULL) {
        /* Most probably not fully initialized yet */
        DEBUG(SSSDBG_FUNC_DATA, "We do not listen to this signal!\n");
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    DLIST_FOR_EACH(item, list) {
        ret = sbus_issue_request(conn, meta, conn, message,
                                 SBUS_REQUEST_SIGNAL,
                                 &item->listener->invoker,
                                 &item->listener->handler);
        if (ret != EOK) {
            /* Nothing to do, try the next one. */
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to issue request [%d]: %s\n",
                  ret, sss_strerror(ret));
        }
    }

    return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult
sbus_router_filter(struct sbus_connection *conn,
                   struct sbus_router *router,
                   DBusMessage *message)
{
    struct sbus_message_meta meta;

    sbus_message_meta_read(message, &meta);

    switch (meta.type) {
    case DBUS_MESSAGE_TYPE_SIGNAL:
        return sbus_signal_handler(conn, router, &meta, message);
    case DBUS_MESSAGE_TYPE_METHOD_CALL:
        return sbus_method_handler(conn, router, &meta, message);
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
    case DBUS_MESSAGE_TYPE_ERROR:
        /* This will be processed by the caller. */
        return DBUS_HANDLER_RESULT_HANDLED;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid message type: %d\n", meta.type);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

DBusHandlerResult
sbus_connection_filter(DBusConnection *dbus_conn,
                       DBusMessage *message,
                       void *handler_data)
{
    struct sbus_connection *conn;

    conn = talloc_get_type(handler_data, struct sbus_connection);

    return sbus_router_filter(conn, conn->router, message);
}
