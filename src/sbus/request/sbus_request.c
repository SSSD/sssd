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

#include <talloc.h>
#include <tevent.h>
#include <dhash.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/dlinklist.h"
#include "util/sss_chain_id.h"
#include "sbus/sbus_request.h"
#include "sbus/sbus_private.h"

typedef errno_t
(*sbus_request_messages_fn)(struct tevent_req *req,
                            TALLOC_CTX **_reply_mem_ctx,
                            DBusMessage **_client_message,
                            DBusMessage ***_reply);

struct sbus_active_requests *
sbus_active_requests_init(TALLOC_CTX *mem_ctx)
{
    struct sbus_active_requests *requests;

    requests = talloc_zero(mem_ctx, struct sbus_active_requests);
    if (requests == NULL) {
        return NULL;
    }

    requests->incoming = sbus_requests_init(requests);
    if (requests->incoming == NULL) {
        goto fail;
    }

    requests->outgoing = sbus_requests_init(requests);
    if (requests->outgoing == NULL) {
        goto fail;
    }

    return requests;

fail:
    talloc_free(requests);
    return NULL;
}

struct sbus_request *
sbus_request_create(TALLOC_CTX *mem_ctx,
                    struct sbus_connection *conn,
                    enum sbus_request_type type,
                    const char *destination,
                    const char *interface,
                    const char *member,
                    const char *path)
{
    struct sbus_request *request;

    request = talloc_zero(mem_ctx, struct sbus_request);
    if (request == NULL) {
        return NULL;
    }

    request->conn = conn;
    request->type = type;
    request->sender = NULL;

    request->destination = talloc_strdup(request, destination);
    if (destination != NULL && request->destination == NULL) {
        goto fail;
    }

    request->interface = talloc_strdup(request, interface);
    if (request->interface == NULL) {
        goto fail;
    }

    request->member = talloc_strdup(request, member);
    if (request->member == NULL) {
        goto fail;
    }

    request->path = talloc_strdup(request, path);
    if (request->path == NULL) {
        goto fail;
    }

    return request;

fail:
    talloc_free(request);
    return NULL;
}

static errno_t
sbus_request_prepare_reply(TALLOC_CTX *mem_ctx,
                           enum sbus_request_type type,
                           DBusMessage *msg,
                           DBusMessage **_reply,
                           DBusMessageIter **_reply_iterator)
{
    DBusMessageIter *iterator;
    DBusMessage *reply;
    errno_t ret;

    if (type == SBUS_REQUEST_SIGNAL) {
        /* Signals don't send reply*/
        *_reply = NULL;
        *_reply_iterator = NULL;
        return EOK;
    }

    iterator = talloc_zero(mem_ctx, DBusMessageIter);
    if (iterator == NULL) {
        return ENOMEM;
    }

    reply = dbus_message_new_method_return(msg);
    if (reply == NULL) {
        talloc_free(iterator);
        return ENOMEM;
    }

    ret = sbus_message_bound(mem_ctx, reply);
    if (ret != EOK) {
        talloc_free(iterator);
        dbus_message_unref(reply);
        return ret;
    }

    dbus_message_iter_init_append(reply, iterator);

    *_reply = reply;
    *_reply_iterator = iterator;

    return EOK;
}

static errno_t
sbus_request_switch_reply(DBusMessage *reply,
                          struct tevent_req *req,
                          sbus_request_messages_fn messages_fn)
{
    DBusMessage *client_message;
    DBusMessage **reply_pointer;
    TALLOC_CTX *reply_mem_ctx;
    const char *sender;
    dbus_uint32_t serial;
    dbus_bool_t dbret;
    errno_t ret;

    ret = messages_fn(req, &reply_mem_ctx, &client_message, &reply_pointer);
    if (ret != EOK) {
        return ret;
    }

    /* Do not copy reply if there is none. */
    if (reply == NULL) {
        *reply_pointer = NULL;
        return EOK;
    }

    /* Copy reply to location in a state of this request. */

    *reply_pointer = dbus_message_copy(reply);
    if (*reply_pointer == NULL) {
        return ENOMEM;
    }

    ret = sbus_message_bound(reply_mem_ctx, *reply_pointer);
    if (ret != EOK) {
        goto done;
    }

    if (client_message == NULL) {
        ret = EOK;
        goto done;
    }

    /* We set destination and serial in reply to point to the original
     * client request. */

    sender = dbus_message_get_sender(client_message);
    serial = dbus_message_get_serial(client_message);

    dbret = dbus_message_set_destination(*reply_pointer, sender);
    if (dbret == false) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set reply sender!\n");
        ret = EIO;
        goto done;
    }

    dbret = dbus_message_set_reply_serial(*reply_pointer, serial);
    if (dbret == false) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set reply serial!\n");
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        dbus_message_unref(*reply_pointer);
        *reply_pointer = NULL;
    }

    return ret;
}

static void
sbus_request_notify_error(hash_table_t *table,
                          const char *key,
                          struct tevent_req *req,
                          errno_t error)
{
    struct sbus_request_list *mainreq = NULL;
    struct sbus_request_list *list;
    struct sbus_request_list *item;

    list = sbus_requests_lookup(table, key);
    if (list == NULL) {
        /* This was the only request with no key generator available. */
        tevent_req_error(req, error);
        return;
    }

    /* First notify all chained D-Bus requests. */
    DLIST_FOR_EACH(item, list) {
        /* Remember the main request. */
        if (item->req == req) {
            mainreq = item;
            continue;
        }

        /* We don't want to notify current, invalid or non D-Bus request. */
        if (!item->is_dbus || item->is_invalid) {
            continue;
        }

        sbus_requests_finish(item, error);
    }

    /* Now we finish the main request. */
    sbus_requests_finish(mainreq, error);

    /* And as last, we notify all await requests. */
    DLIST_FOR_EACH(item, list) {
        if (item->is_dbus) {
            continue;
        }

        sbus_requests_finish(item, error);
    }

    sbus_requests_delete(list);
}

static void
sbus_request_notify_success(hash_table_t *table,
                            const char *key,
                            struct tevent_req *req,
                            sbus_request_messages_fn messages_fn,
                            DBusMessage *reply)
{
    struct sbus_request_list *mainreq = NULL;
    struct sbus_request_list *list;
    struct sbus_request_list *item;
    errno_t ret;

    list = sbus_requests_lookup(table, key);
    if (list == NULL) {
        /* This was the only request with no key generator available. */
        tevent_req_done(req);
        return;
    }

    /* First notify all chained D-Bus requests so we can steal the reply. */
    DLIST_FOR_EACH(item, list) {
        /* Remember the main request. */
        if (item->req == req) {
            mainreq = item;
            continue;
        }

        /* We don't want to notify current, invalid or non D-Bus request. */
        if (!item->is_dbus || item->is_invalid) {
            continue;
        }

        ret = sbus_request_switch_reply(reply, item->req, messages_fn);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to switch reply for %p, "
                  "terminating this request!\n", item->req);
            sbus_requests_finish(item, ret);
            continue;
        }

        sbus_requests_finish(item, EOK);
    }

    /* Now we finish the main request. */
    sbus_requests_finish(mainreq, EOK);

    /* And as last, we notify all await requests. */
    DLIST_FOR_EACH(item, list) {
        if (item->is_dbus) {
            continue;
        }

        sbus_requests_finish(item, EOK);
    }

    sbus_requests_delete(list);
}

struct sbus_incoming_request_state {
    struct tevent_context *ev;
    const struct sbus_invoker *invoker;
    const struct sbus_handler *handler;
    struct sbus_connection *conn;
    struct sbus_request *request;
    DBusMessageIter *read_iter;
    DBusMessage *reply;
    DBusMessage *msg;
    const char *key;
};

static errno_t
sbus_request_messages(struct tevent_req *req,
                      TALLOC_CTX **_reply_mem_ctx,
                      DBusMessage **_client_message,
                      DBusMessage ***_reply)
{
    struct sbus_incoming_request_state *state;

    state = tevent_req_data(req, struct sbus_incoming_request_state);
    if (state == NULL) {
        return ERR_INTERNAL;
    }

    *_reply_mem_ctx = state;
    *_client_message = state->msg;
    *_reply = &state->reply;

    return EOK;
}

static void sbus_incoming_request_sender_done(struct tevent_req *subreq);
static void sbus_incoming_request_done(struct tevent_req *subreq);

struct tevent_req *
sbus_incoming_request_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sbus_connection *conn,
                           struct sbus_request *request,
                           const struct sbus_invoker *invoker,
                           const struct sbus_handler *handler,
                           const char *sender_name,
                           DBusMessageIter *read_iter,
                           DBusMessage *msg)
{
    struct sbus_incoming_request_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sbus_incoming_request_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    if (invoker->issue == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "There is no invoker set!\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    switch (handler->type) {
    case SBUS_HANDLER_SYNC:
        if (handler->sync == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "There is no handler set!\n");
            ret = ERR_INTERNAL;
            goto done;
        }
        break;
    case SBUS_HANDLER_ASYNC:
        if (handler->async_send == NULL || handler->async_recv == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "There is no handler set!\n");
            ret = ERR_INTERNAL;
            goto done;
        }
        break;
    }

    state->ev = ev;
    state->msg = msg;
    state->conn = conn;
    state->request = request;
    state->invoker = invoker;
    state->handler = handler;
    state->read_iter = read_iter;
    state->reply = NULL;

    subreq = sbus_sender_resolve_send(mem_ctx, ev, conn, request->type,
                                      request->destination, request->path,
                                      request->interface, request->member,
                                      sender_name);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sbus_incoming_request_sender_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sbus_incoming_request_sender_done(struct tevent_req *subreq)
{
    struct sbus_incoming_request_state *state;
    DBusMessageIter *write_iter = NULL;
    struct sbus_sender *sender;
    struct tevent_req *req;
    const char *member = NULL;
    bool key_exists;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sbus_incoming_request_state);

    ret = sbus_sender_resolve_recv(state, subreq, &sender);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    state->request->sender = talloc_steal(state->request, sender);
    if (sender != NULL) {
        member = sender->name;
    }

    ret = sbus_check_access(state->conn, state->request);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_request_prepare_reply(state, state->request->type, state->msg,
                                     &state->reply, &write_iter);
    if (ret != EOK) {
        goto done;
    }

    /**
     * Invoke a read invoker. This function will read method arguments
     * from message. Then it will use these arguments to create a key
     * describing this method and at last, it will schedule method handler
     * to be issued in next loop.
     */
    subreq = state->invoker->issue(state, state->ev, state->request,
                                   state->invoker->keygen, state->handler,
                                   state->read_iter, write_iter,
                                   &state->key);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        tevent_req_error(req, ENOMEM);
        return;
    }

    /**
     * Now when we have the key, we will search table to see if the same
     * request is not already in progress. If it is, we cancel this one
     * and register ourselves for notification when it is finished.
     *
     * Otherwise we add ourselves as the first request of this type and
     * set a tevent callback that is triggered when the method handler is done.
     */
    ret = sbus_requests_add(state->conn->requests->incoming, state->key,
                            state->conn, req, member, true, &key_exists);
    if (ret != EOK || key_exists) {
        /* Cancel the sub request. Since there was either an error or the
         * sub request was chained. */
        talloc_zfree(subreq);
        goto done;
    }

    tevent_req_set_callback(subreq, sbus_incoming_request_done, req);
    return;

done:
    talloc_zfree(write_iter);

    if (state->reply != NULL) {
        dbus_message_unref(state->reply);
        state->reply = NULL;
    }

    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void sbus_incoming_request_done(struct tevent_req *subreq)
{
    struct sbus_incoming_request_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sbus_incoming_request_state);

    /* state->reply is filled through iterator in the subrequest. */
    ret = sbus_invoker_recv(subreq);
    talloc_zfree(subreq);

    if (ret != EOK) {
        sbus_request_notify_error(state->conn->requests->incoming,
                                  state->key, req, ret);
        return;
    }

    sbus_request_notify_success(state->conn->requests->incoming,
                                state->key, req, sbus_request_messages,
                                state->reply);
}

errno_t
sbus_incoming_request_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           DBusMessage **_reply)
{
    struct sbus_incoming_request_state *state;
    errno_t ret;

    state = tevent_req_data(req, struct sbus_incoming_request_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    /* Signals have no reply so this is ok. */
    if (state->reply == NULL) {
        *_reply = NULL;
        return EOK;
    }

    ret = sbus_message_bound_steal(mem_ctx, state->reply);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to steal message [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    *_reply = state->reply;

    return EOK;
}

struct sbus_outgoing_request_state {
    const char *key;
    struct sbus_connection *conn;
    DBusMessage *reply;
    uint64_t chain_id;
};

static errno_t
sbus_outgoing_request_messages(struct tevent_req *req,
                               TALLOC_CTX **_reply_mem_ctx,
                               DBusMessage **_client_message,
                               DBusMessage ***_reply)
{
    struct sbus_outgoing_request_state *state;

    state = tevent_req_data(req, struct sbus_outgoing_request_state);
    if (state == NULL) {
        return ERR_INTERNAL;
    }

    *_reply_mem_ctx = state;
    *_client_message = NULL;
    *_reply = &state->reply;

    return EOK;
}

static void sbus_outgoing_request_done(struct tevent_req *subreq);

struct tevent_req *
sbus_outgoing_request_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sbus_connection *conn,
                           const char *key,
                           DBusMessage *msg)
{
    struct sbus_outgoing_request_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    const char *destination;
    bool key_exists;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sbus_outgoing_request_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->conn = conn;

    /*
     * The message is sent over top level dbus tevent code. This means that
     * the chain id information is lost and is not restored when we get reply
     * from dbus. Therefore we need to remember it and restore it manually
     * when this request is done.
     */
    state->chain_id = sss_chain_id_get();

    if (key != NULL) {
        state->key = talloc_strdup(state, key);
        if (state->key == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed!\n");
            ret = ENOMEM;
            goto done;
        }
    }

    destination = dbus_message_get_destination(msg);

    /**
     * We will search table to see if the same request is not already
     * in progress. If it is, we register ourselves for notification
     * when it is finished.
     *
     * Otherwise we add ourselves as the first request of this type and
     * set a tevent callback that is triggered when the method handler is done.
     */
    ret = sbus_requests_add(conn->requests->outgoing, key,
                            conn, req, destination, true, &key_exists);
    if (ret != EOK) {
        goto done;
    }

    if (key_exists) {
        return req;
    }

    subreq = sbus_message_send(state, conn, msg, SBUS_MESSAGE_TIMEOUT);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sbus_outgoing_request_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sbus_outgoing_request_done(struct tevent_req *subreq)
{
    struct sbus_outgoing_request_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sbus_outgoing_request_state);

    sss_chain_id_set(state->chain_id);

    ret = sbus_message_recv(state, subreq, &state->reply);
    talloc_zfree(subreq);

    if (ret != EOK) {
        sbus_request_notify_error(state->conn->requests->outgoing,
                                  state->key, req, ret);
        return;
    }

    sbus_request_notify_success(state->conn->requests->outgoing,
                                state->key, req,
                                sbus_outgoing_request_messages,
                                state->reply);
}

errno_t
sbus_outgoing_request_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           DBusMessage **_reply)
{
    struct sbus_outgoing_request_state *state;
    errno_t ret;

    state = tevent_req_data(req, struct sbus_outgoing_request_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    ret = sbus_message_bound_steal(mem_ctx, state->reply);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to steal message [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    *_reply = state->reply;

    return EOK;
}

struct sbus_request_await_state {
    int dummy;
};

struct tevent_req *
sbus_request_await_send(TALLOC_CTX *mem_ctx,
                        struct sbus_connection *conn,
                        enum sbus_request_type type,
                        const char *object_path,
                        const char *interface,
                        const char *member,
                        const char *additional_key)
{
    struct sbus_request_await_state *state;
    struct sbus_request_list *list;
    struct tevent_req *req;
    const char *key;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sbus_request_await_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    key = talloc_asprintf(state, "-:%u:%s.%s:%s%s%s",
                          type, interface, member, object_path,
                          additional_key == NULL ? "" : ":",
                          additional_key == NULL ? "" : additional_key);
    if (key == NULL) {
        ret = ENOMEM;
        goto done;
    }

    list = sbus_requests_lookup(conn->requests->outgoing, key);
    if (list == NULL) {
        /* No active request with this key exists. */
        ret = EOK;
        goto done;
    }

    /* Otherwise attach to this request. */
    ret = sbus_requests_add(conn->requests->outgoing, key, conn,
                            req, member, false, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to attach to the request list "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, conn->ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, conn->ev);
    }

    return req;
}

errno_t sbus_request_await_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static errno_t sbus_unwanted_reply_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

void sbus_unwanted_reply(struct tevent_req *subreq)
{
    errno_t ret;

    ret = sbus_unwanted_reply_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ERR_SBUS_UNKNOWN_SERVICE) {
        DEBUG(SSSDBG_OP_FAILURE, "Error sending sbus message [%d]: %s\n",
              ret, sss_strerror(ret));
    }
}
