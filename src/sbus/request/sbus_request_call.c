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

#include <tevent.h>
#include <talloc.h>

#include "sbus/sbus_private.h"

struct sbus_call_method_state {
    DBusMessage *reply;
};

static void sbus_call_method_done(struct tevent_req *subreq);

struct tevent_req *
sbus_call_method_send(TALLOC_CTX *mem_ctx,
                      struct sbus_connection *conn,
                      DBusMessage *raw_message,
                      sbus_invoker_keygen keygen,
                      sbus_invoker_writer_fn writer,
                      const char *bus,
                      const char *path,
                      const char *iface,
                      const char *method,
                      void *input)
{
    struct sbus_call_method_state *state;
    struct sbus_request *sbus_req;
    struct tevent_req *subreq;
    struct tevent_req *req;
    const char *key = NULL;
    DBusMessage *msg;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sbus_call_method_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    sbus_req = sbus_request_create(state, conn, SBUS_REQUEST_METHOD,
                                   bus, iface, method, path);
    if (sbus_req == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg = sbus_create_method_call(state, raw_message, writer, bus, path,
                                  iface, method, input);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sbus_request_key(state, keygen, sbus_req, input, &key);
    if (ret != EOK) {
        goto done;
    }

    subreq = sbus_outgoing_request_send(state, conn->ev, conn, key, msg);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sbus_call_method_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, conn->ev);
    }

    return req;
}

static void sbus_call_method_done(struct tevent_req *subreq)
{
    struct sbus_call_method_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sbus_call_method_state);

    ret = sbus_outgoing_request_recv(state, subreq, &state->reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
sbus_call_method_recv(TALLOC_CTX *mem_ctx,
                      struct tevent_req *req,
                      DBusMessage **_reply)
{
    struct sbus_call_method_state *state;
    errno_t ret;

    state = tevent_req_data(req, struct sbus_call_method_state);

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

void
sbus_call_signal_send(struct sbus_connection *conn,
                      DBusMessage *raw_message,
                      sbus_invoker_writer_fn writer,
                      const char *path,
                      const char *iface,
                      const char *signal_name,
                      void *input)
{
    DBusMessage *msg;

    msg = sbus_create_signal_call(NULL, raw_message, writer, path, iface,
                                  signal_name, input);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create signal message!\n");
        return;
    }

    sbus_emit_signal(conn, msg);
}
