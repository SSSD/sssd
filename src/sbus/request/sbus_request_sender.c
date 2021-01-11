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

#include <dhash.h>
#include <stdint.h>
#include <string.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/sss_ptr_hash.h"
#include "sbus/sbus_private.h"
#include "sbus/interface_dbus/sbus_dbus_client_async.h"

struct sbus_sender *
sbus_sender_create(TALLOC_CTX *mem_ctx,
                   const char *name,
                   int64_t uid)
{
    struct sbus_sender sender = {.name = name, .uid = uid};

    if (name == NULL) {
        return NULL;
    }

    return sbus_sender_copy(mem_ctx, &sender);
}

struct sbus_sender *
sbus_sender_copy(TALLOC_CTX *mem_ctx,
                 const struct sbus_sender *input)
{
    struct sbus_sender *copy;

    copy = talloc_zero(mem_ctx, struct sbus_sender);
    if (copy == NULL) {
        return NULL;
    }

    copy->name = talloc_strdup(copy, input->name);
    if (copy->name == NULL) {
        talloc_free(copy);
        return NULL;
    }

    copy->uid = input->uid;

    return copy;
}

hash_table_t *
sbus_senders_init(TALLOC_CTX *mem_ctx)
{
    return sss_ptr_hash_create(mem_ctx, NULL, NULL);
}

static errno_t
sbus_senders_add(hash_table_t *table,
                 struct sbus_sender *sender)
{
    struct sbus_sender *copy;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Inserting identity of sender [%s]: %"PRIi64"\n",
          sender->name, sender->uid);

    copy = sbus_sender_copy(table, sender);
    if (copy == NULL) {
        return ENOMEM;
    }

    return sss_ptr_hash_add(table, sender->name, copy, struct sbus_sender);
}

static struct sbus_sender *
sbus_senders_lookup(hash_table_t *table,
                    const char *name)
{
    DEBUG(SSSDBG_TRACE_INTERNAL, "Looking for identity of sender [%s]\n",
          name);

    return sss_ptr_hash_lookup(table, name, struct sbus_sender);
}

void
sbus_senders_delete(hash_table_t *table,
                    const char *name)
{
    if (sss_ptr_hash_has_key(table, name)) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Removing identity of sender [%s]\n",
              name);
        sss_ptr_hash_delete(table, name, true);
    }
}

errno_t
sbus_sender_check_input(TALLOC_CTX *mem_ctx,
                        struct sbus_connection *conn,
                        enum sbus_request_type type,
                        const char *destination,
                        const char *object_path,
                        const char *interface,
                        const char *member,
                        const char *name,
                        struct sbus_sender **_sender)
{
    /* This is a server call. We do not need to resolve sender in this case. */
    if (destination != NULL && strcmp(destination, DBUS_SERVICE_DBUS) == 0) {
        return EOK;
    }

    /* Hello is a special method that is used by clients to register on the
     * bus. Upon registration server assigns unique name to the clients.
     * Therefore it is not actually possible to resolve a sender name
     * prior this call. */
    if (name == NULL && type == SBUS_REQUEST_METHOD
        && strcmp(object_path, DBUS_PATH_DBUS) == 0
        && strcmp(interface, DBUS_INTERFACE_DBUS) == 0
        && strcmp(member, "Hello") == 0) {

        *_sender = sbus_sender_create(mem_ctx, name, SBUS_SENDER_HELLO);
        if (*_sender == NULL) {
            return ENOMEM;
        }

        return EOK;
    }

    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Can not resolve empty name!\n");
        return EINVAL;
    }

    /* Got signal from bus, this is OK. This name is not really resolvable. */
    if (strcmp(name, DBUS_SERVICE_DBUS) == 0) {
        *_sender = sbus_sender_create(mem_ctx, name, SBUS_SENDER_DBUS);
        if (*_sender == NULL) {
            return ENOMEM;
        }

        return EOK;
    }

    return EAGAIN;
}

struct sbus_sender_resolve_state {
    struct sbus_connection *conn;
    enum sbus_request_type type;
    struct sbus_sender *sender;
    const char *name;
};

static void sbus_sender_resolve_done(struct tevent_req *subreq);

struct tevent_req *
sbus_sender_resolve_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sbus_connection *conn,
                         enum sbus_request_type type,
                         const char *destination,
                         const char *object_path,
                         const char *interface,
                         const char *member,
                         const char *name)
{
    struct sbus_sender_resolve_state *state;
    struct sbus_sender *sender;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sbus_sender_resolve_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->conn = conn;
    state->type = type;
    state->sender = NULL;

    ret = sbus_sender_check_input(state, conn, type, destination, object_path,
                                  interface, member, name, &state->sender);
    if (ret != EAGAIN) {
        goto done;
    }

    /* Check if the sender is already known. If yes, we must create a copy
     * of it since it may be asynchronously deleted through NameOwnerChanged
     * signal. */
    sender = sbus_senders_lookup(conn->senders, name);
    if (sender != NULL) {
        state->sender = sbus_sender_copy(state, sender);
        if (state->sender == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = EOK;
        goto done;
    }

    state->name = talloc_strdup(state, name);
    if (state->name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    subreq = sbus_call_DBus_GetConnectionUnixUser_send(state, conn,
                 DBUS_SERVICE_DBUS, DBUS_PATH_DBUS, name);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sbus_sender_resolve_done, req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sbus_sender_resolve_done(struct tevent_req *subreq)
{
    struct sbus_sender_resolve_state *state;
    struct sbus_sender *sender;
    struct tevent_req *req;
    uint32_t uid;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sbus_sender_resolve_state);

    ret = sbus_call_DBus_GetConnectionUnixUser_recv(subreq, &uid);
    talloc_zfree(subreq);
    if (ret == ERR_SBUS_UNKNOWN_OWNER && state->type == SBUS_REQUEST_SIGNAL) {
        /* If the caller of the signal exits before we translate the name,
         * it is possible that the name is no longer known on the bus.
         * E.g. when the signal is sent via dbus-send. */
        DEBUG(SSSDBG_MINOR_FAILURE, "Identity of signal sender "
              "[%s] is not known. Continue without it.\n", state->name);

        state->sender = sbus_sender_create(state, state->name,
                                           SBUS_SENDER_SIGNAL);
        if (state->sender == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    /* We don't have request chaining on this level so it is possible that
     * a concurrent lookup finished first. If this is this case, we return
     * the previous lookup result and just finish.
     *
     * We must create a copy of the result since it may be asynchronously
     * deleted through NameOwnerChanged signal. */
    sender = sbus_senders_lookup(state->conn->senders, state->name);
    if (sender != NULL) {
        state->sender = sbus_sender_copy(state, sender);
        if (state->sender == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = EOK;
        goto done;
    }

    /* Otherwise we insert this result into the table. The add operation
     * will create a copy of this structure so we can return state->sender
     * directly in the result. */
    state->sender = sbus_sender_create(state, state->name, uid);
    if (state->sender == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sbus_senders_add(state->conn->senders, state->sender);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
sbus_sender_resolve_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         struct sbus_sender **_sender)
{
    struct sbus_sender_resolve_state *state;
    state = tevent_req_data(req, struct sbus_sender_resolve_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_sender) {
        *_sender = talloc_steal(mem_ctx, state->sender);
    }

    return EOK;
}
