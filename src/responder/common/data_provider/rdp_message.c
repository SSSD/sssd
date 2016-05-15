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
#include <tevent.h>

#include "responder/common/data_provider/rdp.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_errors.h"
#include "util/util.h"

static errno_t rdp_error_to_errno(DBusError *error)
{
    static struct {
        const char *name;
        errno_t ret;
    } list[] = {{SBUS_ERROR_INTERNAL, ERR_INTERNAL},
                {SBUS_ERROR_NOT_FOUND, ENOENT},
                {SBUS_ERROR_DP_FATAL, ERR_TERMINATED},
                {SBUS_ERROR_DP_OFFLINE, ERR_OFFLINE},
                {SBUS_ERROR_DP_NOTSUP, ENOTSUP},
                {NULL, ERR_INTERNAL}
    };
    int i;

    if (!dbus_error_is_set(error)) {
        return EOK;
    }

    for (i = 0; list[i].name != NULL; i ++) {
        if (dbus_error_has_name(error, list[i].name)) {
            return list[i].ret;
        }
    }

    return EIO;
}

struct rdp_message_state {
    struct DBusMessage *reply;
};

static int rdp_message_state_destructor(struct rdp_message_state *state)
{
    if (state->reply != NULL) {
        dbus_message_unref(state->reply);
    }

    return 0;
}

static void rdp_message_done(DBusPendingCall *pending, void *ptr);

struct tevent_req *_rdp_message_send(TALLOC_CTX *mem_ctx,
                                     struct resp_ctx *rctx,
                                     struct sss_domain_info *domain,
                                     const char *path,
                                     const char *iface,
                                     const char *method,
                                     int first_arg_type,
                                     ...)
{
    struct rdp_message_state *state;
    struct be_conn *be_conn;
    struct tevent_req *req;
    DBusMessage *msg;
    dbus_bool_t bret;
    errno_t ret;
    va_list va;

    req = tevent_req_create(mem_ctx, &state, struct rdp_message_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    talloc_set_destructor(state, rdp_message_state_destructor);

    ret = sss_dp_get_domain_conn(rctx, domain->conn_name, &be_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: The Data Provider connection for "
              "%s is not available!\n", domain->name);
        ret = ERR_INTERNAL;
        goto immediately;
    }

    msg = dbus_message_new_method_call(NULL, path, iface, method);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create message\n");
        ret = ENOMEM;
        goto immediately;
    }

    va_start(va, first_arg_type);
    bret = dbus_message_append_args_valist(msg, first_arg_type, va);
    va_end(va);
    if (!bret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build message\n");
        ret = EIO;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "DP Request: %s %s.%s\n", path, iface, method);

    ret = sbus_conn_send(be_conn->conn, msg, 30000,
                         rdp_message_done, req, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to contact Data Provider "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto immediately;
    }

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, rctx->ev);

    return req;
}

static void rdp_message_done(DBusPendingCall *pending, void *ptr)
{
    struct rdp_message_state *state;
    DBusMessage *reply = NULL;
    struct tevent_req *req;
    DBusError error;
    dbus_bool_t bret;
    errno_t ret;

    req = talloc_get_type(ptr, struct tevent_req);
    state = tevent_req_data(req, struct rdp_message_state);

    dbus_error_init(&error);

    reply = dbus_pending_call_steal_reply(pending);
    if (reply == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Severe error. A reply callback was "
              "called but no reply was received and no timeout occurred\n");
        ret = EFAULT;
        goto done;
    }

    switch (dbus_message_get_type(reply)) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        DEBUG(SSSDBG_TRACE_FUNC, "DP Success\n");
        state->reply = reply;
        ret = EOK;
        goto done;

    case DBUS_MESSAGE_TYPE_ERROR:
        bret = dbus_set_error_from_message(&error, reply);
        if (bret == false) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read error from message\n");
            ret = EIO;
            goto done;
        }

        DEBUG(SSSDBG_CRIT_FAILURE, "DP Error [%s]: %s\n",
              error.name, (error.message == NULL ? "(null)" : error.message));
        ret = rdp_error_to_errno(&error);
        goto done;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected type?\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    ret = ERR_INTERNAL;

done:
    dbus_pending_call_unref(pending);
    dbus_error_free(&error);

    if (ret == EOK) {
        tevent_req_done(req);
        return;
    }

    if (reply != NULL) {
        dbus_message_unref(reply);
    }
    tevent_req_error(req, ret);
}

errno_t _rdp_message_recv(struct tevent_req *req,
                          int first_arg_type,
                          ...)
{
    struct rdp_message_state *state;
    DBusError error;
    dbus_bool_t bret;
    errno_t ret;
    va_list va;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    state = tevent_req_data(req, struct rdp_message_state);
    dbus_error_init(&error);

    va_start(va, first_arg_type);
    bret = dbus_message_get_args_valist(state->reply, &error, first_arg_type, va);
    va_end(va);

    if (bret == false) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse reply\n");
        ret = EIO;
        goto done;
    }

    ret = rdp_error_to_errno(&error);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse message [%s]: %s\n",
              error.name, error.message);
        goto done;
    }

done:
    dbus_error_free(&error);
    return ret;
}

