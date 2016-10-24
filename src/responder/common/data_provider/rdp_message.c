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

static errno_t
rdp_message_send_internal(struct resp_ctx *rctx,
                          struct sss_domain_info *domain,
                          DBusPendingCallNotifyFunction notify_fn,
                          void *notify_fn_data,
                          const char *path,
                          const char *iface,
                          const char *method,
                          int first_arg_type,
                          va_list va)
{
    struct be_conn *be_conn;
    DBusMessage *msg = NULL;
    dbus_bool_t bret;
    errno_t ret;

    ret = sss_dp_get_domain_conn(rctx, domain->conn_name, &be_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: The Data Provider connection for "
              "%s is not available!\n", domain->name);
        goto done;
    }

    msg = dbus_message_new_method_call(NULL, path, iface, method);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create message\n");
        ret = ENOMEM;
        goto done;
    }

    bret = dbus_message_append_args_valist(msg, first_arg_type, va);
    if (!bret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build message\n");
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "DP Request: %s %s.%s\n", path, iface, method);

    ret = sbus_conn_send(be_conn->conn, msg, 3000,
                         notify_fn, notify_fn_data, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to contact Data Provider "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    if (msg != NULL) {
        dbus_message_unref(msg);
    }

    return ret;
}

static errno_t rdp_process_pending_call(TALLOC_CTX *mem_ctx,
                                        DBusPendingCall *pending,
                                        DBusMessage **_reply)
{
    DBusMessage *reply;
    dbus_bool_t bret;
    DBusError error;
    errno_t ret;

    *_reply = NULL;

    dbus_error_init(&error);

    reply = dbus_pending_call_steal_reply(pending);
    if (reply == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Severe error. A reply callback was "
              "called but no reply was received and no timeout occurred\n");
        ret = EFAULT;
        goto done;
    }

    ret = sbus_talloc_bound_message(mem_ctx, reply);
    if (ret != EOK) {
        return ret;
    }

    switch (dbus_message_get_type(reply)) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        DEBUG(SSSDBG_TRACE_FUNC, "DP Success\n");
        ret = EOK;
        break;

    case DBUS_MESSAGE_TYPE_ERROR:
        bret = dbus_set_error_from_message(&error, reply);
        if (bret == false) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read error from message\n");
            ret = EIO;
            goto done;
        }

        DEBUG(SSSDBG_CRIT_FAILURE, "DP Error [%s]: %s\n",
              error.name, (error.message == NULL ? "(null)" : error.message));
        ret = sbus_error_to_errno(&error);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected type?\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    *_reply = reply;

done:
    dbus_pending_call_unref(pending);
    dbus_error_free(&error);

    return ret;
}

struct rdp_message_state {
    struct DBusMessage *reply;
};

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
    struct tevent_req *req;
    errno_t ret;
    va_list va;

    req = tevent_req_create(mem_ctx, &state, struct rdp_message_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    va_start(va, first_arg_type);
    ret = rdp_message_send_internal(rctx, domain, rdp_message_done, req,
                                    path, iface, method, first_arg_type, va);
    va_end(va);
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
    struct tevent_req *req;
    errno_t ret;

    req = talloc_get_type(ptr, struct tevent_req);
    state = tevent_req_data(req, struct rdp_message_state);

    ret = rdp_process_pending_call(state, pending, &state->reply);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t _rdp_message_recv(struct tevent_req *req,
                          int first_arg_type,
                          ...)
{
    struct rdp_message_state *state;
    errno_t ret;
    va_list va;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    state = tevent_req_data(req, struct rdp_message_state);

    va_start(va, first_arg_type);
    ret = sbus_parse_message_valist(state->reply, false, first_arg_type, va);
    va_end(va);

    return ret;
}

static void rdp_message_send_and_reply_done(DBusPendingCall *pending,
                                            void *ptr);

void _rdp_message_send_and_reply(struct sbus_request *sbus_req,
                                 struct resp_ctx *rctx,
                                 struct sss_domain_info *domain,
                                 const char *path,
                                 const char *iface,
                                 const char *method,
                                 int first_arg_type,
                                 ...)
{
    errno_t ret;
    va_list va;

    va_start(va, first_arg_type);
    ret = rdp_message_send_internal(rctx, domain,
                                    rdp_message_send_and_reply_done, sbus_req,
                                    path, iface, method, first_arg_type, va);
    va_end(va);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to contact Data Provider "
              "[%d]: %s\n", ret, sss_strerror(ret));
        talloc_free(sbus_req);
    }
}

static void rdp_message_send_and_reply_done(DBusPendingCall *pending,
                                            void *ptr)
{
    struct sbus_request *sbus_req;
    DBusMessage *reply;
    dbus_uint32_t serial;
    const char *sender;
    dbus_bool_t dbret;
    errno_t ret;

    sbus_req = talloc_get_type(ptr, struct sbus_request);

    ret = rdp_process_pending_call(sbus_req, pending, &reply);
    if (ret != EOK) {
        /* Something bad happened. Just kill the request. */
        ret = EIO;
        goto done;
    }

    /* Otherwise we have a valid reply and we do not care about returned
     * value. We set destination and serial in reply to point to the original
     * client request. */

    sender = dbus_message_get_sender(sbus_req->message);
    serial = dbus_message_get_serial(sbus_req->message);

    dbret = dbus_message_set_destination(reply, sender);
    if (dbret == false) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set reply sender!\n");
        ret = EIO;
        goto done;
    }

    dbret = dbus_message_set_reply_serial(reply, serial);
    if (dbret == false) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set reply serial!\n");
        ret = EIO;
        goto done;
    }

    sbus_request_finish(sbus_req, reply);

    ret = EOK;

done:
    if (ret != EOK) {
        /* Something bad happend, just kill the request. */
        talloc_free(sbus_req);
    }
}
