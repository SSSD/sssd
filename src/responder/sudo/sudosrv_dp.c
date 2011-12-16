/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2011 Red Hat

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
#include <dbus/dbus.h>
#include "sbus/sssd_dbus.h"

#include "util/util.h"
#include "sbus/sbus_client.h"
#include "providers/data_provider.h"
#include "responder/common/responder.h"
#include "responder/sudo/sudosrv_private.h"

struct sudo_dp_refresh_state {
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
};

/* FIXME -- need to keep track of a running request
 * and just queue a callback
 * OR reuse the common dp requests
 */
static void sudosrv_dp_process_reply(DBusPendingCall *pending, void *ptr);

struct tevent_req * sudosrv_dp_refresh_send(struct resp_ctx *rctx,
                                            struct sss_domain_info *dom,
                                            const char *username)
{
    struct be_conn *be_conn;
    struct sudo_dp_refresh_state *state;
    DBusMessage *msg;
    dbus_bool_t dbret;
    int ret;
    const int timeout = SSS_CLI_SOCKET_TIMEOUT / 2;
    struct tevent_req *req;

     /* Cache refresh requests need to be allocated on the responder context
      * so that they don't go away if a client disconnects. The worst-
      * case scenario here is that the cache is updated without any
      * client expecting a response.
      */
    req = tevent_req_create(rctx, &state, struct sudo_dp_refresh_state);
    if (!req) return NULL;

    /* double check dp_ctx has actually been initialized.
     * in some pathological cases it may happen that sudo starts up before
     * dp connection code is actually able to establish a connection.
     */
    ret = sss_dp_get_domain_conn(rctx, dom->name, &be_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("The Data Provider connection for %s is not available! "
               "This maybe a bug, it shouldn't happen!\n",
               dom->name));
        ret = EIO;
        goto error;
    }

    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DP_INTERFACE,
                                       DP_METHOD_SUDOHANDLER);
    if (msg == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("Out of memory?!\n"));
        ret = ENOMEM;
        goto error;
    }

    if (username != NULL) {
        dbret = dbus_message_append_args(msg,
                                         DBUS_TYPE_STRING, &username,
                                         DBUS_TYPE_INVALID);
        if (!dbret) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to generate dbus reply\n"));
            ret = EIO;
            goto error;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Sending SUDOers refresh request\n"));
    ret = sbus_conn_send(be_conn->conn, msg,
                         timeout, sudosrv_dp_process_reply,
                         req, NULL);
    dbus_message_unref(msg);

    return req;

error:
    tevent_req_error(req, ret);
    tevent_req_post(req, rctx->ev);
    return req;
}

static int sudosrv_dp_get_reply(DBusPendingCall *pending,
                                dbus_uint16_t *err_maj,
                                dbus_uint32_t *err_min,
                                char **err_msg)
{
    DBusMessage *reply;
    DBusError dbus_error;
    dbus_bool_t ret;
    int type;
    int err = EOK;

    dbus_error_init(&dbus_error);

    reply = dbus_pending_call_steal_reply(pending);
    if (!reply) {
        /* reply should never be null. This function shouldn't be called
         * until reply is valid or timeout has occurred. If reply is NULL
         * here, something is seriously wrong and we should bail out.
         */
        DEBUG(0, ("Severe error. A reply callback was called but no reply was received and no timeout occurred\n"));

        err = EIO;
        goto done;
    }

    type = dbus_message_get_type(reply);
    switch (type) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        ret = dbus_message_get_args(reply, &dbus_error,
                                    DBUS_TYPE_UINT16, err_maj,
                                    DBUS_TYPE_UINT32, err_min,
                                    DBUS_TYPE_STRING, err_msg,
                                    DBUS_TYPE_INVALID);
        if (!ret) {
            DEBUG(1,("Failed to parse message\n"));
            if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
            err = EIO;
            goto done;
        }

        DEBUG(4, ("Got reply (%u, %u, %s) from Data Provider\n",
                  (unsigned int)*err_maj, (unsigned int)*err_min, *err_msg));

        break;

    case DBUS_MESSAGE_TYPE_ERROR:
        if (strcmp(dbus_message_get_error_name(reply),
                   DBUS_ERROR_NO_REPLY) == 0) {
            err = ETIME;
            goto done;
        }
        DEBUG(0,("The Data Provider returned an error [%s]\n",
                 dbus_message_get_error_name(reply)));
        /* Falling through to default intentionally*/
    default:
        /*
         * Timeout or other error occurred or something
         * unexpected happened.
         * It doesn't matter which, because either way we
         * know that this connection isn't trustworthy.
         * We'll destroy it now.
         */

        err = EIO;
    }

done:
    dbus_pending_call_unref(pending);
    dbus_message_unref(reply);

    return err;
}

static void sudosrv_dp_process_reply(DBusPendingCall *pending, void *ptr)
{
    struct tevent_req *req;
    errno_t ret;
    char *err_msg;
    struct sudo_dp_refresh_state *state;

    req = talloc_get_type(ptr, struct tevent_req);
    state = tevent_req_data(req, struct sudo_dp_refresh_state);

    ret = sudosrv_dp_get_reply(pending, &state->err_maj, &state->err_min, &err_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to get a reply from DP! "
              "err_maj: %d err_min: %d err_msg: [%s]\n",
              state->err_maj, state->err_min, err_msg ? err_msg : "none set"));
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_done(req);
}

errno_t sudosrv_dp_refresh_recv(struct tevent_req *req,
                                dbus_uint16_t *_err_maj,
                                dbus_uint32_t *_err_min)
{
    struct sudo_dp_refresh_state *state;
    state = tevent_req_data(req, struct sudo_dp_refresh_state);

    if (_err_maj) *_err_maj = state->err_maj;
    if (_err_min) *_err_min = state->err_min;

    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}
