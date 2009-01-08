/*
   SSSD

   NSS Responder - Data Provider Interfaces

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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
#include "nss/nsssrv.h"
#include "providers/data_provider.h"

int nss_dp_send_acct_req(struct nss_ctx *nctx, TALLOC_CTX *memctx,
                         DBusPendingCallNotifyFunction callback,
                         void *callback_ctx,
                         const char *domain, int type,
                         const char *opt_name, uint32_t opt_id)
{
    DBusMessage *msg;
    DBusPendingCall *pending_reply;
    DBusConnection *conn;
    DBusError dbus_error;
    dbus_bool_t ret;
    uint32_t be_type;
    const char *attrs = "core";
    char *filter;

    /* either, or, not both */
    if (opt_name && opt_id) {
        return EINVAL;
    }

    switch (type) {
    case NSS_DP_USER:
        be_type = BE_REQ_USER;
        break;
    case NSS_DP_GROUP:
        be_type = BE_REQ_GROUP;
        break;
    default:
        return EINVAL;
    }

    if (opt_name) {
        filter = talloc_asprintf(memctx, "name=%s", opt_name);
    } else if (opt_id) {
        filter = talloc_asprintf(memctx, "idnumber=%u", opt_id);
    } else {
        filter = talloc_strdup(memctx, "name=*");
    }
    if (!filter) {
        talloc_free(nctx);
        return ENOMEM;
    }

    conn = sbus_get_connection(nctx->dp_ctx->scon_ctx);
    dbus_error_init(&dbus_error);

    /* create the message */
    msg = dbus_message_new_method_call(NULL,
                                       DP_CLI_PATH,
                                       DP_CLI_INTERFACE,
                                       DP_SRV_METHOD_GETACCTINFO);
    if (msg == NULL) {
        DEBUG(0,("Out of memory?!\n"));
        return ENOMEM;
    }

    DEBUG(4, ("Sending request for [%s][%u][%s][%s]\n",
              domain, be_type, attrs, filter));

    ret = dbus_message_append_args(msg,
                                   DBUS_TYPE_STRING, &domain,
                                   DBUS_TYPE_UINT32, &be_type,
                                   DBUS_TYPE_STRING, &attrs,
                                   DBUS_TYPE_STRING, &filter,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        DEBUG(1,("Failed to build message\n"));
        return EIO;
    }

    ret = dbus_connection_send_with_reply(conn, msg, &pending_reply,
                                            600000 /* TODO: set timeout */);
    if (!ret) {
        /*
         * Critical Failure
         * We can't communicate on this connection
         * We'll drop it using the default destructor.
         */
        DEBUG(0, ("D-BUS send failed.\n"));
        dbus_message_unref(msg);
        return EIO;
    }

    /* Set up the reply handler */
    dbus_pending_call_set_notify(pending_reply, callback, callback_ctx, NULL);
    dbus_message_unref(msg);

    return EOK;
}

int nss_dp_get_reply(DBusPendingCall *pending,
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

        /* FIXME: Destroy this connection ? */
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
            DEBUG(1,("Filed to parse message\n"));
            /* FIXME: Destroy this connection ? */
            err = EIO;
            goto done;
        }

        break;

    case DBUS_MESSAGE_TYPE_ERROR:
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

        /* FIXME: Destroy this connection ? */
        err = EIO;
    }

done:
    dbus_pending_call_unref(pending);
    dbus_message_unref(reply);

    return err;
}

static int nss_dp_identity(DBusMessage *message, void *data, DBusMessage **r)
{
    dbus_uint16_t version = DATA_PROVIDER_VERSION;
    dbus_uint16_t clitype = DP_CLI_FRONTEND;
    const char *cliname = "NSS";
    const char *nullname = "";
    DBusMessage *reply;
    dbus_bool_t ret;

    DEBUG(4,("Sending ID reply: (%d,%d,%s)\n",
             clitype, version, cliname));

    reply = dbus_message_new_method_return(message);
    ret = dbus_message_append_args(reply,
                                   DBUS_TYPE_UINT16, &clitype,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_STRING, &cliname,
                                   DBUS_TYPE_STRING, &nullname,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        return EIO;
    }

    *r = reply;
    return EOK;
}

struct sbus_method nss_dp_methods[] = {
    { DP_CLI_METHOD_IDENTITY, nss_dp_identity },
    { NULL, NULL }
};

int nss_dp_init(struct nss_ctx *nctx)
{
    int ret;

    /* Set up SBUS connection to the data provider */
    ret = dp_sbus_cli_init(nctx, nctx->ev, nctx->cdb,
                           nss_dp_methods, &nctx->dp_ctx);
    if (ret != EOK) {
        return ret;
    }

    /* attach context to the connection */
    sbus_conn_set_private_data(nctx->dp_ctx->scon_ctx, nctx);

    return EOK;
}

