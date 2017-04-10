/*
    Authors:
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
#include "providers/data_provider/dp_responder_iface.h"
#include "responder/common/responder.h"
#include "responder/autofs/autofs_private.h"

struct sss_dp_get_autofs_info {
    struct sss_domain_info *dom;

    bool fast_reply;
    enum sss_dp_autofs_type type;
    const char *name;
};

static DBusMessage *
sss_dp_get_autofs_msg(void *pvt);

struct tevent_req *
sss_dp_get_autofs_send(TALLOC_CTX *mem_ctx,
                       struct resp_ctx *rctx,
                       struct sss_domain_info *dom,
                       bool fast_reply,
                       enum sss_dp_autofs_type type,
                       const char *name)
{
    struct tevent_req *req;
    struct sss_dp_req_state *state;
    struct sss_dp_get_autofs_info *info;
    errno_t ret;
    char *key;

    req = tevent_req_create(mem_ctx, &state, struct sss_dp_req_state);
    if (!req) {
        return NULL;
    }

    if (!dom) {
        ret = EINVAL;
        goto error;
    }

    info = talloc_zero(state, struct sss_dp_get_autofs_info);
    info->fast_reply = fast_reply;
    info->type = type;
    info->name = name;
    info->dom = dom;

    key = talloc_asprintf(state, "%d:%s@%s", type, name, dom->name);
    if (!key) {
        ret = ENOMEM;
        goto error;
    }

    ret = sss_dp_issue_request(state, rctx, key, dom, sss_dp_get_autofs_msg,
                               info, req);
    talloc_free(key);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not issue DP request [%d]: %s\n",
               ret, strerror(ret));
        goto error;
    }

    return req;

error:
    tevent_req_error(req, ret);
    tevent_req_post(req, rctx->ev);
    return req;
}

static DBusMessage *
sss_dp_get_autofs_msg(void *pvt)
{
    DBusMessage *msg;
    dbus_bool_t dbret;
    struct sss_dp_get_autofs_info *info;
    uint32_t dp_flags = 0;

    info = talloc_get_type_abort(pvt, struct sss_dp_get_autofs_info);

    if (info->fast_reply) {
        dp_flags |= DP_FAST_REPLY;
    }

    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       IFACE_DP,
                                       IFACE_DP_AUTOFSHANDLER);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        return NULL;
    }

    /* create the message */
    DEBUG(SSSDBG_TRACE_FUNC,
          "Creating autofs request for [%s][%u][%s]\n",
           info->dom->name, dp_flags, info->name);

    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_UINT32, &dp_flags,
                                     DBUS_TYPE_STRING, &info->name,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build message\n");
        dbus_message_unref(msg);
        return NULL;
    }

    return msg;
}

errno_t
sss_dp_get_autofs_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       dbus_uint16_t *dp_err,
                       dbus_uint32_t *dp_ret,
                       char **err_msg)
{
    return sss_dp_req_recv(mem_ctx, req, dp_err, dp_ret, err_msg);
}
