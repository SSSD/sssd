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

#include "util/util.h"
#include "providers/data_provider.h"
#include "providers/data_provider_req.h"
#include "responder/common/responder.h"
#include "responder/sudo/sudosrv_private.h"
#include "db/sysdb.h"
#include "sss_iface/sss_iface_async.h"

static DBusMessage *
sss_dp_get_sudoers_msg(TALLOC_CTX *mem_ctx,
                       const char *bus_name,
                       struct sss_domain_info *dom,
                       bool fast_reply,
                       enum sss_dp_sudo_type type,
                       const char *name,
                       uint32_t num_rules,
                       struct sysdb_attrs **rules)
{
    DBusMessage *msg;
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    dbus_bool_t dbret;
    errno_t ret;
    uint32_t be_type = 0;
    uint32_t dp_flags = 0;
    const char *rule_name = NULL;
    uint32_t i;

    switch (type) {
        case SSS_DP_SUDO_REFRESH_RULES:
            be_type = BE_REQ_SUDO_RULES;
            break;
        case SSS_DP_SUDO_FULL_REFRESH:
            be_type = BE_REQ_SUDO_FULL;
            break;
    }

    if (fast_reply) {
        dp_flags |= DP_FAST_REPLY;
    }

    msg = dbus_message_new_method_call(bus_name,
                                       SSS_BUS_PATH,
                                       "sssd.dataprovider",
                                       "sudoHandler");
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        return NULL;
    }

    /* create the message */
    DEBUG(SSSDBG_TRACE_FUNC,
          "Creating SUDOers request for [%s][%u][%s][%u]\n",
           dom->name, be_type, name, num_rules);

    dbus_message_iter_init_append(msg, &iter);

    dbret = dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &dp_flags);
    if (dbret == FALSE) {
        goto fail;
    }

    /* BE TYPE */
    dbret = dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &be_type);
    if (dbret == FALSE) {
        goto fail;
    }

    /* BE TYPE SPECIFIC */
    if (be_type & BE_REQ_SUDO_RULES) {
        dbret = dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32,
                                               &num_rules);
        if (dbret == FALSE) {
            goto fail;
        }

        dbret = dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                                 DBUS_TYPE_STRING_AS_STRING,
                                                 &array_iter);
        if (dbret == FALSE) {
            goto fail;
        }

        for (i = 0; i < num_rules; i++) {
            ret = sysdb_attrs_get_string(rules[i], SYSDB_NAME, &rule_name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Could not get rule name [%d]: %s\n",
                      ret, strerror(ret));
                goto fail;
            }

            dbret = dbus_message_iter_append_basic(&array_iter,
                                                   DBUS_TYPE_STRING,
                                                   &rule_name);
            if (dbret == FALSE) {
                goto fail;
            }
        }

        dbret = dbus_message_iter_close_container(&iter, &array_iter);
        if (dbret == FALSE) {
            goto fail;
        }
    }

    return msg;

fail:
    DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build message\n");
    dbus_message_unref(msg);
    return NULL;
}

struct sss_dp_get_sudoers_state {
    uint16_t dp_error;
    uint32_t error;
    const char *error_message;
};

static void sss_dp_get_sudoers_done(struct tevent_req *subreq);

struct tevent_req *
sss_dp_get_sudoers_send(TALLOC_CTX *mem_ctx,
                        struct resp_ctx *rctx,
                        struct sss_domain_info *dom,
                        bool fast_reply,
                        enum sss_dp_sudo_type type,
                        const char *name,
                        uint32_t num_rules,
                        struct sysdb_attrs **rules)
{
    struct sss_dp_get_sudoers_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    DBusMessage *msg;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sss_dp_get_sudoers_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    if (rctx->sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
            "BUG: The D-Bus connection is not available!\n");
        ret = EIO;
        goto done;
    }

    msg = sss_dp_get_sudoers_msg(state, dom->conn_name, dom, fast_reply,
                                 type, name, num_rules, rules);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    subreq = sbus_call_dp_dp_sudoHandler_send(state, rctx->sbus_conn, msg);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sss_dp_get_sudoers_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, rctx->ev);
    }

    return req;
}

static void sss_dp_get_sudoers_done(struct tevent_req *subreq)
{
    struct sss_dp_get_sudoers_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_dp_get_sudoers_state);

    ret = sbus_call_dp_dp_sudoHandler_recv(state, subreq, &state->dp_error,
                                           &state->error,
                                           &state->error_message);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
sss_dp_get_sudoers_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        uint16_t *_dp_error,
                        uint32_t *_error,
                        const char ** _error_message)
{
    struct sss_dp_get_sudoers_state *state;
    state = tevent_req_data(req, struct sss_dp_get_sudoers_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_dp_error = state->dp_error;
    *_error = state->error;
    *_error_message = talloc_steal(mem_ctx, state->error_message);

    return EOK;
}
