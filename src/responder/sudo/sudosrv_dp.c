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
#include "db/sysdb.h"

struct sss_dp_get_sudoers_info {
    struct sss_domain_info *dom;

    bool fast_reply;
    enum sss_dp_sudo_type type;
    const char *name;
    size_t num_rules;
    struct sysdb_attrs **rules;
};

static DBusMessage *
sss_dp_get_sudoers_msg(void *pvt);

struct tevent_req *
sss_dp_get_sudoers_send(TALLOC_CTX *mem_ctx,
                        struct resp_ctx *rctx,
                        struct sss_domain_info *dom,
                        bool fast_reply,
                        enum sss_dp_sudo_type type,
                        const char *name,
                        size_t num_rules,
                        struct sysdb_attrs **rules)
{
    struct tevent_req *req;
    struct sss_dp_req_state *state;
    struct sss_dp_get_sudoers_info *info;
    errno_t ret;
    char *key = NULL;

    req = tevent_req_create(mem_ctx, &state, struct sss_dp_req_state);
    if (!req) {
        ret = ENOMEM;
        goto error;
    }

    if (!dom) {
        ret = EINVAL;
        goto error;
    }

    info = talloc_zero(state, struct sss_dp_get_sudoers_info);
    info->fast_reply = fast_reply;
    info->type = type;
    info->name = name;
    info->dom = dom;
    info->num_rules = num_rules;
    info->rules = rules;

    switch (info->type) {
        case SSS_DP_SUDO_REFRESH_RULES:
            key = talloc_asprintf(state, "%d:%u:%s@%s", type,
                                  (unsigned int)num_rules, name, dom->name);
            break;
        case SSS_DP_SUDO_FULL_REFRESH:
            key = talloc_asprintf(state, "%d:%s", type, dom->name);
            break;
    }

    if (!key) {
        ret = ENOMEM;
        goto error;
    }

    ret = sss_dp_issue_request(state, rctx, key, dom, sss_dp_get_sudoers_msg,
                               info, req);
    talloc_free(key);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not issue DP request [%d]: %s\n",
               ret, strerror(ret)));
        goto error;
    }

    return req;

error:
    tevent_req_error(req, ret);
    tevent_req_post(req, rctx->ev);
    return req;
}

static DBusMessage *
sss_dp_get_sudoers_msg(void *pvt)
{
    DBusMessage *msg;
    DBusMessageIter iter;
    dbus_bool_t dbret;
    errno_t ret;
    struct sss_dp_get_sudoers_info *info;
    uint32_t be_type = 0;
    const char *rule_name = NULL;
    int i;

    info = talloc_get_type(pvt, struct sss_dp_get_sudoers_info);

    switch (info->type) {
        case SSS_DP_SUDO_REFRESH_RULES:
            be_type = BE_REQ_SUDO_RULES;
            break;
        case SSS_DP_SUDO_FULL_REFRESH:
            be_type = BE_REQ_SUDO_FULL;
            break;
    }

    if (info->fast_reply) {
        be_type |= BE_REQ_FAST;
    }

    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DP_INTERFACE,
                                       DP_METHOD_SUDOHANDLER);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory?!\n"));
        return NULL;
    }

    /* create the message */
    DEBUG(SSSDBG_TRACE_FUNC,
          ("Creating SUDOers request for [%s][%u][%s][%u]\n",
           info->dom->name, be_type, info->name, (unsigned int)info->num_rules));

    dbus_message_iter_init_append(msg, &iter);

    /* BE TYPE */
    dbret = dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &be_type);
    if (dbret == FALSE) {
        goto fail;
    }

    /* BE TYPE SPECIFIC */
    if (be_type & BE_REQ_SUDO_RULES) {
        dbret = dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32,
                                               &info->num_rules);
        if (dbret == FALSE) {
            goto fail;
        }

        for (i = 0; i < info->num_rules; i++) {
            ret = sysdb_attrs_get_string(info->rules[i], SYSDB_NAME, &rule_name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("Could not get rule name [%d]: %s\n",
                      ret, strerror(ret)));
                goto fail;
            }

            dbret = dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING,
                                                   &rule_name);
            if (dbret == FALSE) {
                goto fail;
            }
        }
    }

    return msg;

fail:
    DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to build message\n"));
    dbus_message_unref(msg);
    return NULL;
}

errno_t
sss_dp_get_sudoers_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        dbus_uint16_t *dp_err,
                        dbus_uint32_t *dp_ret,
                        char **err_msg)
{
    return sss_dp_req_recv(mem_ctx, req, dp_err, dp_ret, err_msg);
}
