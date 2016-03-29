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

#include "sbus/sssd_dbus.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/backend.h"
#include "util/util.h"

static errno_t dp_sudo_parse_message(TALLOC_CTX *mem_ctx,
                                     DBusMessage *msg,
                                     uint32_t *_dp_flags,
                                     uint32_t *_sudo_type,
                                     char ***_rules)
{
    DBusError error;
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    uint32_t dp_flags;
    uint32_t sudo_type;
    uint32_t num_rules;
    const char *rule;
    char **rules = NULL;
    uint32_t i;
    errno_t ret;

    dbus_error_init(&error);
    dbus_message_iter_init(msg, &iter);

    /* get dp flags */
    if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed, to parse the message!\n");
        ret = EIO;
        goto done;
    }

    dbus_message_iter_get_basic(&iter, &dp_flags);
    dbus_message_iter_next(&iter); /* step behind the request type */

    /* get type of the request */
    if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed, to parse the message!\n");
        ret = EIO;
        goto done;
    }

    dbus_message_iter_get_basic(&iter, &sudo_type);
    dbus_message_iter_next(&iter); /* step behind the request type */

    /* get additional arguments according to the request type */
    switch (sudo_type) {
    case BE_REQ_SUDO_FULL:
        /* no arguments required */
        break;
    case BE_REQ_SUDO_RULES:
        /* additional arguments:
         * rules_num
         * rules[rules_num]
         */
        /* read rules_num */
        if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed, to parse the message!\n");
            ret = EIO;
            goto done;
        }

        dbus_message_iter_get_basic(&iter, &num_rules);

        rules = talloc_zero_array(mem_ctx, char *, num_rules + 1);
        if (rules == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_array() failed.\n");
            ret = ENOMEM;
            goto done;
        }

        dbus_message_iter_next(&iter);

        if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
           DEBUG(SSSDBG_CRIT_FAILURE, "Failed, to parse the message!\n");
            ret = EIO;
            goto done;
        }

        dbus_message_iter_recurse(&iter, &array_iter);

        /* read the rules */
       for (i = 0; i < num_rules; i++) {
            if (dbus_message_iter_get_arg_type(&array_iter)
                    != DBUS_TYPE_STRING) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Failed, to parse the message!\n");
                ret = EIO;
                goto done;
            }

            dbus_message_iter_get_basic(&array_iter, &rule);
            rules[i] = talloc_strdup(rules, rule);
            if (rules[i] == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed.\n");
                ret = ENOMEM;
                goto done;
            }

            dbus_message_iter_next(&array_iter);
        }

        rules[num_rules] = NULL;

        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request type %d\n", sudo_type);
        return EINVAL;
    }

    *_dp_flags = dp_flags;
    *_sudo_type = sudo_type;
    *_rules = rules;

    ret = EOK;

done:
   if (ret != EOK) {
        talloc_free(rules);
    }

    return ret;
}

static const char *dp_sudo_get_key(uint32_t type)
{
    switch (type) {
    case BE_REQ_SUDO_FULL:
        return "full-refresh";
    case BE_REQ_SUDO_RULES:
        return NULL;
    }

    return NULL;
}

static const char *dp_sudo_get_name(uint32_t type)
{
    switch (type) {
    case BE_REQ_SUDO_FULL:
        return "SUDO Full Refresh";
    case BE_REQ_SUDO_RULES:
        return "SUDO Rules Refresh";
    }

    return NULL;
}

errno_t dp_sudo_handler(struct sbus_request *sbus_req, void *dp_cli)
{
    struct dp_sudo_data *data;
    uint32_t dp_flags;
    const char *key;
    const char *name;
    errno_t ret;

    data = talloc_zero(sbus_req, struct dp_sudo_data);
    if (data == NULL) {
        return ENOMEM;
    }

    ret = dp_sudo_parse_message(data, sbus_req->message, &dp_flags,
                                &data->type, &data->rules);
    if (ret != EOK) {
        return ret;
    }

    key = dp_sudo_get_key(data->type);
    name = dp_sudo_get_name(data->type);

    dp_req_with_reply(dp_cli, NULL, name, key, sbus_req, DPT_SUDO,
                      DPM_SUDO_HANDLER, dp_flags, data,
                      dp_req_reply_std, struct dp_reply_std);

    return EOK;
}
