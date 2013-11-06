/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2013 Red Hat

    InfoPipe responder: Utility functions

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

#include "db/sysdb.h"
#include "responder/ifp/ifp_private.h"

errno_t ifp_req_create(struct sbus_request *dbus_req,
                       struct ifp_ctx *ifp_ctx,
                       struct ifp_req **_ifp_req)
{
    struct ifp_req *ireq = NULL;
    errno_t ret;

    if (ifp_ctx->sysbus == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Responder not connected to sysbus!\n");
        return EINVAL;
    }

    ireq = talloc_zero(dbus_req, struct ifp_req);
    if (ireq == NULL) {
        return ENOMEM;
    }

    ireq->ifp_ctx = ifp_ctx;
    ireq->dbus_req = dbus_req;

    if (dbus_req->client == -1) {
        /* We got a sysbus message but couldn't identify the
         * caller? Bail out! */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "BUG: Received a message without a known caller!\n");
        ret = EACCES;
        goto done;
    }

    ret = check_allowed_uids(dbus_req->client,
                             ifp_ctx->rctx->allowed_uids_count,
                             ifp_ctx->rctx->allowed_uids);
    if (ret == EACCES) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "User %"PRIi64" not in ACL\n", dbus_req->client);
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot check if user %"PRIi64" is present in ACL\n",
              dbus_req->client);
        goto done;
    }

    *_ifp_req = ireq;
    ret = EOK;
done:
    if (ret != EOK) {
        talloc_free(ireq);
    }
    return ret;
}

int ifp_req_create_handle_failure(struct sbus_request *dbus_req, errno_t err)
{
    if (err == EACCES) {
        return sbus_request_fail_and_finish(dbus_req,
                               sbus_error_new(dbus_req,
                                              DBUS_ERROR_ACCESS_DENIED,
                                              "User %"PRIi64" not in ACL\n",
                                              dbus_req->client));
    }

    return sbus_request_fail_and_finish(dbus_req,
                                        sbus_error_new(dbus_req,
                                            DBUS_ERROR_FAILED,
                                            "Cannot create IFP request\n"));
}

const char *ifp_path_strip_prefix(const char *path, const char *prefix)
{
    if (strncmp(path, prefix, strlen(prefix)) == 0) {
        return path + strlen(prefix);
    }

    return NULL;
}

errno_t ifp_add_ldb_el_to_dict(DBusMessageIter *iter_dict,
                               struct ldb_message_element *el)
{
    DBusMessageIter iter_dict_entry;
    DBusMessageIter iter_dict_val;
    DBusMessageIter iter_array;
    dbus_bool_t dbret;
    unsigned int i;

    if (el == NULL) {
        return EINVAL;
    }

    dbret = dbus_message_iter_open_container(iter_dict,
                                             DBUS_TYPE_DICT_ENTRY, NULL,
                                             &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    /* Start by appending the key */
    dbret = dbus_message_iter_append_basic(&iter_dict_entry,
                                           DBUS_TYPE_STRING, &(el->name));
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_open_container(&iter_dict_entry,
                                             DBUS_TYPE_VARIANT,
                                             DBUS_TYPE_ARRAY_AS_STRING
                                             DBUS_TYPE_STRING_AS_STRING,
                                             &iter_dict_val);
    if (!dbret) {
        return ENOMEM;
    }

    /* Open container for values */
    dbret = dbus_message_iter_open_container(&iter_dict_val,
                                 DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING,
                                 &iter_array);
    if (!dbret) {
        return ENOMEM;
    }

    /* Now add all the values */
    for (i = 0; i < el->num_values; i++) {
        DEBUG(SSSDBG_TRACE_FUNC, "element [%s] has value [%s]\n",
              el->name, (const char *) el->values[i].data);

        dbret = dbus_message_iter_append_basic(&iter_array,
                                               DBUS_TYPE_STRING,
                                               &(el->values[i].data));
        if (!dbret) {
            return ENOMEM;
        }
    }

    dbret = dbus_message_iter_close_container(&iter_dict_val,
                                              &iter_array);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(&iter_dict_entry,
                                              &iter_dict_val);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(iter_dict,
                                              &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    return EOK;
}
