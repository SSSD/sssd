/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    InfoPipe responder: the responder commands

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

#include "responder/ifp/ifp_private.h"

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version ssh_cli_protocol_version[] = {
        {0, NULL, NULL}
    };

    return ssh_cli_protocol_version;
}

/* This is a throwaway method to ease the review of the patch.
 * It will be removed later */
int ifp_ping(struct sbus_request *dbus_req, void *data)
{
    struct ifp_ctx *ifp_ctx = talloc_get_type(data, struct ifp_ctx);
    static const char *pong = "PONG";
    const char *request;
    DBusError dberr;
    errno_t ret;
    struct ifp_req *ifp_req;

    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
    }

    ret = ifp_req_create(dbus_req, ifp_ctx, &ifp_req);
    if (ret != EOK) {
        return ifp_req_create_handle_failure(dbus_req, ret);
    }

    if (!sbus_request_parse_or_finish(dbus_req,
                                      DBUS_TYPE_STRING, &request,
                                      DBUS_TYPE_INVALID)) {
        return EOK; /* handled */
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Got request for [%s]\n", request);

    if (strcasecmp(request, "ping") != 0) {
        dbus_error_init(&dberr);
        dbus_set_error_const(&dberr,
                             DBUS_ERROR_INVALID_ARGS,
                             "Ping() only accepts ping as a param\n");
        return sbus_request_fail_and_finish(dbus_req, &dberr);
    }

    return sbus_request_return_and_finish(dbus_req,
                                          DBUS_TYPE_STRING, &pong,
                                          DBUS_TYPE_INVALID);
}
