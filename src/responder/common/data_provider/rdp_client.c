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

#include "responder/common/data_provider/rdp.h"
#include "util/util.h"

static void rdp_register_client_done(struct tevent_req *req);

errno_t rdp_register_client(struct be_conn *be_conn,
                            const char *client_name)
{
    struct tevent_req *req;

    req = rdp_message_send(be_conn, be_conn->rctx, be_conn->domain,
                           DP_PATH, IFACE_DP_CLIENT, IFACE_DP_CLIENT_REGISTER,
                           DBUS_TYPE_STRING, &client_name);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, rdp_register_client_done, NULL);

    return EOK;
}

static void rdp_register_client_done(struct tevent_req *req)
{
    errno_t ret;

    ret = rdp_message_recv(req);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to register client with DP\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Client is registered with DP\n");
}
