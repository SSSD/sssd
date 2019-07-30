/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>

    Copyright (C) 2019 SUSE LINUX GmbH, Nuernberg, Germany.

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

#include "providers/proxy/proxy.h"

struct proxy_hosts_handler_state {
    int dummy;
};

struct tevent_req *
proxy_hosts_handler_send(TALLOC_CTX *mem_ctx,
                      struct proxy_resolver_ctx *proxy_resolver_ctx,
                      struct dp_resolver_data *resolver_data,
                      struct dp_req_params *params)
{
    struct proxy_hosts_handler_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state, struct proxy_hosts_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    /* TODO */
    tevent_req_done(req);
    return tevent_req_post(req, params->ev);
}

errno_t
proxy_hosts_handler_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         struct dp_reply_std *data)
{
    struct proxy_hosts_handler_state *state;

    state = tevent_req_data(req, struct proxy_hosts_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    /* TODO */

    return EOK;
}
