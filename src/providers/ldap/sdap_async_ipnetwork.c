/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>

    Copyright (C) 2020 SUSE LINUX GmbH, Nuernberg, Germany.

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

#include "providers/ldap/sdap_async_private.h"

struct sdap_get_ipnetwork_state {
};

struct tevent_req *
sdap_get_ipnetwork_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sss_domain_info *dom,
                        struct sysdb_ctx *sysdb,
                        struct sdap_options *opts,
                        struct sdap_search_base **search_bases,
                        struct sdap_handle *sh,
                        const char **attrs,
                        const char *filter,
                        int timeout,
                        bool enumeration)
{
    struct sdap_get_ipnetwork_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_get_ipnetwork_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    /* TODO */

    tevent_req_done(req);
    return tevent_req_post(req, ev);
}

errno_t
sdap_get_ipnetwork_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        char **usn_value)
{
    /* TODO */

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
