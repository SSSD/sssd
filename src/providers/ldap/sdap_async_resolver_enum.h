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

#ifndef _SDAP_ASYNC_RESOLVER_ENUM_H_
#define _SDAP_ASYNC_RESOLVER_ENUM_H_

struct tevent_req *
sdap_dom_resolver_enum_send(TALLOC_CTX *memctx,
                            struct tevent_context *ev,
                            struct sdap_resolver_ctx *resolver_ctx,
                            struct sdap_id_ctx *id_ctx,
                            struct sdap_domain *sdom,
                            struct sdap_id_conn_ctx *conn);

errno_t sdap_dom_resolver_enum_recv(struct tevent_req *req);

#endif /* _SDAP_ASYNC_RESOLVER_ENUM_H_ */
