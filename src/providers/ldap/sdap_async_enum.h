/*
    SSSD

    LDAP Enumeration Module

    Authors:
        Simo Sorce <ssorce@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

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

#ifndef _SDAP_ASYNC_ENUM_H_
#define _SDAP_ASYNC_ENUM_H_

struct tevent_req *
sdap_dom_enum_ex_send(TALLOC_CTX *memctx,
                      struct tevent_context *ev,
                      struct sdap_id_ctx *ctx,
                      struct sdap_domain *sdom,
                      struct sdap_id_conn_ctx *user_conn,
                      struct sdap_id_conn_ctx *group_conn,
                      struct sdap_id_conn_ctx *svc_conn);

errno_t sdap_dom_enum_ex_recv(struct tevent_req *req);

struct tevent_req *
sdap_dom_enum_send(TALLOC_CTX *memctx,
                   struct tevent_context *ev,
                   struct sdap_id_ctx *ctx,
                   struct sdap_domain *sdom,
                   struct sdap_id_conn_ctx *conn);

errno_t sdap_dom_enum_recv(struct tevent_req *req);

#endif /* _SDAP_ASYNC_ENUM_H_ */
