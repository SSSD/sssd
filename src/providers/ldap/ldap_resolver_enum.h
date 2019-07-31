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

#ifndef LDAP_RESOLVER_ENUM_H_
#define LDAP_RESOLVER_ENUM_H_

errno_t ldap_resolver_setup_tasks(struct be_ctx *be_ctx,
                                  struct sdap_resolver_ctx *ctx,
                                  be_ptask_send_t send_fn,
                                  be_ptask_recv_t recv_fn);

struct tevent_req *
ldap_resolver_enumeration_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct be_ctx *be_ctx,
                               struct be_ptask *be_ptask,
                               void *pvt);

errno_t
ldap_resolver_enumeration_recv(struct tevent_req *req);

errno_t
ldap_resolver_cleanup(struct sdap_resolver_ctx *ctx);

#endif /* LDAP_RESOLVER_ENUM_H_ */
