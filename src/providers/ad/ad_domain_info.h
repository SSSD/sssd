/*
    SSSD

    AD Master Domain Module

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#ifndef _AD_DOMAIN_INFO_H_
#define _AD_DOMAIN_INFO_H_

struct tevent_req *
ad_domain_info_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct sdap_id_conn_ctx *conn,
                      struct sdap_id_op *op,
                      const char *dom_name);

errno_t
ad_domain_info_recv(struct tevent_req *req,
                      TALLOC_CTX *mem_ctx,
                      char **_flat,
                      char **_id,
                      char **_site,
                      char **_forest);
#endif /* _AD_DOMAIN_INFO_H_ */
