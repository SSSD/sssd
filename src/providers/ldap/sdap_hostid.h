/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

    Copyright (C) 2012 Red Hat

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

#ifndef _SDAP_HOSTID_H_
#define _SDAP_HOSTID_H_

errno_t sdap_hostid_init(TALLOC_CTX *mem_ctx,
                         struct be_ctx *be_ctx,
                         struct sdap_id_ctx *id_ctx,
                         struct dp_method *dp_methods);

struct tevent_req *
sdap_hostid_handler_send(TALLOC_CTX *mem_ctx,
                         struct sdap_id_ctx *id_ctx,
                         struct dp_hostid_data *data,
                         struct dp_req_params *params);

errno_t
sdap_hostid_handler_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         struct dp_reply_std *data);

#endif /* _SDAP_HOSTID_H_ */
