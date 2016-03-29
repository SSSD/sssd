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

#ifndef _IPA_HOSTID_H_
#define _IPA_HOSTID_H_

struct ipa_hostid_ctx {
    struct sdap_id_ctx *sdap_id_ctx;
    struct ipa_options *ipa_opts;

    struct sdap_search_base **host_search_bases;
};

struct tevent_req *
ipa_hostid_handler_send(TALLOC_CTX *mem_ctx,
                       struct ipa_hostid_ctx *hostid_ctx,
                       struct dp_hostid_data *data,
                       struct dp_req_params *params);

errno_t
ipa_hostid_handler_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct dp_reply_std *data);

#endif /* _IPA_HOSTID_H_ */
