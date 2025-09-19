/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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

#ifndef AD_ID_H_
#define AD_ID_H_

struct tevent_req *
ad_account_info_handler_send(TALLOC_CTX *mem_ctx,
                              struct ad_id_ctx *id_ctx,
                              struct dp_id_data *data,
                              struct dp_req_params *params);

errno_t ad_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct dp_reply_std *data);

struct tevent_req *
ad_account_info_send(TALLOC_CTX *mem_ctx,
                     struct be_ctx *be_ctx,
                     struct ad_id_ctx *id_ctx,
                     struct dp_id_data *data);

errno_t ad_account_info_recv(struct tevent_req *req,
                             int *_dp_error,
                             const char **_err_msg);

struct tevent_req *
ad_handle_acct_info_send(TALLOC_CTX *mem_ctx,
                         struct dp_id_data *ar,
                         struct sdap_id_ctx *ctx,
                         struct ad_options *ad_options,
                         struct sdap_domain *sdom,
                         struct sdap_id_conn_ctx **conn);
errno_t
ad_handle_acct_info_recv(struct tevent_req *req,
                         int *_dp_error, const char **_err);

struct tevent_req *
ad_get_account_domain_send(TALLOC_CTX *mem_ctx,
                           struct ad_id_ctx *id_ctx,
                           struct dp_get_acct_domain_data *data,
                           struct dp_req_params *params);

errno_t ad_get_account_domain_recv(TALLOC_CTX *mem_ctx,
                                   struct tevent_req *req,
                                   struct dp_reply_std *data);

#endif /* AD_ID_H_ */
