/*
    SSSD

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#ifndef AD_PAC_H_
#define AD_PAC_H_

#include <stdbool.h>
#include <stdint.h>
/* ldb_val is defined as datablob in the Samba header files data_blob.h which
 * is included via ndr.h -> samba_util.h -> data_blob.h.
 * To allow proper type checking we have to make sure to keep the original
 * definition from ldb.h */
#ifdef ldb_val
#error Please make sure to include ad_pac.h before ldb.h
#endif
#include <ndr.h>
#include <gen_ndr/krb5pac.h>
#include <gen_ndr/ndr_krb5pac.h>
#undef ldb_val

#include "util/util.h"
#include "providers/ldap/ldap_common.h"

errno_t check_if_pac_is_available(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *dom,
                                  struct dp_id_data *ar,
                                  struct ldb_message **_msg);

errno_t ad_get_data_from_pac(TALLOC_CTX *mem_ctx, const uint32_t pac_check_opts,
                             uint8_t *pac_blob, size_t pac_len,
                             struct PAC_LOGON_INFO **_logon_info,
                             struct PAC_UPN_DNS_INFO **_upn_dns_info);

errno_t ad_get_sids_from_pac(TALLOC_CTX *mem_ctx,
                             struct sss_idmap_ctx *idmap_ctx,
                             struct PAC_LOGON_INFO *logon_info,
                             char **_user_sid_str,
                             char **_primary_group_sid_str,
                             size_t *_num_sids,
                             char *** _sid_list);

errno_t ad_get_pac_data_from_user_entry(TALLOC_CTX *mem_ctx,
                                        struct ldb_message *msg,
                                        struct sss_idmap_ctx *idmap_ctx,
                                        char **username,
                                        char **user_sid,
                                        char **primary_group_sid,
                                        size_t *num_sids,
                                        char ***group_sids);

struct tevent_req *ad_handle_pac_initgr_send(TALLOC_CTX *mem_ctx,
                                             struct be_ctx *be_ctx,
                                             struct dp_id_data *ar,
                                             struct sdap_id_ctx *id_ctx,
                                             struct sdap_domain *sdom,
                                             struct sdap_id_conn_ctx *conn,
                                             bool noexist_delete,
                                             struct ldb_message *msg);

errno_t ad_handle_pac_initgr_recv(struct tevent_req *req,
                                  int *_dp_error, const char **_err,
                                  int *sdap_ret);

errno_t check_upn_and_sid_from_user_and_pac(struct ldb_message *msg,
                                          struct sss_idmap_ctx *ctx,
                                          struct PAC_UPN_DNS_INFO *upn_dns_info,
                                          const uint32_t pac_check_opts);
#endif /* AD_PAC_H_ */
