/*
    SSSD

    IPA Identity Backend Module

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

    Copyright (C) 2011 Red Hat

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


#ifndef _IPA_ID_H_
#define _IPA_ID_H_

#include "providers/ldap/ldap_common.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ipa/ipa_subdomains.h"

#define IPA_DEFAULT_VIEW_NAME "Default Trust View"

struct tevent_req *
ipa_account_info_send(TALLOC_CTX *mem_ctx,
                      struct be_ctx *be_ctx,
                      struct ipa_id_ctx *id_ctx,
                      struct dp_id_data *data);
errno_t ipa_account_info_recv(struct tevent_req *req,
                              int *_dp_error);

struct tevent_req *
ipa_account_info_handler_send(TALLOC_CTX *mem_ctx,
                              struct ipa_id_ctx *id_ctx,
                              struct dp_id_data *data,
                              struct dp_req_params *params);

errno_t ipa_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct dp_reply_std *data);

struct tevent_req *ipa_get_netgroups_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sysdb_ctx *sysdb,
                                          struct sss_domain_info *dom,
                                          struct sdap_options *opts,
                                          struct ipa_options *ipa_options,
                                          struct sdap_handle *sh,
                                          const char **attrs,
                                          const char *filter,
                                          int timeout);

int ipa_get_netgroups_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           size_t *reply_count,
                           struct sysdb_attrs ***reply);

struct tevent_req *ipa_s2n_get_acct_info_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct ipa_id_ctx *ipa_ctx,
                                             struct sdap_options *opts,
                                             struct sss_domain_info *dom,
                                             struct sysdb_attrs *override_attrs,
                                             struct sdap_handle *sh,
                                             int entry_type,
                                             struct req_input *req_input);
int ipa_s2n_get_acct_info_recv(struct tevent_req *req);

struct tevent_req *ipa_get_subdom_acct_send(TALLOC_CTX *memctx,
                                            struct tevent_context *ev,
                                            struct ipa_id_ctx *ipa_ctx,
                                            struct sysdb_attrs *override_attrs,
                                            struct dp_id_data *ar);
int ipa_get_subdom_acct_recv(struct tevent_req *req, int *dp_error_out);

errno_t get_dp_id_data_for_sid(TALLOC_CTX *mem_ctx, const char *sid,
                                const char *domain_name,
                                struct dp_id_data **_ar);

errno_t get_dp_id_data_for_uuid(TALLOC_CTX *mem_ctx, const char *uuid,
                                 const char *domain_name,
                                 struct dp_id_data **_ar);

errno_t get_dp_id_data_for_user_name(TALLOC_CTX *mem_ctx,
                                      const char *user_name,
                                      const char *domain_name,
                                      struct dp_id_data **_ar);

struct tevent_req *ipa_get_trusted_override_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct sdap_id_ctx *sdap_id_ctx,
                                                 struct ipa_options *ipa_options,
                                                 const char *ipa_realm,
                                                 const char *view_name,
                                                 struct dp_id_data *ar);

errno_t ipa_get_trusted_override_recv(struct tevent_req *req, int *dp_error_out,
                                      TALLOC_CTX *mem_ctx,
                                      struct sysdb_attrs **override_attrs);

struct tevent_req *ipa_subdomain_account_send(TALLOC_CTX *memctx,
                                              struct tevent_context *ev,
                                              struct ipa_id_ctx *ipa_ctx,
                                              struct dp_id_data *ar);

errno_t ipa_subdomain_account_recv(struct tevent_req *req, int *dp_error_out);

errno_t split_ipa_anchor(TALLOC_CTX *mem_ctx, const char *anchor,
                         char **_anchor_domain, char **_ipa_uuid);

errno_t get_object_from_cache(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *dom,
                              struct dp_id_data *ar,
                              struct ldb_message **_msg);

struct tevent_req *
ipa_initgr_get_overrides_send(TALLOC_CTX *memctx,
                             struct tevent_context *ev,
                             struct ipa_id_ctx *ipa_ctx,
                             struct sss_domain_info *user_dom,
                             size_t groups_count,
                             struct ldb_message **groups,
                             const char *groups_id_attr);
int ipa_initgr_get_overrides_recv(struct tevent_req *req, int *dp_error);

struct tevent_req *ipa_get_subdom_acct_process_pac_send(TALLOC_CTX *mem_ctx,
                                                   struct tevent_context *ev,
                                                   struct sdap_handle *sh,
                                                   struct ipa_id_ctx *ipa_ctx,
                                                   struct sss_domain_info *dom,
                                                   struct ldb_message *user_msg);

errno_t ipa_get_subdom_acct_process_pac_recv(struct tevent_req *req);

struct tevent_req *
ipa_resolve_user_list_send(TALLOC_CTX *memctx, struct tevent_context *ev,
                           struct ipa_id_ctx *ipa_ctx,
                           const char *domain_name,
                           struct ldb_message_element *users);
int ipa_resolve_user_list_recv(struct tevent_req *req, int *dp_error);

struct tevent_req *
ipa_id_get_account_info_send(TALLOC_CTX *memctx, struct tevent_context *ev,
                             struct ipa_id_ctx *ipa_ctx,
                             struct dp_id_data *ar);
int ipa_id_get_account_info_recv(struct tevent_req *req, int *dp_error);
#endif
