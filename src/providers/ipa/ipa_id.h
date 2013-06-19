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

void ipa_account_info_handler(struct be_req *breq);
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

void ipa_check_online(struct be_req *be_req);

struct tevent_req *ipa_s2n_get_acct_info_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct sdap_options *opts,
                                              struct sss_domain_info *dom,
                                              struct sdap_handle *sh,
                                              int entry_type,
                                              struct req_input *req_input);
int ipa_s2n_get_acct_info_recv(struct tevent_req *req);

struct tevent_req *ipa_get_subdom_acct_send(TALLOC_CTX *memctx,
                                            struct tevent_context *ev,
                                            struct sdap_id_ctx *ctx,
                                            struct be_acct_req *ar);
int ipa_get_subdom_acct_recv(struct tevent_req *req, int *dp_error_out);

struct tevent_req *ipa_get_ad_acct_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct ipa_id_ctx *ipa_ctx,
                                        struct be_req *be_req,
                                        struct be_acct_req *ar);

errno_t ipa_get_ad_acct_recv(struct tevent_req *req, int *dp_error_out);

#endif
