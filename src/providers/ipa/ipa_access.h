/*
    SSSD

    IPA Backend Module -- Access control

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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

#ifndef _IPA_ACCESS_H_
#define _IPA_ACCESS_H_

#include "providers/ldap/ldap_common.h"

enum ipa_access_mode {
    IPA_ACCESS_DENY = 0,
    IPA_ACCESS_ALLOW
};

struct ipa_access_ctx {
    struct sdap_id_ctx *sdap_ctx;
    struct dp_option *ipa_options;
    time_t last_update;
    struct sdap_access_ctx *sdap_access_ctx;

    struct sdap_attr_map *host_map;
    struct sdap_attr_map *hostgroup_map;
    struct sdap_search_base **host_search_bases;
    struct sdap_search_base **hbac_search_bases;
};

struct hbac_ctx {
    struct be_ctx *be_ctx;
    struct dp_option *ipa_options;
    struct pam_data *pd;
    size_t rule_count;
    struct sysdb_attrs **rules;
};

struct tevent_req *
ipa_pam_access_handler_send(TALLOC_CTX *mem_ctx,
                           struct ipa_access_ctx *access_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params);

errno_t
ipa_pam_access_handler_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             struct pam_data **_data);

struct tevent_req *
ipa_refresh_access_rules_send(TALLOC_CTX *mem_ctx,
                              struct ipa_access_ctx *access_ctx,
                              void *no_input_data,
                              struct dp_req_params *params);

errno_t ipa_refresh_access_rules_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      void **_no_output_data);

#endif /* _IPA_ACCESS_H_ */
