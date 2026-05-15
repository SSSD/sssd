/*
    SSSD

    IPA Backend Module -- Session Management

    Authors:
        Fabiano Fidêncio <fidencio@redhat.com>

    Copyright (C) 2017 Red Hat

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

#ifndef IPA_SESSION_H_
#define IPA_SESSION_H_

#include "providers/ldap/ldap_common.h"

struct ipa_session_ctx {
    struct sdap_id_ctx *sdap_ctx;
    struct dp_option *ipa_options;
    time_t last_update;
    time_t last_request;
    bool no_rules_found;

    struct sdap_attr_map *host_map;
    struct sdap_attr_map *hostgroup_map;
    struct sdap_search_base **deskprofile_search_bases;
    struct sdap_search_base **host_search_bases;
};

struct tevent_req *
ipa_pam_session_handler_send(TALLOC_CTX *mem_ctx,
                             struct ipa_session_ctx *session_ctx,
                             struct pam_data *pd,
                             struct dp_req_params *params);

errno_t
ipa_pam_session_handler_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             struct pam_data **_data);

#endif /* IPA_SESSION_H_ */
