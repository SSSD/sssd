/*
    SSSD

    IPA Backend Module -- selinux loading

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

#ifndef _IPA_SELINUX_H_
#define _IPA_SELINUX_H_

#include "providers/ldap/ldap_common.h"

struct ipa_selinux_ctx {
    struct ipa_id_ctx *id_ctx;
    time_t last_update;

    struct sdap_search_base **selinux_search_bases;
    struct sdap_search_base **host_search_bases;
    struct sdap_search_base **hbac_search_bases;
};

struct tevent_req *
ipa_selinux_handler_send(TALLOC_CTX *mem_ctx,
                         struct ipa_selinux_ctx *selinux_ctx,
                         struct pam_data *pd,
                         struct dp_req_params *params);

errno_t
ipa_selinux_handler_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         struct pam_data **_data);

#endif
