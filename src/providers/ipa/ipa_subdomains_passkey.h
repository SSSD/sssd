/*
    SSSD

    IPA Subdomains Passkey Module

    Authors:
        Justin Stephenson

    Copyright (C) 2022 Red Hat

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

#ifndef _IPA_SUBDOMAINS_PASSKEY_H_
#define _IPA_SUBDOMAINS_PASSKEY_H_

#include "providers/backend.h"
#include "providers/ipa/ipa_common.h"
#include "config.h"

struct ipa_subdomains_passkey_state {
    struct sss_domain_info *domain;
    struct sdap_options *sdap_opts;
};

struct tevent_req *
ipa_subdomains_passkey_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct ipa_subdomains_ctx *sd_ctx,
                            struct sdap_handle *sh);

errno_t ipa_subdomains_passkey_recv(struct tevent_req *req);

#endif /* _IPA_SUBDOMAINS_PASSKEY_H_ */
