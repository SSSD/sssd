/*
    SSSD

    IPA Backend Module -- Authentication

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

#ifndef _IPA_AUTH_H_
#define _IPA_AUTH_H_

#include "providers/backend.h"
#include "providers/ipa/ipa_common.h"

struct tevent_req *
ipa_pam_auth_handler_send(TALLOC_CTX *mem_ctx,
                          struct ipa_auth_ctx *auth_ctx,
                          struct pam_data *pd,
                          struct dp_req_params *params);

errno_t
ipa_pam_auth_handler_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             struct pam_data **_data);

#endif /* _IPA_AUTH_H_ */
