/*
    SSSD

    minimal Identity Backend Module

    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Copyright (C) 2025 Red Hat

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


#ifndef _MINIMAL_ID_H_
#define _MINIMAL_ID_H_

#include "config.h"
#include <stdbool.h>

#include "providers/backend.h"
#include "providers/ldap/ldap_common.h"
#include "util/util.h"

struct minimal_id_ctx {
    struct be_ctx *be_ctx;
    struct minimal_init_ctx *init_ctx;
    struct dp_option *minimal_options;
};

struct tevent_req *
minimal_account_info_handler_send(TALLOC_CTX *mem_ctx,
                              struct sdap_id_ctx *id_ctx,
                              struct dp_id_data *data,
                              struct dp_req_params *params);

errno_t minimal_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct dp_reply_std *data);
#endif
