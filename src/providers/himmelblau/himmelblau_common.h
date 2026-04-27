/*
    SSSD

    Himmelblau Provider - Common definitions

    Authors:
        David Mulder <dmulder@suse.com>

    Copyright (C) 2026 SUSE

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

#ifndef _HIMMELBLAU_COMMON_H_
#define _HIMMELBLAU_COMMON_H_

#include "providers/data_provider/dp.h"
#include "providers/backend.h"

/* Context structures */
struct himmelblau_init_ctx {
    struct be_ctx *be_ctx;
    struct dp_option *opts;

    char *domain;
    char *device_storage_path;

    struct himmelblau_auth_ctx *auth_ctx;
    struct himmelblau_id_ctx *id_ctx;
};

struct himmelblau_auth_ctx {
    struct be_ctx *be_ctx;
    struct himmelblau_init_ctx *init_ctx;

    char *domain;
    char *device_storage_path;
};

struct himmelblau_id_ctx {
    struct be_ctx *be_ctx;
    struct himmelblau_init_ctx *init_ctx;

    char *domain;
};

/* Auth handler (himmelblau_auth.c) */
struct tevent_req *
himmelblau_pam_handler_send(TALLOC_CTX *mem_ctx,
                           struct himmelblau_auth_ctx *auth_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params);

errno_t
himmelblau_pam_handler_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           struct pam_data **_data);

/* ID handler (himmelblau_id.c) */
struct tevent_req *
himmelblau_account_info_handler_send(TALLOC_CTX *mem_ctx,
                                    struct himmelblau_id_ctx *id_ctx,
                                    struct dp_id_data *data,
                                    struct dp_req_params *params);

errno_t
himmelblau_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct dp_reply_std *data);

#endif /* _HIMMELBLAU_COMMON_H_ */
