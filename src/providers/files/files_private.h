/*
    SSSD

    Files provider declarations

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

#ifndef __FILES_PRIVATE_H_
#define __FILES_PRIVATE_H_

#include "config.h"

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <sys/types.h>
#include <nss.h>
#include <pwd.h>
#include <grp.h>

#include "providers/data_provider/dp.h"

struct files_id_ctx {
    struct be_ctx *be;
    struct sss_domain_info *domain;
    struct files_ctx *fctx;

    const char **passwd_files;
    const char **group_files;

    bool updating_passwd;
    bool updating_groups;

    struct tevent_req *users_req;
    struct tevent_req *groups_req;
    struct tevent_req *initgroups_req;
};

/* files_ops.c */
struct files_ctx *sf_init(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          const char **passwd_files,
                          const char **group_files,
                          struct files_id_ctx *id_ctx);

/* files_id.c */
struct tevent_req *
files_account_info_handler_send(TALLOC_CTX *mem_ctx,
                               struct files_id_ctx *id_ctx,
                               struct dp_id_data *data,
                               struct dp_req_params *params);

errno_t files_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                        struct tevent_req *req,
                                        struct dp_reply_std *data);

void files_account_info_finished(struct files_id_ctx *id_ctx,
                                 int req_type,
                                 errno_t ret);
#endif /* __FILES_PRIVATE_H_ */
