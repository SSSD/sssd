/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2026 Red Hat

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

#ifndef _PAMSRV_BOT_H_
#define _PAMSRV_BOT_H_

#include <dhash.h>
#include <talloc.h>
#include <tevent.h>

#include "responder/common/responder.h"
#include "util/util_errors.h"

struct pam_auth_req;

struct pam_bot_ctx {
    struct tevent_context *ev;
    hash_table_t *table;
};

errno_t pam_bot_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct pam_bot_ctx **_ctx);

int pam_bot_cmd_register(struct cli_ctx *cctx);

/* Export bot identity and consume any available metadata on success. */
errno_t pam_bot_export_env(struct pam_auth_req *preq,
                           struct pam_bot_ctx *ctx);

#endif /* _PAMSRV_BOT_H_ */
