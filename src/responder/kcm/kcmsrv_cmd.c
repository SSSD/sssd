/*
   SSSD

   KCM Server - the KCM server request and reply parsing and dispatching

   Copyright (C) Red Hat, 2016

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

#include "config.h"
#include "util/util.h"
#include "responder/common/responder.h"

struct kcm_proto_ctx {
    void *unused;
};

static void kcm_fd_handler(struct tevent_context *ev,
                           struct tevent_fd *fde,
                           uint16_t flags, void *ptr)
{
    errno_t ret;
    struct cli_ctx *cctx = talloc_get_type(ptr, struct cli_ctx);

    /* Always reset the idle timer on any activity */
    ret = reset_client_idle_timer(cctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not create idle timer for client. "
               "This connection may not auto-terminate\n");
        /* Non-fatal, continue */
    }
}

int kcm_connection_setup(struct cli_ctx *cctx)
{
    struct kcm_proto_ctx *protocol_ctx;

    protocol_ctx = talloc_zero(cctx, struct kcm_proto_ctx);
    if (protocol_ctx == NULL) {
        return ENOMEM;
    }

    cctx->protocol_ctx = protocol_ctx;
    cctx->cfd_handler = kcm_fd_handler;
    return EOK;
}

/* Dummy, not used here but required to link to other responder files */
struct cli_protocol_version *register_cli_protocol_version(void)
{
    return NULL;
}
