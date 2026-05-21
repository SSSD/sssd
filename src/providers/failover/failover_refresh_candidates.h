;/*
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

#ifndef _FAILOVER_REFRESH_CANDIDATES_H_
#define _FAILOVER_REFRESH_CANDIDATES_H_

#include <talloc.h>

#include "config.h"
#include "providers/failover/failover.h"

struct tevent_req *
sss_failover_refresh_candidates_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct sss_failover_ctx *fctx);

errno_t
sss_failover_refresh_candidates_recv(struct tevent_req *req);

bool
sss_failover_refresh_candidates_oob_can_run(struct sss_failover_ctx *fctx);

void
sss_failover_refresh_candidates_oob_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sss_failover_ctx *fctx);

#endif /* _FAILOVER_REFRESH_CANDIDATES_H_ */
