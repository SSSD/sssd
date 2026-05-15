/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: Common utilities for tests that exercise domains

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

#include "util/util.h"
#include "tests/cmocka/common_mock_resp.h"

/* Mock a responder context */
struct resp_ctx *
mock_rctx(TALLOC_CTX *mem_ctx,
          struct tevent_context *ev,
          struct sss_domain_info *domains,
          void *pvt_ctx)
{
    struct resp_ctx *rctx;
    errno_t ret;

    rctx = talloc_zero(mem_ctx, struct resp_ctx);
    if (!rctx) return NULL;

    ret = sss_ncache_init(rctx, 10, 0, &rctx->ncache);
    if (ret != EOK) {
        talloc_free(rctx);
        return NULL;
    }

    rctx->ev = ev;
    rctx->domains = domains;
    rctx->pvt_ctx = pvt_ctx;
    if (domains != NULL) {
        ret = sss_resp_populate_cr_domains(rctx);
        if (ret != EOK) {
            return NULL;
        }
    }
    return rctx;
}

/* Mock a client context */
struct cli_ctx *
mock_cctx(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx)
{
    struct cli_ctx *cctx;

    cctx = talloc_zero(mem_ctx, struct cli_ctx);
    if (!cctx) return NULL;

    cctx->rctx = rctx;
    cctx->ev = rctx->ev;
    return cctx;
}

struct cli_protocol *
mock_prctx(TALLOC_CTX *mem_ctx)
{
    struct cli_protocol *prctx;

    prctx = talloc_zero(mem_ctx, struct cli_protocol);
    if (!prctx) return NULL;

    prctx->creq = talloc_zero(prctx, struct cli_request);
    if (prctx->creq == NULL) {
        talloc_free(prctx);
        return NULL;
    }

    return prctx;
}
