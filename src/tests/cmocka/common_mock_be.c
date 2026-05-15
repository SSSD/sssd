/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests: Fake back end

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

struct be_ctx *mock_be_ctx(TALLOC_CTX *mem_ctx, struct sss_test_ctx *tctx)
{
    struct be_ctx *be_ctx;

    be_ctx = talloc_zero(mem_ctx, struct be_ctx);
    assert_non_null(be_ctx);

    be_ctx->cdb = tctx->confdb;
    be_ctx->ev  = tctx->ev;
    be_ctx->domain  = tctx->dom;
    be_ctx->conf_path = tctx->conf_dom_path;

    return be_ctx;
}
