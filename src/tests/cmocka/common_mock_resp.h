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

#ifndef __COMMON_MOCK_RESP_H_
#define __COMMON_MOCK_RESP_H_

#include "util/util.h"
#include "responder/common/responder.h"
#include "tests/cmocka/common_mock.h"

/* Mock a responder context */
struct resp_ctx *
mock_rctx(TALLOC_CTX *mem_ctx,
          struct tevent_context *ev,
          struct sss_domain_info *domains,
          void *pvt_ctx);

/* Mock a client context */
struct cli_ctx *
mock_cctx(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx);

struct cli_protocol *
mock_prctx(TALLOC_CTX *mem_ctx);

/* When mocking a module that calls sss_dp_get_account_{send,recv}
 * requests, your test, when linked against this module, will call
 * the mock functions instead. Then you can simulate results of the
 * sss_dp_get_account_recv call by calling mock_account_recv.
 *
 * The mocked sss_sp_get_account_recv shall return the return values
 * given with parameters dp_err, dp_ret and msg and optionally also call
 * the acct_cb_t callback, if given with the pvt pointer as user data.
 * The callback can for instance populate the cache, thus simulating
 * Data Provider lookup.
 *
 * There is also even simpler wrapper called mock_account_recv_simple
 * that just finishes the account request with a success.
 */
typedef int (*acct_cb_t)(void *);
typedef int (*resolver_cb_t)(void *);

void mock_account_recv(uint16_t dp_err, uint32_t dp_ret, char *msg,
                       acct_cb_t acct_cb, void *pvt);

void mock_account_recv_simple(void);

void mock_resolver_recv(uint16_t dp_err, uint32_t dp_ret, char *msg,
                        resolver_cb_t acct_cb, void *pvt);

void mock_resolver_recv_simple(void);

void mock_parse_inp(const char *name, const char *domname, errno_t ret);

#endif /* __COMMON_MOCK_RESP_H_ */
