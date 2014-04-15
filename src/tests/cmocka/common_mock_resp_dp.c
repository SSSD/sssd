/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: Fake Data Provider requests

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

/* Mock DP requests that finish immediatelly and return
 * mocked values as per previous set by mock_account_recv
 */
struct tevent_req *
sss_dp_get_account_send(TALLOC_CTX *mem_ctx,
                        struct resp_ctx *rctx,
                        struct sss_domain_info *dom,
                        bool fast_reply,
                        enum sss_dp_acct_type type,
                        const char *opt_name,
                        uint32_t opt_id,
                        const char *extra)
{
    return test_req_succeed_send(mem_ctx, rctx->ev);
}


errno_t
sss_dp_get_account_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        dbus_uint16_t *dp_err,
                        dbus_uint32_t *dp_ret,
                        char **err_msg)
{
    acct_cb_t cb;

    *dp_err = sss_mock_type(dbus_uint16_t);
    *dp_ret = sss_mock_type(dbus_uint32_t);
    *dp_ret = sss_mock_type(dbus_uint32_t);

    cb = sss_mock_ptr_type(acct_cb_t);
    if (cb) {
        (cb)(sss_mock_ptr_type(void *));
    }

    return test_request_recv(req);
}

void mock_account_recv(uint16_t dp_err, uint32_t dp_ret, char *msg,
                       acct_cb_t acct_cb, void *pvt)
{
    will_return(sss_dp_get_account_recv, dp_err);
    will_return(sss_dp_get_account_recv, dp_ret);
    will_return(sss_dp_get_account_recv, msg);

    will_return(sss_dp_get_account_recv, acct_cb);
    if (acct_cb) {
        will_return(sss_dp_get_account_recv, pvt);
    }
}

void mock_account_recv_simple(void)
{
    return mock_account_recv(0, 0, NULL, NULL, NULL);
}

struct tevent_req *
sss_parse_inp_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                   const char *rawinp)
{
    return test_req_succeed_send(mem_ctx, rctx->ev);
}

errno_t sss_parse_inp_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                           char **_name, char **_domname)
{
    *_name = sss_mock_ptr_type(char *);
    *_domname = sss_mock_ptr_type(char *);

    return test_request_recv(req);
}

void mock_parse_inp(const char *name, const char *domname)
{
    will_return(sss_parse_inp_recv, name);
    will_return(sss_parse_inp_recv, domname);
}

/* Mock subdomain requests */
struct tevent_req *
sss_dp_get_domains_send(TALLOC_CTX *mem_ctx,
                        struct resp_ctx *rctx,
                        bool force,
                        const char *hint)
{
    return test_req_succeed_send(mem_ctx, rctx->ev);
}

errno_t sss_dp_get_domains_recv(struct tevent_req *req)
{
    return test_request_recv(req);
}
