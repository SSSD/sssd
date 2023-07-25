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
#include "responder/common/responder.h"
#include "tests/cmocka/common_mock_resp.h"

/* Mock DP requests that finish immediately and return
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
                        const char **err_msg)
{
    acct_cb_t cb;

    *dp_err = sss_mock_type(dbus_uint16_t);
    *dp_ret = sss_mock_type(dbus_uint32_t);
    *err_msg = sss_mock_ptr_type(char *);

    cb = sss_mock_ptr_type(acct_cb_t);
    if (cb) {
        (cb)(sss_mock_ptr_type(void *));
    }

    return test_request_recv(req);
}

struct tevent_req *
sss_dp_resolver_get_send(TALLOC_CTX *mem_ctx,
                         struct resp_ctx *rctx,
                         struct sss_domain_info *dom,
                         bool fast_reply,
                         uint32_t entry_type,
                         uint32_t query_type,
                         const char *query_value)
{
    return test_req_succeed_send(mem_ctx, rctx->ev);
}

errno_t
sss_dp_resolver_get_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         dbus_uint16_t *dp_err,
                         dbus_uint32_t *dp_ret,
                         const char **err_msg)
{
    resolver_cb_t cb;

    *dp_err = sss_mock_type(dbus_uint16_t);
    *dp_ret = sss_mock_type(dbus_uint32_t);
    *err_msg = sss_mock_ptr_type(char *);

    cb = sss_mock_ptr_type(resolver_cb_t);
    if (cb) {
        (cb)(sss_mock_ptr_type(void *));
    }

    return test_request_recv(req);
}

void mock_resolver_recv(uint16_t dp_err, uint32_t dp_ret, char *msg,
                        resolver_cb_t cb, void *pvt)
{
    will_return(sss_dp_resolver_get_recv, dp_err);
    will_return(sss_dp_resolver_get_recv, dp_ret);
    will_return(sss_dp_resolver_get_recv, msg);

    will_return(sss_dp_resolver_get_recv, cb);
    if (cb) {
        will_return(sss_dp_resolver_get_recv, pvt);
    }
}

void mock_resolver_recv_simple(void)
{
    return mock_resolver_recv(0, 0, NULL, NULL, NULL);
}

struct tevent_req *
sss_dp_get_ssh_host_send(TALLOC_CTX *mem_ctx,
                         struct resp_ctx *rctx,
                         struct sss_domain_info *dom,
                         bool fast_reply,
                         const char *name,
                         const char *alias)
{
    return test_req_succeed_send(mem_ctx, rctx->ev);
}


errno_t
sss_dp_get_ssh_host_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         dbus_uint16_t *dp_err,
                         dbus_uint32_t *dp_ret,
                         char **err_msg)
{
    acct_cb_t cb;

    *dp_err = sss_mock_type(dbus_uint16_t);
    *dp_ret = sss_mock_type(dbus_uint32_t);
    *err_msg = sss_mock_ptr_type(char *);

    cb = sss_mock_ptr_type(acct_cb_t);
    if (cb) {
        (cb)(sss_mock_ptr_type(void *));
    }

    return test_request_recv(req);
}

errno_t
sss_dp_req_recv(TALLOC_CTX *mem_ctx,
                struct tevent_req *req,
                dbus_uint16_t *dp_err,
                dbus_uint32_t *dp_ret,
                char **err_msg)
{
    acct_cb_t cb;

    *dp_err = sss_mock_type(dbus_uint16_t);
    *dp_ret = sss_mock_type(dbus_uint32_t);
    *err_msg = sss_mock_ptr_type(char *);

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
sss_parse_inp_send(TALLOC_CTX *mem_ctx,
                   struct resp_ctx *rctx,
                   const char *default_domain,
                   const char *rawinp)
{
    return test_req_succeed_send(mem_ctx, rctx->ev);
}

errno_t sss_parse_inp_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                           char **_name, char **_domname)
{
    *_name = sss_mock_ptr_type(char *);
    *_domname = sss_mock_ptr_type(char *);

    return sss_mock_type(errno_t);
}

void mock_parse_inp(const char *name, const char *domname, errno_t ret)
{
    will_return(sss_parse_inp_recv, name);
    will_return(sss_parse_inp_recv, domname);
    will_return(sss_parse_inp_recv, ret);
}

/* Mock subdomain requests */
struct tevent_req *
sss_dp_get_domains_send(TALLOC_CTX *mem_ctx,
                        struct resp_ctx *rctx,
                        bool force,
                        const char *hint)
{
    errno_t ret;
    ret = sss_resp_populate_cr_domains(rctx);
    if (ret != EOK) {
        return NULL;
    }

    return test_req_succeed_send(mem_ctx, rctx->ev);
}

errno_t sss_dp_get_domains_recv(struct tevent_req *req)
{
    return test_request_recv(req);
}

struct tevent_req *
sss_dp_get_account_domain_send(TALLOC_CTX *mem_ctx,
                               struct resp_ctx *rctx,
                               struct sss_domain_info *domain,
                               bool fast_reply,
                               enum sss_dp_acct_type type,
                               uint32_t opt_id,
                               const char *opt_str)
{
    return test_req_succeed_send(mem_ctx, rctx->ev);
}

errno_t sss_dp_get_account_domain_recv(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req,
                                       char **_domain)
{
    errno_t ret;

    ret = sss_mock_type(errno_t);
    if (ret == EOK) {
        *_domain = sss_mock_ptr_type(char *);
    }
    return ret;
}
