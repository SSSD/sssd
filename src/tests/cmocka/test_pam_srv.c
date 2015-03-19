/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests: PAM responder tests

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

#include <security/pam_modules.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"
#include "responder/common/responder_packet.h"
#include "responder/common/negcache.h"
#include "responder/pam/pamsrv.h"
#include "responder/pam/pam_helpers.h"
#include "sss_client/pam_message.h"
#include "sss_client/sss_cli.h"

#include "util/crypto/nss/nss_util.h"

#define TESTS_PATH "tests_pam"
#define TEST_CONF_DB "test_pam_conf.ldb"
#define TEST_DOM_NAME "pam_test"
#define TEST_SUBDOM_NAME "test.subdomain"
#define TEST_ID_PROVIDER "ldap"

struct pam_test_ctx {
    struct sss_test_ctx *tctx;
    struct sss_domain_info *subdom;

    struct resp_ctx *rctx;
    struct cli_ctx *cctx;
    struct sss_cmd_table *pam_cmds;
    struct pam_ctx *pctx;

    int ncache_hits;
    int exp_pam_status;
};

/* Must be global because it is needed in some wrappers */
struct pam_test_ctx *pam_test_ctx;

struct pam_ctx *mock_pctx(TALLOC_CTX *mem_ctx)
{
    struct pam_ctx *pctx;
    errno_t ret;

    pctx = talloc_zero(mem_ctx, struct pam_ctx);
    assert_non_null(pctx);

    ret = sss_ncache_init(pctx, &pctx->ncache);
    assert_int_equal(ret, EOK);

    pctx->neg_timeout = 10;

    ret = sss_hash_create(pctx, 10, &pctx->id_table);
    assert_int_equal(ret, EOK);

    return pctx;
}

void test_pam_setup(struct sss_test_conf_param params[],
                    void **state)
{
    errno_t ret;

    pam_test_ctx = talloc_zero(NULL, struct pam_test_ctx);
    assert_non_null(pam_test_ctx);

    pam_test_ctx->tctx = create_dom_test_ctx(pam_test_ctx, TESTS_PATH,
                                             TEST_CONF_DB, TEST_DOM_NAME,
                                             TEST_ID_PROVIDER, params);
    assert_non_null(pam_test_ctx->tctx);

    pam_test_ctx->pam_cmds = get_pam_cmds();
    assert_non_null(pam_test_ctx->pam_cmds);

    /* FIXME - perhaps this should be folded into sssd_domain_init or stricty
     * used together
     */
    ret = sss_names_init(pam_test_ctx, pam_test_ctx->tctx->confdb,
                         TEST_DOM_NAME, &pam_test_ctx->tctx->dom->names);
    assert_int_equal(ret, EOK);

    /* Initialize the PAM responder */
    pam_test_ctx->pctx = mock_pctx(pam_test_ctx);
    assert_non_null(pam_test_ctx->pctx);

    pam_test_ctx->rctx = mock_rctx(pam_test_ctx, pam_test_ctx->tctx->ev,
                                   pam_test_ctx->tctx->dom, pam_test_ctx->pctx);
    assert_non_null(pam_test_ctx->rctx);
    pam_test_ctx->rctx->cdb = pam_test_ctx->tctx->confdb;
    pam_test_ctx->pctx->rctx = pam_test_ctx->rctx;

    /* Create client context */
    pam_test_ctx->cctx = mock_cctx(pam_test_ctx, pam_test_ctx->rctx);
    assert_non_null(pam_test_ctx->cctx);

    pam_test_ctx->cctx->cli_protocol_version = register_cli_protocol_version();
}

static int pam_test_setup(void **state)
{
    int ret;

    struct sss_test_conf_param params[] = {
        { "enumerate", "false" },
        { "cache_credentials", "true" },
        { NULL, NULL },             /* Sentinel */
    };

    test_pam_setup(params, state);

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(pam_test_ctx->tctx->dom,
                         "pamuser", 123, 456, "pam user",
                         "/home/pamuser", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    /* Add entry to the initgr cache to make sure no initgr request is sent to
     * the backend */
    ret = pam_initgr_cache_set(pam_test_ctx->pctx->rctx->ev,
                               pam_test_ctx->pctx->id_table,
                               discard_const("pamuser"),
                               pam_test_ctx->pctx->id_timeout);
    assert_int_equal(ret, EOK);
    return 0;
}

static int pam_test_teardown(void **state)
{
    int ret;

    ret = sysdb_delete_user(pam_test_ctx->tctx->dom, "pamuser", 0);
    assert_int_equal(ret, EOK);

    talloc_free(pam_test_ctx);
    return 0;
}

typedef int (*cmd_cb_fn_t)(uint32_t, uint8_t *, size_t);

void __real_sss_packet_get_body(struct sss_packet *packet,
                                uint8_t **body, size_t *blen);

void __wrap_sss_packet_get_body(struct sss_packet *packet,
                                uint8_t **body, size_t *blen)
{
    enum sss_test_wrapper_call wtype = sss_mock_type(enum sss_test_wrapper_call);
    size_t len;

    if (wtype == WRAP_CALL_REAL) {
        return __real_sss_packet_get_body(packet, body, blen);
    }

    *body = sss_mock_ptr_type(uint8_t *);
    len = sss_mock_type(size_t);
    if (len == 0) {
        len = strlen((const char *) *body) + 1;
    }
    *blen = len;
    return;
}

void __real_sss_packet_get_body(struct sss_packet *packet,
                                uint8_t **body, size_t *blen);

void __wrap_sss_cmd_done(struct cli_ctx *cctx, void *freectx)
{
    struct sss_packet *packet = cctx->creq->out;
    uint8_t *body;
    size_t blen;
    cmd_cb_fn_t check_cb;

    assert_non_null(packet);

    check_cb = sss_mock_ptr_type(cmd_cb_fn_t);

    __real_sss_packet_get_body(packet, &body, &blen);

    pam_test_ctx->tctx->error = check_cb(sss_packet_get_status(packet),
                                         body, blen);
    pam_test_ctx->tctx->done = true;
}

enum sss_cli_command __wrap_sss_packet_get_cmd(struct sss_packet *packet)
{
    return sss_mock_type(enum sss_cli_command);
}

int __wrap_sss_cmd_send_empty(struct cli_ctx *cctx, TALLOC_CTX *freectx)
{
    pam_test_ctx->tctx->done = true;
    pam_test_ctx->tctx->error = ENOENT;
    return EOK;
}

static void set_cmd_cb(cmd_cb_fn_t fn)
{
    will_return(__wrap_sss_cmd_done, fn);
}

int __wrap_pam_dp_send_req(struct pam_auth_req *preq, int timeout)
{

    /* Set expected status */
    preq->pd->pam_status = pam_test_ctx->exp_pam_status;

    preq->callback(preq);

    return EOK;
}

static void mock_input_pam(TALLOC_CTX *mem_ctx, const char *name,
                           const char *pwd, const char *fa2)
{
    size_t buf_size;
    uint8_t *m_buf;
    uint8_t *buf;
    struct pam_items pi = { 0 };
    int ret;
    size_t needed_size;
    uint8_t *authtok;

    pi.pam_user = name;
    pi.pam_user_size = strlen(pi.pam_user) + 1;

    if (pwd != NULL) {
        if (fa2 != NULL) {
            ret = sss_auth_pack_2fa_blob(pwd, 0, fa2, 0, NULL, 0, &needed_size);
            assert_int_equal(ret, EAGAIN);

            authtok = talloc_size(mem_ctx, needed_size);
            assert_non_null(authtok);

            ret = sss_auth_pack_2fa_blob(pwd, 0, fa2, 0, authtok,
                                         needed_size, &needed_size);
            assert_int_equal(ret, EOK);

            pi.pam_authtok = (char *) authtok;
            pi.pam_authtok_size = needed_size;
            pi.pam_authtok_type = SSS_AUTHTOK_TYPE_2FA;
        } else {
            pi.pam_authtok = discard_const(pwd);
            pi.pam_authtok_size = strlen(pi.pam_authtok) + 1;
            pi.pam_authtok_type = SSS_AUTHTOK_TYPE_PASSWORD;
        }
    }

    pi.pam_service = "ssh";
    pi.pam_service_size = strlen(pi.pam_service) + 1;
    pi.pam_tty = "/dev/tty";
    pi.pam_tty_size = strlen(pi.pam_tty) + 1;
    pi.pam_ruser = "remuser";
    pi.pam_ruser_size = strlen(pi.pam_ruser) + 1;
    pi.pam_rhost = "remhost";
    pi.pam_rhost_size = strlen(pi.pam_rhost) + 1;
    pi.requested_domains = "";
    pi.cli_pid = 12345;

    ret = pack_message_v3(&pi, &buf_size, &m_buf);
    assert_int_equal(ret, 0);

    buf = talloc_memdup(mem_ctx, m_buf, buf_size);
    free(m_buf);
    assert_non_null(buf);

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, buf);
    will_return(__wrap_sss_packet_get_body, buf_size);
}

static int test_pam_simple_check(uint32_t status, uint8_t *body, size_t blen)
{
    size_t rp = 0;
    uint32_t val;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, pam_test_ctx->exp_pam_status);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 1);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_DOMAIN_NAME);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 9);

    assert_int_equal(*(body + rp + val - 1), 0);
    assert_string_equal(body + rp, TEST_DOM_NAME);

    return EOK;
}

static int test_pam_offline_chauthtok_check(uint32_t status,
                                            uint8_t *body, size_t blen)
{
    size_t rp = 0;
    uint32_t val;

    pam_test_ctx->exp_pam_status = PAM_AUTHTOK_ERR;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, pam_test_ctx->exp_pam_status);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 2);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_DOMAIN_NAME);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 9);

    assert_int_equal(*(body + rp + val - 1), 0);
    assert_string_equal(body + rp, TEST_DOM_NAME);
    rp += val;

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_USER_INFO);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 4);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_USER_INFO_OFFLINE_CHPASS);

    return EOK;
}


static int test_pam_failed_offline_auth_check(uint32_t status, uint8_t *body,
                                              size_t blen)
{
    pam_test_ctx->exp_pam_status = PAM_PERM_DENIED;
    return test_pam_simple_check(status, body, blen);
}

static int test_pam_successful_offline_auth_check(uint32_t status,
                                                  uint8_t *body, size_t blen)
{
    pam_test_ctx->exp_pam_status = PAM_SUCCESS;
    return test_pam_simple_check(status, body, blen);
}

static int test_pam_wrong_pw_offline_auth_check(uint32_t status,
                                                uint8_t *body, size_t blen)
{
    pam_test_ctx->exp_pam_status = PAM_AUTH_ERR;
    return test_pam_simple_check(status, body, blen);
}

void test_pam_authenticate(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_setcreds(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_SETCRED);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_SETCRED,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_acct_mgmt(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_ACCT_MGMT);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_ACCT_MGMT,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_open_session(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_OPEN_SESSION);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_NO_MODULE_DATA;
    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_OPEN_SESSION,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_close_session(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_CLOSE_SESSION);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_CLOSE_SESSION,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_chauthtok(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_CHAUTHTOK);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_CHAUTHTOK,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_chauthtok_prelim(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_CHAUTHTOK_PRELIM);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_CHAUTHTOK_PRELIM,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_no_hash(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", "12345", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_failed_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_success(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom, "pamuser", "12345");
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "12345", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_successful_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_wrong_pw(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom, "pamuser", "12345");
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "11111", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_wrong_pw_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_success_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom, "pamuser", "12345");
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "12345", "abcde");

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_successful_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_failed_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom, "pamuser", "12345");
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "11111", "abcde");

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_wrong_pw_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_success_2fa_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom, "pamuser", "12345",
                                  SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "12345", "abcde");

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_successful_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_failed_2fa_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom, "pamuser", "12345",
                                  SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "11111", "abcde");

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_wrong_pw_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_success_pw_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom, "pamuser", "12345",
                                  SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "12345", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_successful_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_failed_pw_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom, "pamuser", "12345",
                                  SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "11111", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_wrong_pw_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_success_combined_pw_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom, "pamuser",
                                  "12345678", SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "12345678abcde", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_successful_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_failed_combined_pw_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom, "pamuser",
                                  "12345678", SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "11111111abcde", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_wrong_pw_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_auth_failed_wrong_2fa_size_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom, "pamuser",
                                  "12345678", SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    mock_input_pam(pam_test_ctx, "pamuser", "12345678abcd", NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_wrong_pw_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_chauthtok_prelim(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_CHAUTHTOK_PRELIM);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_offline_chauthtok_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_CHAUTHTOK_PRELIM,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_offline_chauthtok(void **state)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", NULL, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_CHAUTHTOK);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_AUTHINFO_UNAVAIL;

    set_cmd_cb(test_pam_offline_chauthtok_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_CHAUTHTOK,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}


int main(int argc, const char *argv[])
{
    int rv;
    int no_cleanup = 0;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        { "no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
          _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_pam_authenticate,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_setcreds,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_acct_mgmt,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_open_session,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_close_session,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_chauthtok,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_chauthtok_prelim,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_auth_no_hash,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_auth_success,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_auth_wrong_pw,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_auth_success_2fa,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_auth_failed_2fa,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                              test_pam_offline_auth_success_2fa_with_cached_2fa,
                              pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                               test_pam_offline_auth_failed_2fa_with_cached_2fa,
                               pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                               test_pam_offline_auth_success_pw_with_cached_2fa,
                               pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                                test_pam_offline_auth_failed_pw_with_cached_2fa,
                                pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                      test_pam_offline_auth_success_combined_pw_with_cached_2fa,
                      pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                       test_pam_offline_auth_failed_combined_pw_with_cached_2fa,
                       pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                    test_pam_offline_auth_failed_wrong_2fa_size_with_cached_2fa,
                    pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_chauthtok_prelim,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_offline_chauthtok,
                                        pam_test_setup, pam_test_teardown),
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while ((opt = poptGetNextOpt(pc)) != -1) {
        switch (opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old db to be sure */
    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    test_dom_suite_setup(TESTS_PATH);

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    if (rv == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    }

#ifdef HAVE_NSS
    /* Cleanup NSS and NSPR to make valgrund happy. */
    nspr_nss_cleanup();
#endif

    return rv;
}
