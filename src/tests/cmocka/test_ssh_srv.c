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

#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"
#include "responder/common/responder_packet.h"
#include "responder/common/negcache.h"
#include "responder/ssh/ssh_private.h"
#include "confdb/confdb.h"

#include "util/crypto/sss_crypto.h"

#ifdef HAVE_TEST_CA
#include "tests/test_CA/SSSD_test_cert_x509_0001.h"
#include "tests/test_CA/SSSD_test_cert_pubsshkey_0001.h"
#include "tests/test_CA/SSSD_test_cert_x509_0002.h"
#include "tests/test_CA/SSSD_test_cert_pubsshkey_0002.h"
#include "tests/test_CA/SSSD_test_cert_x509_0007.h"
#include "tests/test_CA/SSSD_test_cert_pubsshkey_0007.h"
#else
#define SSSD_TEST_CERT_0001 ""
#define SSSD_TEST_CERT_SSH_KEY_0001 ""
#define SSSD_TEST_CERT_0002 ""
#define SSSD_TEST_CERT_SSH_KEY_0002 ""
#define SSSD_TEST_CERT_0007 ""
#define SSSD_TEST_CERT_SSH_KEY_0007 ""
#endif

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_ssh_conf.ldb"
#define TEST_DOM_NAME "ssh_test"
#define TEST_SUBDOM_NAME "test.subdomain"
#define TEST_ID_PROVIDER "ldap"

#define TEST_SSH_PUBKEY \
"AAAAB3NzaC1yc2EAAAADAQABAAABAQC1" \
"OlYGkYw8JyhKQrlNBGbZC2az9TJhUWNn" \
"/kS26OOI9hXCZgz4eHyZnCS1bY1/0ptG" \
"ByQAk2qvF9uYV2plxULoiOUYAWCnnqx/" \
"bnhQ4SxmCcA5RPy3h8FX2OrxMlQEadH6" \
"wz3ZTnOvsw57/ZV8yXjzVexJeeO1A59g" \
"pLD43f3v056zSF/Jo1NwAZUzCJuzpFAy" \
"Ale6mZ/1rpGN+ah6rN70wz3brwEOi4f2" \
"HQNbKAL4idVyRYbA7oU+htCLEd6YsSdy" \
"murxDMAEEQbLeMbF1DXNt1OunoeprXrU" \
"UE1U9Rxi6xvPt7s3h9NbZiaLRPJU6due" \
"+nqwn8En7mesd7LnRQST"

struct ssh_test_ctx {
    struct sss_test_ctx *tctx;
    struct sss_domain_info *subdom;

    struct resp_ctx *rctx;
    struct cli_ctx *cctx;
    struct sss_cmd_table *ssh_cmds;
    struct ssh_ctx *ssh_ctx;

    int ncache_hits;
    bool provider_contacted;

    const char *ssh_user_fqdn;
    const char *wrong_user_fqdn;
};

/* Must be global because it is needed in some wrappers */
struct ssh_test_ctx *ssh_test_ctx;

struct ssh_ctx *mock_ssh_ctx(TALLOC_CTX *mem_ctx)
{
    struct ssh_ctx *ssh_ctx;

    ssh_ctx = talloc_zero(mem_ctx, struct ssh_ctx);
    assert_non_null(ssh_ctx);

    return ssh_ctx;
}

static int add_confdb_params(struct sss_test_conf_param params[],
                             struct confdb_ctx *cdb, const char *section)
{
    const char *val[2];
    int ret;

    val[1] = NULL;

    for (int i = 0; params[i].key; i++) {
        val[0] = params[i].value;
        ret = confdb_add_param(cdb, true, section, params[i].key, val);
        assert_int_equal(ret, EOK);
    }

    return EOK;
}

static int add_ssh_params(struct sss_test_conf_param ssh_params[],
                          struct confdb_ctx *cdb)
{
    return add_confdb_params(ssh_params, cdb, CONFDB_SSH_CONF_ENTRY);
}

static int add_monitor_params(struct sss_test_conf_param monitor_params[],
                              struct confdb_ctx *cdb)
{
    return add_confdb_params(monitor_params, cdb, CONFDB_MONITOR_CONF_ENTRY);
}

void test_ssh_setup(struct sss_test_conf_param dom_params[],
                    struct sss_test_conf_param ssh_params[],
                    struct sss_test_conf_param monitor_params[],
                    void **state)
{
    struct cli_protocol *prctx;
    errno_t ret;

    ssh_test_ctx = talloc_zero(NULL, struct ssh_test_ctx);
    assert_non_null(ssh_test_ctx);

    ssh_test_ctx->tctx = create_dom_test_ctx(ssh_test_ctx, TESTS_PATH,
                                             TEST_CONF_DB, TEST_DOM_NAME,
                                             TEST_ID_PROVIDER, dom_params);
    assert_non_null(ssh_test_ctx->tctx);

    ssh_test_ctx->ssh_cmds = get_ssh_cmds();
    assert_non_null(ssh_test_ctx->ssh_cmds);

    /* FIXME - perhaps this should be folded into sssd_domain_init or strictly
     * used together
     */
    ret = sss_names_init(ssh_test_ctx, ssh_test_ctx->tctx->confdb,
                         TEST_DOM_NAME, &ssh_test_ctx->tctx->dom->names);
    assert_int_equal(ret, EOK);

    /* Initialize the SSH responder */
    ssh_test_ctx->ssh_ctx = mock_ssh_ctx(ssh_test_ctx);
    assert_non_null(ssh_test_ctx->ssh_ctx);

    ssh_test_ctx->rctx = mock_rctx(ssh_test_ctx, ssh_test_ctx->tctx->ev,
                                   ssh_test_ctx->tctx->dom,
                                   ssh_test_ctx->ssh_ctx);
    assert_non_null(ssh_test_ctx->rctx);
    ssh_test_ctx->rctx->cdb = ssh_test_ctx->tctx->confdb;
    ssh_test_ctx->ssh_ctx->rctx = ssh_test_ctx->rctx;

    ret = add_ssh_params(ssh_params, ssh_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = add_monitor_params(monitor_params, ssh_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    /* Create client context */
    ssh_test_ctx->cctx = mock_cctx(ssh_test_ctx, ssh_test_ctx->rctx);
    assert_non_null(ssh_test_ctx->cctx);
    ssh_test_ctx->cctx->ev = ssh_test_ctx->tctx->ev;

    prctx = mock_prctx(ssh_test_ctx->cctx);
    assert_non_null(prctx);
    ssh_test_ctx->cctx->protocol_ctx = prctx;
    prctx->cli_protocol_version = register_cli_protocol_version();
}

static void ssh_test_setup_common(void)
{
    errno_t ret;

    ssh_test_ctx->ssh_user_fqdn = \
                    sss_create_internal_fqname(ssh_test_ctx,
                                               "sshuser",
                                               ssh_test_ctx->tctx->dom->name);
    assert_non_null(ssh_test_ctx->ssh_user_fqdn);

    ssh_test_ctx->wrong_user_fqdn = \
                    sss_create_internal_fqname(ssh_test_ctx,
                                               "wrongsshuser",
                                               ssh_test_ctx->tctx->dom->name);
    assert_non_null(ssh_test_ctx->wrong_user_fqdn);

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(ssh_test_ctx->tctx->dom,
                         ssh_test_ctx->ssh_user_fqdn,
                         123, 456, "ssh user",
                         "/home/sshuser", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    /* Prime the cache with a user for wrong matches */
    ret = sysdb_add_user(ssh_test_ctx->tctx->dom,
                         ssh_test_ctx->wrong_user_fqdn,
                         321, 654, "wrong ssh user",
                         "/home/wrongsshuser", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);
}

static int ssh_test_setup(void **state)
{
    struct sss_test_conf_param dom_params[] = {
        { "enumerate", "false" },
        { "cache_credentials", "true" },
        { NULL, NULL },             /* Sentinel */
    };

    /* When run under valgrind with --trace-children=yes we have to increase
     * the timeout not because p11_child needs much more time under valgrind
     * but because of the way valgrind handles the children. */
    struct sss_test_conf_param ssh_params[] = {
        { "p11_child_timeout", "80" },
        { NULL, NULL },             /* Sentinel */
    };

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "no_ocsp"},
        { NULL, NULL },             /* Sentinel */
    };

    test_ssh_setup(dom_params, ssh_params, monitor_params, state);

    ssh_test_setup_common();
    return 0;
}

static int ssh_test_teardown(void **state)
{
    int ret;

    ret = sysdb_delete_user(ssh_test_ctx->tctx->dom,
                            ssh_test_ctx->ssh_user_fqdn, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_delete_user(ssh_test_ctx->tctx->dom,
                            ssh_test_ctx->wrong_user_fqdn, 0);
    assert_int_equal(ret, EOK);

    talloc_free(ssh_test_ctx);
    return 0;
}

typedef int (*cmd_cb_fn_t)(uint32_t, uint8_t *, size_t);


int __real_read_pipe_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                          uint8_t **buf, ssize_t *len);

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
    struct cli_protocol *prctx;
    struct sss_packet *packet;
    uint8_t *body;
    size_t blen;
    cmd_cb_fn_t check_cb;

    prctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);
    packet = prctx->creq->out;
    assert_non_null(packet);

    check_cb = sss_mock_ptr_type(cmd_cb_fn_t);

    __real_sss_packet_get_body(packet, &body, &blen);

    ssh_test_ctx->tctx->error = check_cb(sss_packet_get_status(packet),
                                         body, blen);
    ssh_test_ctx->tctx->done = true;
}

enum sss_cli_command __wrap_sss_packet_get_cmd(struct sss_packet *packet)
{
    return sss_mock_type(enum sss_cli_command);
}

int __wrap_sss_cmd_send_empty(struct cli_ctx *cctx, TALLOC_CTX *freectx)
{
    ssh_test_ctx->tctx->done = true;
    ssh_test_ctx->tctx->error = ENOENT;
    return EOK;
}

static void set_cmd_cb(cmd_cb_fn_t fn)
{
    will_return(__wrap_sss_cmd_done, fn);
}

static void mock_input_user(TALLOC_CTX *mem_ctx, const char *username)
{
    uint8_t *buf;
    size_t len = strlen(username);
    size_t buf_len = len + 1 + 2 * sizeof(uint32_t);

    buf = talloc_size(mem_ctx, buf_len);
    SAFEALIGN_SET_UINT32(&buf[0], 0, NULL);
    SAFEALIGN_SET_UINT32(&buf[4], len + 1, NULL);
    memcpy(&buf[8], username, len + 1);

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, buf);
    will_return(__wrap_sss_packet_get_body, buf_len);
    mock_parse_inp("sshuser", TEST_DOM_NAME, EOK);
}

static int test_ssh_user_no_pubkeys_check(uint32_t status,
                                          uint8_t *body, size_t blen)
{
    uint32_t val;

    assert_int_equal(status, EOK);
    assert_int_equal(blen, 8);

    SAFEALIGN_COPY_UINT32(&val, &body[0], NULL);
    assert_int_equal(val, 0);

    SAFEALIGN_COPY_UINT32(&val, &body[4], NULL);
    assert_int_equal(val, 0);

    return EOK;
}

void test_ssh_user_no_pubkeys(void **state) {
    int ret;

    mock_input_user(ssh_test_ctx, ssh_test_ctx->ssh_user_fqdn);
    will_return(__wrap_sss_packet_get_cmd, SSS_SSH_GET_USER_PUBKEYS);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_ssh_user_no_pubkeys_check);
    ret = sss_cmd_execute(ssh_test_ctx->cctx, SSS_SSH_GET_USER_PUBKEYS,
                          ssh_test_ctx->ssh_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(ssh_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_ssh_user_one_pubkey_check(uint32_t status,
                                          uint8_t *body, size_t blen)
{
    uint32_t val;
    size_t exp_len;
    size_t name_len;
    size_t key_len;
    uint8_t *key;
    size_t rp = 0;

    key = sss_base64_decode(ssh_test_ctx, TEST_SSH_PUBKEY, &key_len);
    name_len = strlen(ssh_test_ctx->ssh_user_fqdn) + 1;

    exp_len = 5 * sizeof(uint32_t) + name_len + key_len;

    assert_int_equal(status, EOK);
    assert_int_equal(blen, exp_len);

    SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
    assert_int_equal(val, 1);

    SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
    assert_int_equal(val, 0);

    SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
    assert_int_equal(val, 0);

    SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
    assert_int_equal(val, name_len);

    assert_memory_equal(body + rp, ssh_test_ctx->ssh_user_fqdn, name_len);
    rp += name_len;

    SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
    assert_int_equal(val, key_len);

    assert_memory_equal(body + rp, key, key_len);
    rp += key_len;

    assert_int_equal(rp, blen);

    return EOK;
}

void test_ssh_user_pubkey(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(ssh_test_ctx);
    assert_non_null(attrs);
    ret = sysdb_attrs_add_string(attrs, SYSDB_SSH_PUBKEY, TEST_SSH_PUBKEY);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(ssh_test_ctx->tctx->dom,
                              ssh_test_ctx->ssh_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    talloc_free(attrs);
    assert_int_equal(ret, EOK);

    mock_input_user(ssh_test_ctx, ssh_test_ctx->ssh_user_fqdn);
    will_return(__wrap_sss_packet_get_cmd, SSS_SSH_GET_USER_PUBKEYS);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_ssh_user_one_pubkey_check);
    ret = sss_cmd_execute(ssh_test_ctx->cctx, SSS_SSH_GET_USER_PUBKEYS,
                          ssh_test_ctx->ssh_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(ssh_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_ssh_user_pubkey_cert_disabled(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(ssh_test_ctx);
    assert_non_null(attrs);
    ret = sysdb_attrs_add_string(attrs, SYSDB_SSH_PUBKEY, TEST_SSH_PUBKEY);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_string(attrs, SYSDB_USER_CERT, SSSD_TEST_CERT_0001);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_string(attrs, SYSDB_USER_CERT, SSSD_TEST_CERT_0002);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(ssh_test_ctx->tctx->dom,
                              ssh_test_ctx->ssh_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    talloc_free(attrs);
    assert_int_equal(ret, EOK);

    mock_input_user(ssh_test_ctx, ssh_test_ctx->ssh_user_fqdn);
    will_return(__wrap_sss_packet_get_cmd, SSS_SSH_GET_USER_PUBKEYS);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_ssh_user_one_pubkey_check);
    ret = sss_cmd_execute(ssh_test_ctx->cctx, SSS_SSH_GET_USER_PUBKEYS,
                          ssh_test_ctx->ssh_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(ssh_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_ssh_user_pubkey_cert_pss_check(uint32_t status,
                                               uint8_t *body, size_t blen)
{
    uint32_t val;
    size_t exp_len;
    size_t name_len;
    size_t key_len[2];
    uint8_t *key[2];
    size_t rp = 0;
    size_t c;

    key[0] = sss_base64_decode(ssh_test_ctx, TEST_SSH_PUBKEY, &key_len[0]);
    assert_non_null(key[0]);

    key[1] = sss_base64_decode(ssh_test_ctx, SSSD_TEST_CERT_SSH_KEY_0007,
                               &key_len[1]);
    assert_non_null(key[1]);

    name_len = strlen(ssh_test_ctx->ssh_user_fqdn) + 1;

    exp_len = 2 * sizeof(uint32_t) + 2* 3* sizeof(uint32_t) + 2 * name_len
                                   + key_len[0] + key_len[1];

    assert_int_equal(status, EOK);
    assert_int_equal(blen, exp_len);

    SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
    assert_int_equal(val, 2);

    SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
    assert_int_equal(val, 0);

    for (c = 0; c < 2; c++) {
        SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
        assert_int_equal(val, 0);

        SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
        assert_int_equal(val, name_len);

        assert_memory_equal(body + rp, ssh_test_ctx->ssh_user_fqdn, name_len);
        rp += name_len;

        SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
        assert_int_equal(val, key_len[c]);

        assert_memory_equal(body + rp, key[c], key_len[c]);
        rp += key_len[c];
    }

    assert_int_equal(rp, blen);

    return EOK;
}

static int test_ssh_user_pubkey_cert_check(uint32_t status,
                                           uint8_t *body, size_t blen)
{
    uint32_t val;
    size_t exp_len;
    size_t name_len;
    size_t key_len[3];
    uint8_t *key[3];
    size_t rp = 0;
    size_t c;

    key[0] = sss_base64_decode(ssh_test_ctx, TEST_SSH_PUBKEY, &key_len[0]);
    assert_non_null(key[0]);

    key[1] = sss_base64_decode(ssh_test_ctx, SSSD_TEST_CERT_SSH_KEY_0001,
                               &key_len[1]);
    assert_non_null(key[1]);

    key[2] = sss_base64_decode(ssh_test_ctx, SSSD_TEST_CERT_SSH_KEY_0002,
                               &key_len[2]);
    assert_non_null(key[2]);

    name_len = strlen(ssh_test_ctx->ssh_user_fqdn) + 1;

    exp_len = 2 * sizeof(uint32_t) + 3* 3* sizeof(uint32_t) + 3 * name_len
                                   + key_len[0] + key_len[1] + key_len[2];

    assert_int_equal(status, EOK);
    assert_int_equal(blen, exp_len);

    SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
    assert_int_equal(val, 3);

    SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
    assert_int_equal(val, 0);

    for (c = 0; c < 3; c++) {
        SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
        assert_int_equal(val, 0);

        SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
        assert_int_equal(val, name_len);

        assert_memory_equal(body + rp, ssh_test_ctx->ssh_user_fqdn, name_len);
        rp += name_len;

        SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
        assert_int_equal(val, key_len[c]);

        assert_memory_equal(body + rp, key[c], key_len[c]);
        rp += key_len[c];
    }

    assert_int_equal(rp, blen);

    return EOK;
}

static int test_ssh_user_pubkey_cert_1_check(uint32_t status,
                                             uint8_t *body, size_t blen)
{
    uint32_t val;
    size_t exp_len;
    size_t name_len;
    size_t key_len[2];
    uint8_t *key[2];
    size_t rp = 0;
    size_t c;

    key[0] = sss_base64_decode(ssh_test_ctx, TEST_SSH_PUBKEY, &key_len[0]);
    assert_non_null(key[0]);

    key[1] = sss_base64_decode(ssh_test_ctx, SSSD_TEST_CERT_SSH_KEY_0001,
                               &key_len[1]);
    assert_non_null(key[1]);

    name_len = strlen(ssh_test_ctx->ssh_user_fqdn) + 1;

    exp_len = 2 * sizeof(uint32_t) + 2* 3* sizeof(uint32_t) + 2 * name_len
                                   + key_len[0] + key_len[1];

    assert_int_equal(status, EOK);
    assert_int_equal(blen, exp_len);

    SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
    assert_int_equal(val, 2);

    SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
    assert_int_equal(val, 0);

    for (c = 0; c < 2; c++) {
        SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
        assert_int_equal(val, 0);

        SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
        assert_int_equal(val, name_len);

        assert_memory_equal(body + rp, ssh_test_ctx->ssh_user_fqdn, name_len);
        rp += name_len;

        SAFEALIGN_COPY_UINT32(&val, &body[rp], &rp);
        assert_int_equal(val, key_len[c]);

        assert_memory_equal(body + rp, key[c], key_len[c]);
        rp += key_len[c];
    }

    assert_int_equal(rp, blen);

    return EOK;
}

void test_ssh_user_pubkey_cert(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(ssh_test_ctx);
    assert_non_null(attrs);
    ret = sysdb_attrs_add_string(attrs, SYSDB_SSH_PUBKEY, TEST_SSH_PUBKEY);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0001);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0002);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(ssh_test_ctx->tctx->dom,
                              ssh_test_ctx->ssh_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    talloc_free(attrs);
    assert_int_equal(ret, EOK);

    mock_input_user(ssh_test_ctx, ssh_test_ctx->ssh_user_fqdn);
    will_return(__wrap_sss_packet_get_cmd, SSS_SSH_GET_USER_PUBKEYS);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Enable certificate support */
    ssh_test_ctx->ssh_ctx->use_cert_keys = true;
    ssh_test_ctx->ssh_ctx->ca_db = discard_const(ABS_BUILD_DIR
                                                "/src/tests/test_CA/SSSD_test_CA.pem");

    set_cmd_cb(test_ssh_user_pubkey_cert_check);
    ret = sss_cmd_execute(ssh_test_ctx->cctx, SSS_SSH_GET_USER_PUBKEYS,
                          ssh_test_ctx->ssh_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(ssh_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_ssh_user_pubkey_pss_cert(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(ssh_test_ctx);
    assert_non_null(attrs);
    ret = sysdb_attrs_add_string(attrs, SYSDB_SSH_PUBKEY, TEST_SSH_PUBKEY);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0007);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(ssh_test_ctx->tctx->dom,
                              ssh_test_ctx->ssh_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    talloc_free(attrs);
    assert_int_equal(ret, EOK);

    mock_input_user(ssh_test_ctx, ssh_test_ctx->ssh_user_fqdn);
    will_return(__wrap_sss_packet_get_cmd, SSS_SSH_GET_USER_PUBKEYS);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Enable certificate support */
    ssh_test_ctx->ssh_ctx->use_cert_keys = true;
    ssh_test_ctx->ssh_ctx->ca_db = discard_const(ABS_BUILD_DIR
                                                "/src/tests/test_CA/SSSD_test_CA.pem");

    set_cmd_cb(test_ssh_user_pubkey_cert_pss_check);
    ret = sss_cmd_execute(ssh_test_ctx->cctx, SSS_SSH_GET_USER_PUBKEYS,
                          ssh_test_ctx->ssh_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(ssh_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

struct certmap_info rule_1 = {
                            discard_const("rule1"), -1,
                            discard_const("<SUBJECT>CN=SSSD test cert 0001,.*"),
                            NULL, NULL };
struct certmap_info rule_2 = {
                            discard_const("rule2"), -1,
                            discard_const("<SUBJECT>CN=SSSD test cert 0002,.*"),
                            NULL, NULL };

void test_ssh_user_pubkey_cert_with_rule(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    /* Both rules are enabled, both certificates should be handled. */
    struct certmap_info *certmap_list[] = { &rule_1, &rule_2, NULL};

    attrs = sysdb_new_attrs(ssh_test_ctx);
    assert_non_null(attrs);
    ret = sysdb_attrs_add_string(attrs, SYSDB_SSH_PUBKEY, TEST_SSH_PUBKEY);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0001);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0002);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(ssh_test_ctx->tctx->dom,
                              ssh_test_ctx->ssh_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    talloc_free(attrs);
    assert_int_equal(ret, EOK);

    mock_input_user(ssh_test_ctx, ssh_test_ctx->ssh_user_fqdn);
    will_return(__wrap_sss_packet_get_cmd, SSS_SSH_GET_USER_PUBKEYS);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Enable certificate support */
    ssh_test_ctx->ssh_ctx->use_cert_keys = true;
    ssh_test_ctx->ssh_ctx->rctx->domains->certmaps = certmap_list;
    ssh_test_ctx->ssh_ctx->certmap_last_read = 0;
    ssh_test_ctx->ssh_ctx->rctx->get_domains_last_call.tv_sec = 1;
    ssh_test_ctx->ssh_ctx->ca_db = discard_const(ABS_BUILD_DIR
                                                "/src/tests/test_CA/SSSD_test_CA.pem");

    set_cmd_cb(test_ssh_user_pubkey_cert_check);
    ret = sss_cmd_execute(ssh_test_ctx->cctx, SSS_SSH_GET_USER_PUBKEYS,
                          ssh_test_ctx->ssh_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(ssh_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_ssh_user_pubkey_cert_with_all_rules(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    /* Both rules are enabled, both certificates should be handled. */
    const char *rule_list[] = { "all_rules", NULL };
    struct certmap_info *certmap_list[] = { &rule_1, &rule_2, NULL};

    attrs = sysdb_new_attrs(ssh_test_ctx);
    assert_non_null(attrs);
    ret = sysdb_attrs_add_string(attrs, SYSDB_SSH_PUBKEY, TEST_SSH_PUBKEY);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0001);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0002);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(ssh_test_ctx->tctx->dom,
                              ssh_test_ctx->ssh_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    talloc_free(attrs);
    assert_int_equal(ret, EOK);

    mock_input_user(ssh_test_ctx, ssh_test_ctx->ssh_user_fqdn);
    will_return(__wrap_sss_packet_get_cmd, SSS_SSH_GET_USER_PUBKEYS);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Enable certificate support */
    ssh_test_ctx->ssh_ctx->use_cert_keys = true;
    ssh_test_ctx->ssh_ctx->rctx->domains->certmaps = certmap_list;
    ssh_test_ctx->ssh_ctx->certmap_last_read = 0;
    ssh_test_ctx->ssh_ctx->rctx->get_domains_last_call.tv_sec = 1;
    ssh_test_ctx->ssh_ctx->cert_rules = discard_const(rule_list);
    ssh_test_ctx->ssh_ctx->ca_db = discard_const(ABS_BUILD_DIR
                                                "/src/tests/test_CA/SSSD_test_CA.pem");

    set_cmd_cb(test_ssh_user_pubkey_cert_check);
    ret = sss_cmd_execute(ssh_test_ctx->cctx, SSS_SSH_GET_USER_PUBKEYS,
                          ssh_test_ctx->ssh_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(ssh_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_ssh_user_pubkey_cert_with_all_rules_but_no_rules_present(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    /* Both rules are enabled, both certificates should be handled. */
    const char *rule_list[] = { "all_rules", NULL };

    attrs = sysdb_new_attrs(ssh_test_ctx);
    assert_non_null(attrs);
    ret = sysdb_attrs_add_string(attrs, SYSDB_SSH_PUBKEY, TEST_SSH_PUBKEY);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0001);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0002);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(ssh_test_ctx->tctx->dom,
                              ssh_test_ctx->ssh_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    talloc_free(attrs);
    assert_int_equal(ret, EOK);

    mock_input_user(ssh_test_ctx, ssh_test_ctx->ssh_user_fqdn);
    will_return(__wrap_sss_packet_get_cmd, SSS_SSH_GET_USER_PUBKEYS);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Enable certificate support */
    ssh_test_ctx->ssh_ctx->use_cert_keys = true;
    ssh_test_ctx->ssh_ctx->rctx->domains->certmaps = NULL;
    ssh_test_ctx->ssh_ctx->certmap_last_read = 0;
    ssh_test_ctx->ssh_ctx->rctx->get_domains_last_call.tv_sec = 1;
    ssh_test_ctx->ssh_ctx->cert_rules = discard_const(rule_list);
    ssh_test_ctx->ssh_ctx->ca_db = discard_const(ABS_BUILD_DIR
                                                "/src/tests/test_CA/SSSD_test_CA.pem");

    set_cmd_cb(test_ssh_user_pubkey_cert_check);
    ret = sss_cmd_execute(ssh_test_ctx->cctx, SSS_SSH_GET_USER_PUBKEYS,
                          ssh_test_ctx->ssh_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(ssh_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_ssh_user_pubkey_cert_with_no_rules(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    /* No rules should be used, both certificates should be handled. */
    const char *rule_list[] = { "no_rules", NULL };
    struct certmap_info *certmap_list[] = { &rule_1, &rule_2, NULL};

    attrs = sysdb_new_attrs(ssh_test_ctx);
    assert_non_null(attrs);
    ret = sysdb_attrs_add_string(attrs, SYSDB_SSH_PUBKEY, TEST_SSH_PUBKEY);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0001);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0002);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(ssh_test_ctx->tctx->dom,
                              ssh_test_ctx->ssh_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    talloc_free(attrs);
    assert_int_equal(ret, EOK);

    mock_input_user(ssh_test_ctx, ssh_test_ctx->ssh_user_fqdn);
    will_return(__wrap_sss_packet_get_cmd, SSS_SSH_GET_USER_PUBKEYS);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Enable certificate support */
    ssh_test_ctx->ssh_ctx->use_cert_keys = true;
    ssh_test_ctx->ssh_ctx->rctx->domains->certmaps = certmap_list;
    ssh_test_ctx->ssh_ctx->certmap_last_read = 0;
    ssh_test_ctx->ssh_ctx->rctx->get_domains_last_call.tv_sec = 1;
    ssh_test_ctx->ssh_ctx->cert_rules = discard_const(rule_list);
    ssh_test_ctx->ssh_ctx->ca_db = discard_const(ABS_BUILD_DIR
                                                "/src/tests/test_CA/SSSD_test_CA.pem");

    set_cmd_cb(test_ssh_user_pubkey_cert_check);
    ret = sss_cmd_execute(ssh_test_ctx->cctx, SSS_SSH_GET_USER_PUBKEYS,
                          ssh_test_ctx->ssh_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(ssh_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_ssh_user_pubkey_cert_with_unknow_rule_name(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    /* No rule is enabled because the unknown rule name "none" is used, both
     * certificates should be handled. */
    const char *rule_list[] = { "none", NULL };
    struct certmap_info *certmap_list[] = { &rule_1, &rule_2, NULL};

    attrs = sysdb_new_attrs(ssh_test_ctx);
    assert_non_null(attrs);
    ret = sysdb_attrs_add_string(attrs, SYSDB_SSH_PUBKEY, TEST_SSH_PUBKEY);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0001);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0002);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(ssh_test_ctx->tctx->dom,
                              ssh_test_ctx->ssh_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    talloc_free(attrs);
    assert_int_equal(ret, EOK);

    mock_input_user(ssh_test_ctx, ssh_test_ctx->ssh_user_fqdn);
    will_return(__wrap_sss_packet_get_cmd, SSS_SSH_GET_USER_PUBKEYS);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Enable certificate support */
    ssh_test_ctx->ssh_ctx->use_cert_keys = true;
    ssh_test_ctx->ssh_ctx->rctx->domains->certmaps = certmap_list;
    ssh_test_ctx->ssh_ctx->certmap_last_read = 0;
    ssh_test_ctx->ssh_ctx->rctx->get_domains_last_call.tv_sec = 1;
    ssh_test_ctx->ssh_ctx->cert_rules = discard_const(rule_list);
    ssh_test_ctx->ssh_ctx->ca_db = discard_const(ABS_BUILD_DIR
                                                "/src/tests/test_CA/SSSD_test_CA.pem");

    set_cmd_cb(test_ssh_user_one_pubkey_check);
    ret = sss_cmd_execute(ssh_test_ctx->cctx, SSS_SSH_GET_USER_PUBKEYS,
                          ssh_test_ctx->ssh_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(ssh_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_ssh_user_pubkey_cert_with_rule_1(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    /* Only "rule1" is selected, only certificate 1 should be handled. */
    const char *rule_list[] = { "rule1", NULL };
    struct certmap_info *certmap_list[] = { &rule_1, &rule_2, NULL};

    attrs = sysdb_new_attrs(ssh_test_ctx);
    assert_non_null(attrs);
    ret = sysdb_attrs_add_string(attrs, SYSDB_SSH_PUBKEY, TEST_SSH_PUBKEY);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0001);
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT,
                                      SSSD_TEST_CERT_0002);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(ssh_test_ctx->tctx->dom,
                              ssh_test_ctx->ssh_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    talloc_free(attrs);
    assert_int_equal(ret, EOK);

    mock_input_user(ssh_test_ctx, ssh_test_ctx->ssh_user_fqdn);
    will_return(__wrap_sss_packet_get_cmd, SSS_SSH_GET_USER_PUBKEYS);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Enable certificate support */
    ssh_test_ctx->ssh_ctx->use_cert_keys = true;
    ssh_test_ctx->ssh_ctx->rctx->domains->certmaps = certmap_list;
    ssh_test_ctx->ssh_ctx->certmap_last_read = 0;
    ssh_test_ctx->ssh_ctx->rctx->get_domains_last_call.tv_sec = 1;
    ssh_test_ctx->ssh_ctx->cert_rules = discard_const(rule_list);
    ssh_test_ctx->ssh_ctx->ca_db = discard_const(ABS_BUILD_DIR
                                                "/src/tests/test_CA/SSSD_test_CA.pem");

    set_cmd_cb(test_ssh_user_pubkey_cert_1_check);
    ret = sss_cmd_execute(ssh_test_ctx->cctx, SSS_SSH_GET_USER_PUBKEYS,
                          ssh_test_ctx->ssh_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(ssh_test_ctx->tctx);
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
        cmocka_unit_test_setup_teardown(test_ssh_user_no_pubkeys,
                                        ssh_test_setup, ssh_test_teardown),
        cmocka_unit_test_setup_teardown(test_ssh_user_pubkey,
                                        ssh_test_setup, ssh_test_teardown),
#ifdef HAVE_TEST_CA
        cmocka_unit_test_setup_teardown(test_ssh_user_pubkey_cert_disabled,
                                        ssh_test_setup, ssh_test_teardown),
        cmocka_unit_test_setup_teardown(test_ssh_user_pubkey_cert,
                                        ssh_test_setup, ssh_test_teardown),
        cmocka_unit_test_setup_teardown(test_ssh_user_pubkey_cert_with_rule,
                                        ssh_test_setup, ssh_test_teardown),
        cmocka_unit_test_setup_teardown(test_ssh_user_pubkey_cert_with_all_rules,
                                        ssh_test_setup, ssh_test_teardown),
        cmocka_unit_test_setup_teardown(test_ssh_user_pubkey_cert_with_all_rules_but_no_rules_present,
                                        ssh_test_setup, ssh_test_teardown),
        cmocka_unit_test_setup_teardown(test_ssh_user_pubkey_cert_with_no_rules,
                                        ssh_test_setup, ssh_test_teardown),
        cmocka_unit_test_setup_teardown(test_ssh_user_pubkey_cert_with_unknow_rule_name,
                                        ssh_test_setup, ssh_test_teardown),
        cmocka_unit_test_setup_teardown(test_ssh_user_pubkey_cert_with_rule_1,
                                        ssh_test_setup, ssh_test_teardown),
        cmocka_unit_test_setup_teardown(test_ssh_user_pubkey_pss_cert,
                                        ssh_test_setup, ssh_test_teardown),
#endif
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
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
     * they might not after a failed run. Remove the old DB to be sure */
    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    test_dom_suite_setup(TESTS_PATH);

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    if (rv == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    }

    return rv;
}
