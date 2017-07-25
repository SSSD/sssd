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
#include "confdb/confdb.h"

#include "util/crypto/sss_crypto.h"
#ifdef HAVE_NSS
#include "util/crypto/nss/nss_util.h"
#endif

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_pam_conf.ldb"
#define TEST_DOM_NAME "pam_test"
#define TEST_SUBDOM_NAME "test.subdomain"
#define TEST_ID_PROVIDER "ldap"

#define NSS_DB_PATH TESTS_PATH
#define NSS_DB "sql:"NSS_DB_PATH

#define TEST_TOKEN_NAME "SSSD Test Token"
#define TEST_MODULE_NAME "NSS-Internal"
#define TEST_KEY_ID "A5EF7DEE625CA5996C8D1BA7D036708161FD49E7"
#define TEST_TOKEN_CERT \
"MIIECTCCAvGgAwIBAgIBCTANBgkqhkiG9w0BAQsFADA0MRIwEAYDVQQKDAlJUEEu" \
"REVWRUwxHjAcBgNVBAMMFUNlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xNjA1MjMx" \
"NDE0MTVaFw0xODA1MjQxNDE0MTVaMDIxEjAQBgNVBAoMCUlQQS5ERVZFTDEcMBoG" \
"A1UEAwwTaXBhLWRldmVsLmlwYS5kZXZlbDCCASIwDQYJKoZIhvcNAQEBBQADggEP" \
"ADCCAQoCggEBALHvOzZy/3llvoAYxrtOpux0gDVvSuSRpTGOW/bjpgdTowvXoOb5" \
"G9Cy/9S6be7ZJ9D95lc/J9W8tX+ShKN8Q4b74l4WjmILQJ4dUsJ/BXfvoMPR8tw/" \
"G47dGbLZanMXdWGBSTuXhoiogZWib2DhSwrX2DbEH5L3OWooeAVU5ZWOw55/HD7O" \
"Q/7Of7H3tf4bvxNTFkxh39KQMG28wjPZSv+SZWNHMB+rj2yZgyeHBMkoPOPesAEi" \
"7KKHxw1MHSv2xBI1AiV+aMdKfYUMy0Rq3PrRU4274i3eaBX4Q9GnDi36K/7bHjbt" \
"LW0YTIW/L5/cH/BO88BREjxS3bEXAQqlKOcCAwEAAaOCASYwggEiMB8GA1UdIwQY" \
"MBaAFPci/0Km5D/L5z7YqwEc7E1/GwgcMDsGCCsGAQUFBwEBBC8wLTArBggrBgEF" \
"BQcwAYYfaHR0cDovL2lwYS1jYS5pcGEuZGV2ZWwvY2Evb2NzcDAOBgNVHQ8BAf8E" \
"BAMCBPAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMHQGA1UdHwRtMGsw" \
"aaAxoC+GLWh0dHA6Ly9pcGEtY2EuaXBhLmRldmVsL2lwYS9jcmwvTWFzdGVyQ1JM" \
"LmJpbqI0pDIwMDEOMAwGA1UECgwFaXBhY2ExHjAcBgNVBAMMFUNlcnRpZmljYXRl" \
"IEF1dGhvcml0eTAdBgNVHQ4EFgQUIJuWIts3m3uEYqJ9pUL0y7utTiEwDQYJKoZI" \
"hvcNAQELBQADggEBAB0GyqGxtZ99fsXA1+fHfAwKOwznT7Hh8hN9efEMBJICVud+" \
"ivUBOH6JpSTWgNLuBhrpebV/b/DSjhn+ayuvoPWng3hjwMbSEIe0euzCEdwVcokt" \
"bwNMMSeTxSg6wbJnEyZqQEIr2h/TR9dRNxE+RbQXyamW0fUxSVT16iueL0hMwszT" \
"jCfI/UZv3tDMHbh6D4811A0HO8daW7ufMGb/M+kDxYigJiL2gllMZ+6xba1RRgzF" \
"8Z+9gqZhCa7FEKJOPNR9RVtJs0qUUutMZrp1zpyx0GTmXQBA7LbgPxy8L68uymEQ" \
"XyQBwOYRORlnfGyu+Yc9c3E0Wx8Tlznz0lqPR9g="


static char CACHED_AUTH_TIMEOUT_STR[] = "4";
static const int CACHED_AUTH_TIMEOUT = 4;

struct pam_test_ctx {
    struct sss_test_ctx *tctx;
    struct sss_domain_info *subdom;

    struct resp_ctx *rctx;
    struct cli_ctx *cctx;
    struct sss_cmd_table *pam_cmds;
    struct pam_ctx *pctx;

    int ncache_hits;
    int exp_pam_status;
    bool provider_contacted;

    const char *pam_user_fqdn;
    const char *wrong_user_fqdn;
};

/* Must be global because it is needed in some wrappers */
struct pam_test_ctx *pam_test_ctx;

static errno_t setup_nss_db(void)
{
    int ret;
    FILE *fp;
    int status;
    pid_t child_pid;

    ret = mkdir(NSS_DB_PATH, 0775);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to create " NSS_DB_PATH ".\n");
        return ret;
    }

    child_pid = fork();
    if (child_pid == 0) { /* child */
        ret = execlp("certutil", "certutil", "-N", "--empty-password", "-d",
                     NSS_DB, NULL);
        if (ret == -1) {
            DEBUG(SSSDBG_FATAL_FAILURE, "execl() failed.\n");
            exit(-1);
        }
    } else if (child_pid > 0) {
        wait(&status);
    } else {
        ret = errno;
        DEBUG(SSSDBG_FATAL_FAILURE, "fork() failed\n");
        return ret;
    }

    fp = fopen(NSS_DB_PATH"/pkcs11.txt", "w");
    if (fp == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fopen() failed.\n");
        return ret;
    }
    ret = fprintf(fp, "library=libsoftokn3.so\nname=soft\n");
    if (ret < 0) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fprintf() failed.\n");
        return ret;
    }
    ret = fprintf(fp, "parameters=configdir='sql:%s/src/tests/cmocka/p11_nssdb' dbSlotDescription='SSSD Test Slot' dbTokenDescription='SSSD Test Token' secmod='secmod.db' flags=readOnly \n\n", ABS_SRC_DIR);
    if (ret < 0) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fprintf() failed.\n");
        return ret;
    }
    ret = fclose(fp);
    if (ret != 0) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fclose() failed.\n");
        return ret;
    }

    return EOK;
}

static void cleanup_nss_db(void)
{
    int ret;

    ret = unlink(NSS_DB_PATH"/cert9.db");
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to remove cert9.db.\n");
    }

    ret = unlink(NSS_DB_PATH"/key4.db");
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to remove key4.db.\n");
    }

    ret = unlink(NSS_DB_PATH"/pkcs11.txt");
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to remove pkcs11.db.\n");
    }

    ret = rmdir(NSS_DB_PATH);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to remove " NSS_DB_PATH "\n");
    }
}

struct pam_ctx *mock_pctx(TALLOC_CTX *mem_ctx)
{
    struct pam_ctx *pctx;
    errno_t ret;

    pctx = talloc_zero(mem_ctx, struct pam_ctx);
    assert_non_null(pctx);

    ret = sss_hash_create(pctx, 10, &pctx->id_table);
    assert_int_equal(ret, EOK);

    /* Two NULLs so that tests can just assign a const to the first slot
     * should they need it. The code iterates until first NULL anyway
     */
    pctx->app_services = talloc_zero_array(pctx, char *, 2);
    if (pctx->app_services == NULL) {
        talloc_free(pctx);
        return NULL;
    }

    return pctx;
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

static int add_pam_params(struct sss_test_conf_param pam_params[],
                          struct confdb_ctx *cdb)
{
    return add_confdb_params(pam_params, cdb, CONFDB_PAM_CONF_ENTRY);
}

static int add_monitor_params(struct sss_test_conf_param monitor_params[],
                              struct confdb_ctx *cdb)
{
    return add_confdb_params(monitor_params, cdb, CONFDB_MONITOR_CONF_ENTRY);
}

void test_pam_setup(struct sss_test_conf_param dom_params[],
                    struct sss_test_conf_param pam_params[],
                    struct sss_test_conf_param monitor_params[],
                    void **state)
{
    struct cli_protocol *prctx;
    errno_t ret;

    pam_test_ctx = talloc_zero(NULL, struct pam_test_ctx);
    assert_non_null(pam_test_ctx);

    pam_test_ctx->tctx = create_dom_test_ctx(pam_test_ctx, TESTS_PATH,
                                             TEST_CONF_DB, TEST_DOM_NAME,
                                             TEST_ID_PROVIDER, dom_params);
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

    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = add_monitor_params(monitor_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    /* Create client context */
    pam_test_ctx->cctx = mock_cctx(pam_test_ctx, pam_test_ctx->rctx);
    assert_non_null(pam_test_ctx->cctx);
    pam_test_ctx->cctx->ev = pam_test_ctx->tctx->ev;

    prctx = mock_prctx(pam_test_ctx->cctx);
    assert_non_null(prctx);
    pam_test_ctx->cctx->protocol_ctx = prctx;
    prctx->cli_protocol_version = register_cli_protocol_version();
}

static void pam_test_setup_common(void)
{
    errno_t ret;

    pam_test_ctx->pam_user_fqdn = \
                    sss_create_internal_fqname(pam_test_ctx,
                                               "pamuser",
                                               pam_test_ctx->tctx->dom->name);
    assert_non_null(pam_test_ctx->pam_user_fqdn);

    pam_test_ctx->wrong_user_fqdn = \
                    sss_create_internal_fqname(pam_test_ctx,
                                               "wronguser",
                                               pam_test_ctx->tctx->dom->name);
    assert_non_null(pam_test_ctx->wrong_user_fqdn);

    /* integer values cannot be set by pam_params */
    pam_test_ctx->pctx->id_timeout = 5;

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(pam_test_ctx->tctx->dom,
                         pam_test_ctx->pam_user_fqdn,
                         123, 456, "pam user",
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

    /* Prime the cache with a user for wrong matches */
    ret = sysdb_add_user(pam_test_ctx->tctx->dom,
                         pam_test_ctx->wrong_user_fqdn,
                         321, 654, "wrong user",
                         "/home/wronguser", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    /* Add entry to the initgr cache to make sure no initgr request is sent to
     * the backend */
    ret = pam_initgr_cache_set(pam_test_ctx->pctx->rctx->ev,
                               pam_test_ctx->pctx->id_table,
                               discard_const("wronguser"),
                               pam_test_ctx->pctx->id_timeout);
    assert_int_equal(ret, EOK);
}

static int pam_test_setup(void **state)
{
    struct sss_test_conf_param dom_params[] = {
        { "enumerate", "false" },
        { "cache_credentials", "true" },
        { NULL, NULL },             /* Sentinel */
    };

    struct sss_test_conf_param pam_params[] = {
        { "p11_child_timeout", "30" },
        { NULL, NULL },             /* Sentinel */
    };

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "no_ocsp"},
        { NULL, NULL },             /* Sentinel */
    };

    test_pam_setup(dom_params, pam_params, monitor_params, state);

    pam_test_setup_common();
    return 0;
}

#ifdef HAVE_NSS
static int pam_test_setup_no_verification(void **state)
{
    struct sss_test_conf_param dom_params[] = {
        { "enumerate", "false" },
        { "cache_credentials", "true" },
        { NULL, NULL }, /* Sentinel */
    };

    struct sss_test_conf_param pam_params[] = {
        { "p11_child_timeout", "30" },
        { NULL, NULL }, /* Sentinel */
    };

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "no_verification" },
        { NULL, NULL }, /* Sentinel */
    };

    test_pam_setup(dom_params, pam_params, monitor_params, state);

    pam_test_setup_common();
    return 0;
}
#endif /* HAVE_NSS */

static int pam_cached_test_setup(void **state)
{
    struct sss_test_conf_param dom_params[] = {
        { "enumerate", "false" },
        { "cache_credentials", "true" },
        { "cached_auth_timeout", CACHED_AUTH_TIMEOUT_STR },
        { NULL, NULL },             /* Sentinel */
    };

    struct sss_test_conf_param pam_params[] = {
        { "p11_child_timeout", "30" },
        { NULL, NULL },             /* Sentinel */
    };

    struct sss_test_conf_param monitor_params[] = {
        { "certificate_verification", "no_ocsp"},
        { NULL, NULL },             /* Sentinel */
    };

    test_pam_setup(dom_params, pam_params, monitor_params, state);

    pam_test_setup_common();
    return 0;
}

static int pam_test_teardown(void **state)
{
    int ret;

    ret = sysdb_delete_user(pam_test_ctx->tctx->dom,
                            pam_test_ctx->pam_user_fqdn, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_delete_user(pam_test_ctx->tctx->dom,
                            pam_test_ctx->wrong_user_fqdn, 0);
    assert_int_equal(ret, EOK);

    talloc_free(pam_test_ctx);
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
    pam_test_ctx->provider_contacted = true;

    /* Set expected status */
    preq->pd->pam_status = pam_test_ctx->exp_pam_status;

    preq->callback(preq);

    return EOK;
}

static void mock_input_pam_ex(TALLOC_CTX *mem_ctx,
                              const char *name,
                              const char *pwd,
                              const char *fa2,
                              const char *svc,
                              bool contact_dp)
{
    size_t buf_size;
    uint8_t *m_buf;
    uint8_t *buf;
    struct pam_items pi = { 0 };
    int ret;
    size_t needed_size;
    uint8_t *authtok;
    char *s_name;
    char *dom;

    if (name != NULL) {
        pi.pam_user = name;
        pi.pam_user_size = strlen(pi.pam_user) + 1;
    } else {
        pi.pam_user = "";
        pi.pam_user_size = 0;
    }

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

    if (svc == NULL) {
        svc = "pam_test_service";
    }
    pi.pam_service = svc;
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

    if (strrchr(name, '@') == NULL) {
        mock_parse_inp(name, NULL, EOK);
    } else {
        ret = sss_parse_internal_fqname(mem_ctx, name, &s_name, &dom);
        mock_parse_inp(s_name, dom, EOK);
    }

    if (contact_dp) {
        mock_account_recv_simple();
    }
}

static void mock_input_pam(TALLOC_CTX *mem_ctx,
                           const char *name,
                           const char *pwd,
                           const char *fa2)
{
    return mock_input_pam_ex(mem_ctx, name, pwd, fa2, NULL, true);
}

static void mock_input_pam_cert(TALLOC_CTX *mem_ctx, const char *name,
                                const char *pin, const char *service,
                                acct_cb_t acct_cb, const char *cert,
                                bool only_one_provider_call)
{
    size_t buf_size;
    uint8_t *m_buf;
    uint8_t *buf;
    struct pam_items pi = { 0 };
    int ret;
    bool already_mocked = false;

    if (name != NULL) {
        pi.pam_user = name;
        pi.pam_user_size = strlen(pi.pam_user) + 1;
    } else {
        pi.pam_user = "";
        pi.pam_user_size = 0;
    }

    if (pin != NULL) {
        pi.pam_authtok = discard_const(pin);
        pi.pam_authtok_size = strlen(pi.pam_authtok) + 1;
        pi.pam_authtok_type = SSS_AUTHTOK_TYPE_SC_PIN;
    }

    pi.pam_service = service == NULL ? "login" : service;
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

    if (acct_cb != NULL) {
        mock_account_recv(0, 0, NULL, acct_cb, discard_const(cert));
        already_mocked = true;
    }

    if (name != NULL) {
        mock_parse_inp(name, NULL, EOK);
        if (!(only_one_provider_call && already_mocked)) {
            mock_account_recv_simple();
        }
    }
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

#define PKCS11_LOGIN_TOKEN_ENV_NAME "PKCS11_LOGIN_TOKEN_NAME"

static int test_pam_cert_check_gdm_smartcard(uint32_t status, uint8_t *body,
                                             size_t blen)
{
    size_t rp = 0;
    uint32_t val;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, pam_test_ctx->exp_pam_status);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 3);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_DOMAIN_NAME);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 9);

    assert_int_equal(*(body + rp + val - 1), 0);
    assert_string_equal(body + rp, TEST_DOM_NAME);
    rp += val;

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_ENV_ITEM);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, (strlen(PKCS11_LOGIN_TOKEN_ENV_NAME "=")
                           + sizeof(TEST_TOKEN_NAME)));
    assert_string_equal(body + rp,
                        PKCS11_LOGIN_TOKEN_ENV_NAME "=" TEST_TOKEN_NAME);
    rp += val;

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, SSS_PAM_CERT_INFO);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, (sizeof("pamuser@"TEST_DOM_NAME)
                                + sizeof(TEST_TOKEN_NAME)
                                + sizeof(TEST_MODULE_NAME)
                                + sizeof(TEST_KEY_ID)));

    assert_int_equal(*(body + rp + sizeof("pamuser@"TEST_DOM_NAME) - 1), 0);
    assert_string_equal(body + rp, "pamuser@"TEST_DOM_NAME);
    rp += sizeof("pamuser@"TEST_DOM_NAME);

    assert_int_equal(*(body + rp + sizeof(TEST_TOKEN_NAME) - 1), 0);
    assert_string_equal(body + rp, TEST_TOKEN_NAME);
    rp += sizeof(TEST_TOKEN_NAME);

    assert_int_equal(*(body + rp + sizeof(TEST_MODULE_NAME) - 1), 0);
    assert_string_equal(body + rp, TEST_MODULE_NAME);
    rp += sizeof(TEST_MODULE_NAME);

    assert_int_equal(*(body + rp + sizeof(TEST_KEY_ID) - 1), 0);
    assert_string_equal(body + rp, TEST_KEY_ID);
    rp += sizeof(TEST_KEY_ID);

    assert_int_equal(rp, blen);
    return EOK;
}

static int test_pam_cert_check_ex(uint32_t status, uint8_t *body, size_t blen,
                                  enum response_type type, const char *name)
{
    size_t rp = 0;
    uint32_t val;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, pam_test_ctx->exp_pam_status);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    if (name == NULL || *name == '\0') {
        assert_int_equal(val, 1);
    } else {
        assert_int_equal(val, 2);

        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
        assert_int_equal(val, SSS_PAM_DOMAIN_NAME);

        SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
        assert_int_equal(val, 9);

        assert_int_equal(*(body + rp + val - 1), 0);
        assert_string_equal(body + rp, TEST_DOM_NAME);
        rp += val;
    }

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, type);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, (strlen(name) + 1
                                + sizeof(TEST_TOKEN_NAME)
                                + sizeof(TEST_MODULE_NAME)
                                + sizeof(TEST_KEY_ID)));

    assert_int_equal(*(body + rp + strlen(name)), 0);
    assert_string_equal(body + rp, name);
    rp += strlen(name) + 1;

    assert_int_equal(*(body + rp + sizeof(TEST_TOKEN_NAME) - 1), 0);
    assert_string_equal(body + rp, TEST_TOKEN_NAME);
    rp += sizeof(TEST_TOKEN_NAME);

    assert_int_equal(*(body + rp + sizeof(TEST_MODULE_NAME) - 1), 0);
    assert_string_equal(body + rp, TEST_MODULE_NAME);
    rp += sizeof(TEST_MODULE_NAME);

    assert_int_equal(*(body + rp + sizeof(TEST_KEY_ID) - 1), 0);
    assert_string_equal(body + rp, TEST_KEY_ID);
    rp += sizeof(TEST_KEY_ID);

    assert_int_equal(rp, blen);

    return EOK;
}

static int test_pam_cert_check(uint32_t status, uint8_t *body, size_t blen)
{
    return test_pam_cert_check_ex(status, body, blen,
                                  SSS_PAM_CERT_INFO, "pamuser@"TEST_DOM_NAME);
}

static int test_pam_cert_check_with_hint(uint32_t status, uint8_t *body,
                                         size_t blen)
{
    return test_pam_cert_check_ex(status, body, blen,
                                  SSS_PAM_CERT_INFO_WITH_HINT,
                                  "pamuser@"TEST_DOM_NAME);
}

static int test_pam_cert_check_with_hint_no_user(uint32_t status, uint8_t *body,
                                                 size_t blen)
{
    return test_pam_cert_check_ex(status, body, blen,
                                  SSS_PAM_CERT_INFO_WITH_HINT, "");
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

static int test_pam_successful_cached_auth_check(uint32_t status,
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

static int test_pam_simple_check_success(uint32_t status,
                                                uint8_t *body, size_t blen)
{
    pam_test_ctx->exp_pam_status = PAM_SUCCESS;
    return test_pam_simple_check(status, body, blen);
}

static int test_pam_creds_insufficient_check(uint32_t status,
                                             uint8_t *body, size_t blen)
{
    size_t rp = 0;
    uint32_t val;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, PAM_CRED_INSUFFICIENT);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 0);

    return EOK;
}

static int test_pam_user_unknown_check(uint32_t status,
                                       uint8_t *body, size_t blen)
{
    size_t rp = 0;
    uint32_t val;

    assert_int_equal(status, 0);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, PAM_USER_UNKNOWN);

    SAFEALIGN_COPY_UINT32(&val, body + rp, &rp);
    assert_int_equal(val, 0);

    return EOK;
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

    /* make sure pam_status is not touched by setting it to a value which is
     * not used by SSSD. */
    pam_test_ctx->exp_pam_status = _PAM_RETURN_VALUES;
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

/* Cached on-line authentication */

static void common_test_pam_cached_auth(const char *pwd)
{
    int ret;

    mock_input_pam(pam_test_ctx, "pamuser", pwd, NULL);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_SUCCESS;
    set_cmd_cb(test_pam_successful_cached_auth_check);

    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cached_auth_success(void **state)
{
    int ret;

    common_test_pam_cached_auth("12345");

    /* Back end should be contacted */
    assert_true(pam_test_ctx->provider_contacted);

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    /* Reset before next call */
    pam_test_ctx->provider_contacted = false;

    pam_test_ctx->tctx->done = false;

    common_test_pam_cached_auth("12345");

    /* Back end should not be contacted */
    assert_false(pam_test_ctx->provider_contacted);
}

void test_pam_cached_auth_wrong_pw(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    ret = pam_set_last_online_auth_with_curr_token(pam_test_ctx->tctx->dom,
                                                   pam_test_ctx->pam_user_fqdn,
                                                   time(NULL));
    assert_int_equal(ret, EOK);

    common_test_pam_cached_auth("11111");

    /* Back end should be contacted */
    assert_true(pam_test_ctx->provider_contacted);
}

/* test cached_auth_timeout option */
void test_pam_cached_auth_opt_timeout(void **state)
{
    int ret;
    uint64_t last_online;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    last_online = time(NULL) - CACHED_AUTH_TIMEOUT - 1;
    ret = pam_set_last_online_auth_with_curr_token(pam_test_ctx->tctx->dom,
                                                   pam_test_ctx->pam_user_fqdn,
                                                   last_online);
    assert_int_equal(ret, EOK);

    common_test_pam_cached_auth("12345");

    /* Back end should be contacted */
    assert_true(pam_test_ctx->provider_contacted);
}

/* too long since last on-line authentication */
void test_pam_cached_auth_timeout(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    ret = pam_set_last_online_auth_with_curr_token(pam_test_ctx->tctx->dom,
                                                   pam_test_ctx->pam_user_fqdn,
                                                   0);
    assert_int_equal(ret, EOK);

    common_test_pam_cached_auth("12345");

    /* Back end should be contacted */
    assert_true(pam_test_ctx->provider_contacted);
}

void test_pam_cached_auth_success_combined_pw_with_cached_2fa(void **state)
{
    int ret;

    common_test_pam_cached_auth("12345678");

    assert_true(pam_test_ctx->provider_contacted);

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345678", SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);

    /* Reset before next call */
    pam_test_ctx->provider_contacted = false;

    pam_test_ctx->tctx->done = false;

    common_test_pam_cached_auth("12345678");

    assert_false(pam_test_ctx->provider_contacted);
}

void test_pam_cached_auth_failed_combined_pw_with_cached_2fa(void **state)
{
    int ret;

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345678", SSS_AUTHTOK_TYPE_2FA, 5);
    assert_int_equal(ret, EOK);
    ret = pam_set_last_online_auth_with_curr_token(pam_test_ctx->tctx->dom,
                                                   pam_test_ctx->pam_user_fqdn,
                                                   time(NULL));
    assert_int_equal(ret, EOK);

    common_test_pam_cached_auth("1111abcde");

    assert_true(pam_test_ctx->provider_contacted);
}

/* Off-line authentication */

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

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
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

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
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

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
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

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
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

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345",
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

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345",
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

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345",
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

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  "12345",
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

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
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

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
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

    ret = sysdb_cache_password_ex(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
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

void test_pam_preauth_no_logon_name(void **state)
{
    int ret;

    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL, NULL, NULL, false);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_creds_insufficient_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_auth_no_upn_logon_name(void **state)
{
    int ret;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);

    mock_input_pam_ex(pam_test_ctx, "upn@"TEST_DOM_NAME, "12345", NULL, NULL,
                      true);
    mock_account_recv_simple();

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    pam_test_ctx->exp_pam_status = PAM_USER_UNKNOWN;
    set_cmd_cb(test_pam_simple_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_auth_upn_logon_name(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;

    ret = sysdb_cache_password(pam_test_ctx->tctx->dom,
                               pam_test_ctx->pam_user_fqdn,
                               "12345");
    assert_int_equal(ret, EOK);
    attrs = sysdb_new_attrs(pam_test_ctx);
    assert_non_null(attrs);
    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, "upn@"TEST_DOM_NAME);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(pam_test_ctx->tctx->dom,
                              pam_test_ctx->pam_user_fqdn,
                              attrs,
                              LDB_FLAG_MOD_ADD);
    assert_int_equal(ret, EOK);

    mock_input_pam_ex(pam_test_ctx, "upn@"TEST_DOM_NAME, "12345", NULL, NULL,
                      true);
    mock_account_recv_simple();

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_successful_offline_auth_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}


static void set_cert_auth_param(struct pam_ctx *pctx, const char *dbpath)
{
    pam_test_ctx->pctx->cert_auth = true;
    pam_test_ctx->pctx->nss_db = discard_const(dbpath);
}

void test_pam_preauth_cert_nocert(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, "/no/path");

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL, NULL, NULL, false);

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

static int test_lookup_by_cert_cb(void *pvt)
{
    int ret;
    struct sysdb_attrs *attrs;
    unsigned char *der = NULL;
    size_t der_size;

    if (pvt != NULL) {

        attrs = sysdb_new_attrs(pam_test_ctx);
        assert_non_null(attrs);

        der = sss_base64_decode(pam_test_ctx, pvt, &der_size);
        assert_non_null(der);

        ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_MAPPED_CERT, der, der_size);
        talloc_free(der);
        assert_int_equal(ret, EOK);

        ret = sysdb_set_user_attr(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->pam_user_fqdn,
                                  attrs,
                                  LDB_FLAG_MOD_ADD);
        assert_int_equal(ret, EOK);
    }

    return EOK;
}

static int test_lookup_by_cert_double_cb(void *pvt)
{
    int ret;
    struct sysdb_attrs *attrs;
    unsigned char *der = NULL;
    size_t der_size;

    if (pvt != NULL) {

        ret = test_lookup_by_cert_cb(pvt);
        assert_int_equal(ret, EOK);

        attrs = sysdb_new_attrs(pam_test_ctx);
        assert_non_null(attrs);

        der = sss_base64_decode(pam_test_ctx, pvt, &der_size);
        assert_non_null(der);

        ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_MAPPED_CERT, der, der_size);
        talloc_free(der);
        assert_int_equal(ret, EOK);

        ret = sysdb_set_user_attr(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->wrong_user_fqdn,
                                  attrs,
                                  LDB_FLAG_MOD_ADD);
        assert_int_equal(ret, EOK);
    }

    return EOK;
}

static int test_lookup_by_cert_wrong_user_cb(void *pvt)
{
    int ret;
    struct sysdb_attrs *attrs;
    unsigned char *der = NULL;
    size_t der_size;

    if (pvt != NULL) {
        attrs = sysdb_new_attrs(pam_test_ctx);
        assert_non_null(attrs);

        der = sss_base64_decode(pam_test_ctx, pvt, &der_size);
        assert_non_null(der);

        ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_MAPPED_CERT, der, der_size);
        talloc_free(der);
        assert_int_equal(ret, EOK);

        ret = sysdb_set_user_attr(pam_test_ctx->tctx->dom,
                                  pam_test_ctx->wrong_user_fqdn,
                                  attrs,
                                  LDB_FLAG_MOD_ADD);
        assert_int_equal(ret, EOK);
    }

    return EOK;
}


void test_pam_preauth_cert_nomatch(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, NSS_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL,
                        test_lookup_by_cert_cb, NULL, false);

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

void test_pam_preauth_cert_match(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, NSS_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL,
                        test_lookup_by_cert_cb, TEST_TOKEN_CERT, false);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test if PKCS11_LOGIN_TOKEN_NAME is added for the gdm-smartcard service */
void test_pam_preauth_cert_match_gdm_smartcard(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, NSS_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, "gdm-smartcard",
                        test_lookup_by_cert_cb, TEST_TOKEN_CERT, false);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check_gdm_smartcard);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_match_wrong_user(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, NSS_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", NULL, NULL,
                        test_lookup_by_cert_wrong_user_cb,
                        TEST_TOKEN_CERT, false);

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


void test_pam_preauth_cert_no_logon_name(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, NSS_DB);

    /* If no logon name is given the user is looked by certificate first.
     * Since there is a matching user the upcoming lookup by name will find
     * the user entry. But since we force the lookup by name to go to the
     * backend to make sure the group-membership data is up to date the
     * backend response has to be mocked twice.
     * Additionally sss_parse_inp_recv() must be mocked because the cache
     * request will be done with the username found by the certificate
     * lookup. */
    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL,
                        test_lookup_by_cert_cb, TEST_TOKEN_CERT, false);
    mock_account_recv_simple();
    mock_parse_inp("pamuser", NULL, EOK);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_no_logon_name_with_hint(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, NSS_DB);
    pam_test_ctx->rctx->domains->user_name_hint = true;

    /* If no logon name is given the user is looked by certificate first.
     * Since user name hint is enabled we do not have to search the user
     * during pre-auth and there is no need for an extra mocked response as in
     * test_pam_preauth_cert_no_logon_name. */
    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL,
                        test_lookup_by_cert_cb, TEST_TOKEN_CERT, false);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check_with_hint);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_no_logon_name_double_cert(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, NSS_DB);

    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL,
                        test_lookup_by_cert_double_cb, TEST_TOKEN_CERT, false);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_creds_insufficient_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_no_logon_name_double_cert_with_hint(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, NSS_DB);
    pam_test_ctx->rctx->domains->user_name_hint = true;

    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL,
                        test_lookup_by_cert_double_cb, TEST_TOKEN_CERT, false);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_cert_check_with_hint_no_user);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_no_cert_no_logon_name(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, "/no/path");

    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL, NULL, NULL, false);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_user_unknown_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_preauth_cert_no_logon_name_no_match(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, NSS_DB);

    mock_input_pam_cert(pam_test_ctx, NULL, NULL, NULL,
                        test_lookup_by_cert_cb, NULL, false);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_PREAUTH);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_user_unknown_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_PREAUTH,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cert_auth(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, NSS_DB);

    /* Here the last option must be set to true because the backend is only
     * connected once. During authentication the backend is connected first to
     * see if it can handle Smartcard authentication, but before that the user
     * is looked up. Since the first mocked reply already adds the certificate
     * to the user entry the lookup by certificate will already find the user
     * in the cache and no second request to the backend is needed. */
    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456", NULL,
                        test_lookup_by_cert_cb, TEST_TOKEN_CERT, true);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;


    set_cmd_cb(test_pam_simple_check_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_pam_cert_auth_double_cert(void **state)
{
    int ret;

    set_cert_auth_param(pam_test_ctx->pctx, NSS_DB);

    mock_input_pam_cert(pam_test_ctx, "pamuser", "123456", NULL,
                        test_lookup_by_cert_double_cb, TEST_TOKEN_CERT, true);

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Assume backend cannot handle Smartcard credentials */
    pam_test_ctx->exp_pam_status = PAM_BAD_ITEM;

    set_cmd_cb(test_pam_simple_check_success);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_filter_response(void **state)
{
    int ret;
    struct pam_data *pd;
    uint8_t offline_auth_data[(sizeof(uint32_t) + sizeof(int64_t))];
    uint32_t info_type;
    char *env;

    struct sss_test_conf_param pam_params[] = {
        { CONFDB_PAM_VERBOSITY, "1" },
        { CONFDB_PAM_RESPONSE_FILTER, NULL },
        { NULL, NULL },             /* Sentinel */
    };

    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    pd = talloc_zero(pam_test_ctx, struct pam_data);
    assert_non_null(pd);

    pd->service = discard_const("MyService");

    env = talloc_asprintf(pd, "%s=%s", "MyEnv", "abcdef");
    assert_non_null(env);

    ret = pam_add_response(pd, SSS_PAM_ENV_ITEM,
                           strlen(env) + 1, (uint8_t *) env);
    assert_int_equal(ret, EOK);

    info_type = SSS_PAM_USER_INFO_OFFLINE_AUTH;
    memset(offline_auth_data, 0, sizeof(offline_auth_data));
    memcpy(offline_auth_data, &info_type, sizeof(uint32_t));
    ret = pam_add_response(pd, SSS_PAM_USER_INFO,
                           sizeof(offline_auth_data), offline_auth_data);
    assert_int_equal(ret, EOK);

    /* pd->resp_list points to the SSS_PAM_USER_INFO and pd->resp_list->next
     * to the SSS_PAM_ENV_ITEM message. */


    /* Test CONFDB_PAM_VERBOSITY option */
    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    /* SSS_PAM_USER_INFO_OFFLINE_AUTH message will only be shown with
     * pam_verbosity 2 or above if cache password never expires. */
    pam_params[0].value = "2";
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_false(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    pam_params[0].value = "0";
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    /* Test CONFDB_PAM_RESPONSE_FILTER option */
    pam_params[1].value = "NoSuchOption";
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    pam_params[1].value = "ENV"; /* filter all environment variables */
                                 /* for all services */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    pam_params[1].value = "ENV:"; /* filter all environment variables */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    pam_params[1].value = "ENV::"; /* filter all environment variables */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    pam_params[1].value = "ENV:abc:"; /* variable name does not match */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    pam_params[1].value = "ENV:abc:MyService"; /* variable name does not match */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    pam_params[1].value = "ENV::abc"; /* service name does not match */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    /* service name does not match */
    pam_params[1].value = "ENV:MyEnv:abc";
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_false(pd->resp_list->next->do_not_send_to_client);

    pam_params[1].value = "ENV:MyEnv"; /* match */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    pam_params[1].value = "ENV:MyEnv:"; /* match */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    pam_params[1].value = "ENV:MyEnv:MyService"; /* match */
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    /* multiple rules with a match */
    pam_params[1].value = "ENV:abc:def, "
                          "ENV:MyEnv:MyService, "
                          "ENV:stu:xyz";
    ret = add_pam_params(pam_params, pam_test_ctx->rctx->cdb);
    assert_int_equal(ret, EOK);

    ret = filter_responses(pam_test_ctx->rctx->cdb, pd->resp_list, pd);
    assert_int_equal(ret, EOK);
    assert_true(pd->resp_list->do_not_send_to_client);
    assert_true(pd->resp_list->next->do_not_send_to_client);

    talloc_free(pd);
}

static int pam_test_setup_appsvc_posix_dom(void **state)
{
    int ret;

    ret = pam_test_setup(state);
    if (ret != EOK) {
        return ret;
    }

    /* This config option is only read on startup, which is not executed
     * in test, so we can't just pass in a param
     */
    pam_test_ctx->pctx->app_services[0] = discard_const("app_svc");
    return 0;
}

void test_appsvc_posix_dom(void **state)
{
    int ret;

    /* The domain is POSIX, the request will skip over it */
    mock_input_pam_ex(pam_test_ctx, "pamuser", NULL, NULL, "app_svc", false);
    pam_test_ctx->exp_pam_status = PAM_USER_UNKNOWN;

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_user_unknown_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

    ret = test_ev_loop(pam_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_not_appsvc_posix_dom(void **state)
{
    int ret;

    /* A different service than the app one can authenticate against a POSIX domain */
    mock_input_pam_ex(pam_test_ctx, "pamuser", NULL, NULL, "not_app_svc", true);

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

static int pam_test_setup_appsvc_app_dom(void **state)
{
    struct sss_test_conf_param dom_params[] = {
        { "domain_type", "application" },
        { NULL, NULL },             /* Sentinel */
    };
    struct sss_test_conf_param pam_params[] = {
        { NULL, NULL },             /* Sentinel */
    };
    struct sss_test_conf_param monitor_params[] = {
        { NULL, NULL },             /* Sentinel */
    };


    test_pam_setup(dom_params, pam_params, monitor_params, state);
    pam_test_setup_common();

    /* This config option is only read on startup, which is not executed
     * in test, so we can't just pass in a param
     */
    pam_test_ctx->pctx->app_services[0] = discard_const("app_svc");
    return 0;
}

void test_appsvc_app_dom(void **state)
{
    int ret;

    /* The domain is POSIX, the request will skip over it */
    mock_input_pam_ex(pam_test_ctx, "pamuser", NULL, NULL, "app_svc", true);

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

void test_not_appsvc_app_dom(void **state)
{
    int ret;

    /* A different service than the app one can authenticate against a POSIX domain */
    mock_input_pam_ex(pam_test_ctx, "pamuser", NULL, NULL, "not_app_svc", false);

    pam_test_ctx->exp_pam_status = PAM_USER_UNKNOWN;

    will_return(__wrap_sss_packet_get_cmd, SSS_PAM_AUTHENTICATE);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_pam_user_unknown_check);
    ret = sss_cmd_execute(pam_test_ctx->cctx, SSS_PAM_AUTHENTICATE,
                          pam_test_ctx->pam_cmds);
    assert_int_equal(ret, EOK);

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
        cmocka_unit_test_setup_teardown(test_pam_preauth_no_logon_name,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_auth_no_upn_logon_name,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_auth_upn_logon_name,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cached_auth_success,
                                        pam_cached_test_setup,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cached_auth_wrong_pw,
                                        pam_cached_test_setup,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cached_auth_opt_timeout,
                                        pam_cached_test_setup,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cached_auth_timeout,
                                        pam_cached_test_setup,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cached_auth_success_combined_pw_with_cached_2fa,
                                        pam_cached_test_setup,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cached_auth_failed_combined_pw_with_cached_2fa,
                                        pam_cached_test_setup,
                                        pam_test_teardown),
/* p11_child is not built without NSS */
#ifdef HAVE_NSS
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_nocert,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_nomatch,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_match,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_match_gdm_smartcard,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_match_wrong_user,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_cert_no_logon_name,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                                  test_pam_preauth_cert_no_logon_name_with_hint,
                                  pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                                test_pam_preauth_cert_no_logon_name_double_cert,
                                pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                      test_pam_preauth_cert_no_logon_name_double_cert_with_hint,
                      pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_preauth_no_cert_no_logon_name,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(
                                   test_pam_preauth_cert_no_logon_name_no_match,
                                   pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth,
                                        pam_test_setup_no_verification,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_pam_cert_auth_double_cert,
                                        pam_test_setup, pam_test_teardown),
#endif /* HAVE_NSS */

        cmocka_unit_test_setup_teardown(test_filter_response,
                                        pam_test_setup, pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_appsvc_posix_dom,
                                        pam_test_setup_appsvc_posix_dom,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_not_appsvc_posix_dom,
                                        pam_test_setup_appsvc_posix_dom,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_appsvc_app_dom,
                                        pam_test_setup_appsvc_app_dom,
                                        pam_test_teardown),
        cmocka_unit_test_setup_teardown(test_not_appsvc_app_dom,
                                        pam_test_setup_appsvc_posix_dom,
                                        pam_test_teardown),
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

    cleanup_nss_db();
    rv = setup_nss_db();
    if (rv != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "setup_nss_db failed.\n");
        exit(-1);
    }

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    if (rv == 0 && !no_cleanup) {
        cleanup_nss_db();
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    }

#ifdef HAVE_NSS
    /* Cleanup NSS and NSPR to make valgrund happy. */
    nspr_nss_cleanup();
#endif

    return rv;
}
