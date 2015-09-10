/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: NSS responder tests

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

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"
#include "responder/common/negcache.h"
#include "responder/nss/nsssrv.h"
#include "responder/nss/nsssrv_private.h"
#include "sss_client/idmap/sss_nss_idmap.h"
#include "util/util_sss_idmap.h"
#include "db/sysdb_private.h"   /* new_subdomain() */

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_nss_conf.ldb"
#define TEST_DOM_NAME "nss_test"
#define TEST_SUBDOM_NAME "test.subdomain"
#define TEST_ID_PROVIDER "ldap"
#define TEST_DOM_SID "S-1-5-21-444379608-1639770488-2995963434"

struct nss_test_ctx {
    struct sss_test_ctx *tctx;
    struct sss_domain_info *subdom;

    struct resp_ctx *rctx;
    struct cli_ctx *cctx;
    struct sss_cmd_table *nss_cmds;
    struct nss_ctx *nctx;

    int ncache_hits;
};

const char *global_extra_attrs[] = {"phone", "mobile", NULL};

struct nss_test_ctx *nss_test_ctx;

/* Mock NSS structure */
struct nss_ctx *
mock_nctx(TALLOC_CTX *mem_ctx)
{
    struct nss_ctx *nctx;
    errno_t ret;
    enum idmap_error_code err;

    nctx = talloc_zero(mem_ctx, struct nss_ctx);
    if (!nctx) {
        return NULL;
    }

    ret = sss_ncache_init(nctx, &nctx->ncache);
    if (ret != EOK) {
        talloc_free(nctx);
        return NULL;
    }
    nctx->neg_timeout = 10;
    nctx->pwfield = discard_const("*");

    err = sss_idmap_init(sss_idmap_talloc, nctx, sss_idmap_talloc_free,
                         &nctx->idmap_ctx);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "sss_idmap_init failed.\n");
        talloc_free(nctx);
        return NULL;
    }

    return nctx;
}

/* Mock reading requests from a client. Use values passed from mock
 * instead
 */
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
        len = strlen((const char *) *body)+1;
    }
    *blen = len;
    return;
}

/* Mock returning result to client. Terminate the unit test instead. */
typedef int (*cmd_cb_fn_t)(uint32_t, uint8_t *, size_t );

static void set_cmd_cb(cmd_cb_fn_t fn)
{
    will_return(__wrap_sss_cmd_done, fn);
}

void __wrap_sss_cmd_done(struct cli_ctx *cctx, void *freectx)
{
    struct sss_packet *packet = cctx->creq->out;
    uint8_t *body;
    size_t blen;
    cmd_cb_fn_t check_cb;

    check_cb = sss_mock_ptr_type(cmd_cb_fn_t);

    __real_sss_packet_get_body(packet, &body, &blen);

    nss_test_ctx->tctx->error = check_cb(sss_packet_get_status(packet),
                                         body, blen);
    nss_test_ctx->tctx->done = true;
}

enum sss_cli_command __wrap_sss_packet_get_cmd(struct sss_packet *packet)
{
    return sss_mock_type(enum sss_cli_command);
}

int __wrap_sss_cmd_send_empty(struct cli_ctx *cctx, TALLOC_CTX *freectx)
{
    nss_test_ctx->tctx->done = true;
    nss_test_ctx->tctx->error = ENOENT;
    return EOK;
}

/* Intercept negative cache lookups */
int __real_sss_ncache_check_user(struct sss_nc_ctx *ctx, int ttl,
                                 struct sss_domain_info *dom, const char *name);

int __wrap_sss_ncache_check_user(struct sss_nc_ctx *ctx, int ttl,
                                 struct sss_domain_info *dom, const char *name)
{
    int ret;

    ret = __real_sss_ncache_check_user(ctx, ttl, dom, name);
    if (ret == EEXIST) {
        nss_test_ctx->ncache_hits++;
    }
    return ret;
}

int __real_sss_ncache_check_uid(struct sss_nc_ctx *ctx, int ttl,
                                struct sss_domain_info *dom, uid_t uid);

int __wrap_sss_ncache_check_uid(struct sss_nc_ctx *ctx, int ttl,
                                struct sss_domain_info *dom, uid_t uid)
{
    int ret;

    ret = __real_sss_ncache_check_uid(ctx, ttl, dom, uid);
    if (ret == EEXIST) {
        nss_test_ctx->ncache_hits++;
    }
    return ret;
}

int __real_sss_ncache_check_sid(struct sss_nc_ctx *ctx,
                                int ttl, const char *sid);

int __wrap_sss_ncache_check_sid(struct sss_nc_ctx *ctx,
                                int ttl, const char *sid)
{
    int ret;

    ret = __real_sss_ncache_check_sid(ctx, ttl, sid);
    if (ret == EEXIST) {
        nss_test_ctx->ncache_hits++;
    }
    return ret;
}

/* Mock input from the client library */
static void mock_input_user_or_group(const char *username)
{
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, username);
    will_return(__wrap_sss_packet_get_body, 0);
}

static void mock_input_id(TALLOC_CTX *mem_ctx, uint32_t id)
{
    uint8_t *body;

    body = talloc_zero_array(mem_ctx, uint8_t, 4);
    if (body == NULL) return;

    SAFEALIGN_SETMEM_UINT32(body, id, NULL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, body);
    will_return(__wrap_sss_packet_get_body, sizeof(uint32_t));
}

static void mock_fill_user(void)
{
    /* One packet for the entry and one for num entries */
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
}

static void mock_fill_bysid(void)
{
    /* One packet for the entry and one for num entries */
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
}

static void mock_fill_initgr_user(void)
{
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
}

static void mock_fill_group_with_members(unsigned members)
{
    unsigned i;

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    if (members == 0) return;

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Member header , one per member */
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    for (i=0; i<members; i++) {
        will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    }
}


static int parse_user_packet(uint8_t *body, size_t blen, struct passwd *pwd)
{
    size_t rp = 2 * sizeof(uint32_t);

    SAFEALIGN_COPY_UINT32(&pwd->pw_uid, body+rp, &rp);
    SAFEALIGN_COPY_UINT32(&pwd->pw_gid, body+rp, &rp);

    /* Sequence of null terminated strings (name, passwd, gecos, dir, shell) */
    pwd->pw_name = (char *) body+rp;
    rp += strlen(pwd->pw_name) + 1;
    if (rp >= blen) return EINVAL;

    pwd->pw_passwd = (char *) body+rp;
    rp += strlen(pwd->pw_passwd) + 1;
    if (rp >= blen) return EINVAL;

    pwd->pw_gecos = (char *) body+rp;
    rp += strlen(pwd->pw_gecos) + 1;
    if (rp >= blen) return EINVAL;

    pwd->pw_dir = (char *) body+rp;
    rp += strlen(pwd->pw_dir) + 1;
    if (rp >= blen) return EINVAL;

    pwd->pw_shell = (char *) body+rp;
    rp += strlen(pwd->pw_shell) + 1;
    if (rp != blen) return EINVAL;

    return EOK;
}

static int parse_group_packet(uint8_t *body, size_t blen, struct group *gr, uint32_t *nmem)
{
    size_t rp = 2 * sizeof(uint32_t); /* Len and reserved */
    unsigned i;

    SAFEALIGN_COPY_UINT32(&gr->gr_gid, body+rp, &rp);
    SAFEALIGN_COPY_UINT32(nmem, body+rp, &rp);

    gr->gr_name = (char *) body+rp;
    rp += strlen(gr->gr_name) + 1;
    if (rp >= blen) return EINVAL;

    gr->gr_passwd = (char *) body+rp;
    rp += strlen(gr->gr_passwd) + 1;

    if (*nmem > 0) {
        gr->gr_mem = talloc_zero_array(nss_test_ctx, char *, *nmem);
        if (gr->gr_mem == NULL) return ENOMEM;

        for (i = 0; i < *nmem; i++) {
            if (rp >= blen) return EINVAL;

            gr->gr_mem[i] = talloc_strdup(gr->gr_mem, (char *) body+rp);
            rp += strlen(gr->gr_mem[i]) + 1;
        }
    }

    /* Make sure we exactly matched the end of the packet */
    if (rp != blen) return EINVAL;
    return EOK;
}

static void check_initgr_packet(uint8_t *body, size_t blen,
                                gid_t *gids, size_t num_gids)
{
    size_t rp;
    unsigned i;
    gid_t cur_gid;
    uint32_t num_ret;

    rp = 0;
    SAFEALIGN_COPY_UINT32(&num_ret, body, NULL);
    assert_int_equal(num_ret, num_gids);

    rp = 2 * sizeof(uint32_t); /* Len and reserved */

    for (i = 0; i < num_gids; i++) {
        SAFEALIGN_COPY_UINT32(&cur_gid, body + rp, &rp);
        assert_int_equal(cur_gid, gids[i]);
    }
}

/* ====================== The tests =============================== */

/* Check getting cached and valid user from cache. Account callback will
 * not be called and test_nss_getpwnam_check will make sure the user is
 * the same as the test entered before starting
 */
static int test_nss_getpwnam_check(uint32_t status, uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 123);
    assert_int_equal(pwd.pw_gid, 456);
    assert_string_equal(pwd.pw_name, "testuser");
    assert_string_equal(pwd.pw_shell, "/bin/sh");
    assert_string_equal(pwd.pw_passwd, "*");
    return EOK;
}

void test_nss_getpwnam(void **state)
{
    errno_t ret;

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testuser", 123, 456, "test user",
                         "/home/testuser", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testuser");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_nss_getpwnam_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test that searching for a nonexistant user yields ENOENT.
 * Account callback will be called
 */
void test_nss_getpwnam_neg(void **state)
{
    errno_t ret;

    mock_input_user_or_group("testuser_neg");
    mock_account_recv_simple();

    assert_int_equal(nss_test_ctx->ncache_hits, 0);

    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_int_equal(nss_test_ctx->ncache_hits, 0);

    /* Test that subsequent search for a nonexistent user yields
     * ENOENT and Account callback is not called, on the other hand
     * the ncache functions will be called
     */
    nss_test_ctx->tctx->done = false;

    mock_input_user_or_group("testuser_neg");
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    /* Negative cache was hit this time */
    assert_int_equal(nss_test_ctx->ncache_hits, 1);
}

static int test_nss_getpwnam_search_acct_cb(void *pvt)
{
    errno_t ret;
    struct nss_test_ctx *ctx = talloc_get_type(pvt, struct nss_test_ctx);

    ret = sysdb_add_user(ctx->tctx->dom,
                         "testuser_search", 567, 890, "test search",
                         "/home/testsearch", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    return EOK;
}

static int test_nss_getpwnam_search_check(uint32_t status,
                                          uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 567);
    assert_int_equal(pwd.pw_gid, 890);
    assert_string_equal(pwd.pw_name, "testuser_search");
    assert_string_equal(pwd.pw_shell, "/bin/sh");
    return EOK;
}

void test_nss_getpwnam_search(void **state)
{
    errno_t ret;
    struct ldb_result *res;

    mock_input_user_or_group("testuser_search");
    mock_account_recv(0, 0, NULL, test_nss_getpwnam_search_acct_cb, nss_test_ctx);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();
    set_cmd_cb(test_nss_getpwnam_search_check);

    ret = sysdb_getpwnam(nss_test_ctx, nss_test_ctx->tctx->dom,
                         "testuser_search", &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);

    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* test_nss_getpwnam_search_check will check the user attributes */
    ret = sysdb_getpwnam(nss_test_ctx, nss_test_ctx->tctx->dom,
                         "testuser_search", &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
}

/* Test that searching for a user that is expired in the cache goes to the DP
 * which updates the record and the NSS responder returns the updated record
 *
 * The user's shell attribute is updated.
 */
static int test_nss_getpwnam_update_acct_cb(void *pvt)
{
    errno_t ret;
    struct nss_test_ctx *ctx = talloc_get_type(pvt, struct nss_test_ctx);

    ret = sysdb_store_user(ctx->tctx->dom,
                           "testuser_update", NULL, 10, 11, "test user",
                           "/home/testuser", "/bin/ksh", NULL,
                           NULL, NULL, 300, 0);
    assert_int_equal(ret, EOK);

    return EOK;
}

static int test_nss_getpwnam_update_check(uint32_t status,
                                          uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 10);
    assert_int_equal(pwd.pw_gid, 11);
    assert_string_equal(pwd.pw_name, "testuser_update");
    assert_string_equal(pwd.pw_shell, "/bin/ksh");
    return EOK;
}

void test_nss_getpwnam_update(void **state)
{
    errno_t ret;
    struct ldb_result *res;
    const char *shell;

    /* Prime the cache with a valid but expired user */
    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testuser_update", 10, 11, "test user",
                         "/home/testuser", "/bin/sh", NULL,
                         NULL, 1, 1);
    assert_int_equal(ret, EOK);

    /* Mock client input */
    mock_input_user_or_group("testuser_update");
    /* Mock client command */
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    /* Call this function when user is updated by the mock DP request */
    mock_account_recv(0, 0, NULL, test_nss_getpwnam_update_acct_cb, nss_test_ctx);
    /* Call this function to check what the responder returned to the client */
    set_cmd_cb(test_nss_getpwnam_update_check);
    /* Mock output buffer */
    mock_fill_user();

    /* Fire the command */
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Check the user was updated in the cache */
    ret = sysdb_getpwnam(nss_test_ctx, nss_test_ctx->tctx->dom,
                         "testuser_update", &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);

    shell = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, NULL);
    assert_string_equal(shell, "/bin/ksh");
}

/* Check that a FQDN is returned if the domain is FQDN-only and a
 * FQDN is requested
 */
static int test_nss_getpwnam_check_fqdn(uint32_t status,
                                        uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    nss_test_ctx->cctx->rctx->domains[0].fqnames = false;

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 124);
    assert_int_equal(pwd.pw_gid, 457);
    assert_string_equal(pwd.pw_name, "testuser_fqdn@"TEST_DOM_NAME);
    assert_string_equal(pwd.pw_shell, "/bin/sh");
    return EOK;
}

void test_nss_getpwnam_fqdn(void **state)
{
    errno_t ret;

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testuser_fqdn", 124, 457, "test user",
                         "/home/testuser", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testuser_fqdn@"TEST_DOM_NAME);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_nss_getpwnam_check_fqdn);
    nss_test_ctx->cctx->rctx->domains[0].fqnames = true;
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Check that a user with a space in his username is returned fine.
 */
static int test_nss_getpwnam_check_space(uint32_t status,
                                         uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 225);
    assert_int_equal(pwd.pw_gid, 558);
    assert_string_equal(pwd.pw_name, "space user");
    assert_string_equal(pwd.pw_shell, "/bin/sh");
    return EOK;
}

void test_nss_getpwnam_space(void **state)
{
    errno_t ret;

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "space user", 225, 558, "space user",
                         "/home/testuser", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("space user");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_nss_getpwnam_check_space);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

}

static int test_nss_getpwnam_check_space_sub(uint32_t status,
                                             uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 225);
    assert_int_equal(pwd.pw_gid, 558);
    assert_string_equal(pwd.pw_name, "space_user");
    assert_string_equal(pwd.pw_shell, "/bin/sh");
    return EOK;
}

void test_nss_getpwnam_space_sub(void **state)
{
    errno_t ret;

    /* Set whitespace substitution */
    nss_test_ctx->rctx->override_space = '_';

    mock_input_user_or_group("space user");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_nss_getpwnam_check_space_sub);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    nss_test_ctx->rctx->override_space = '\0';
    assert_int_equal(ret, EOK);
}

void test_nss_getpwnam_space_sub_query(void **state)
{
    errno_t ret;

    /* Set whitespace substitution */
    nss_test_ctx->rctx->override_space = '_';

    mock_input_user_or_group("space_user");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_nss_getpwnam_check_space_sub);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    nss_test_ctx->rctx->override_space = '\0';
    assert_int_equal(ret, EOK);
}

/*
 * Check that FQDN processing is able to handle arbitrarily sized
 * delimeter
 */
static int test_nss_getpwnam_check_fancy_fqdn(uint32_t status,
                                              uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    nss_test_ctx->cctx->rctx->domains[0].fqnames = false;

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 125);
    assert_int_equal(pwd.pw_gid, 458);
    assert_string_equal(pwd.pw_name, "testuser_fqdn_fancy@@@@@"TEST_DOM_NAME);
    assert_string_equal(pwd.pw_shell, "/bin/sh");
    return EOK;
}

void test_nss_getpwnam_fqdn_fancy(void **state)
{
    errno_t ret;

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testuser_fqdn_fancy", 125, 458, "test user",
                         "/home/testuser", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testuser_fqdn_fancy@"TEST_DOM_NAME);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_nss_getpwnam_check_fancy_fqdn);
    nss_test_ctx->cctx->rctx->domains[0].fqnames = true;
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Check getting cached and valid id from cache. Account callback will
 * not be called and test_nss_getpwuid_check will make sure the id is
 * the same as the test entered before starting
 */
static int test_nss_getpwuid_check(uint32_t status, uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 101);
    assert_int_equal(pwd.pw_gid, 401);
    assert_string_equal(pwd.pw_name, "testuser1");
    assert_string_equal(pwd.pw_shell, "/bin/sh");
    assert_string_equal(pwd.pw_passwd, "*");
    return EOK;
}

void test_nss_getpwuid(void **state)
{
    errno_t ret;

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testuser1", 101, 401, "test user1",
                         "/home/testuser1", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    uint32_t id = 101;
    mock_input_id(nss_test_ctx, id);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWUID);
    mock_fill_user();

    /* Query for that id, call a callback when command finishes */
    set_cmd_cb(test_nss_getpwuid_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWUID,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test that searching for a nonexistent id yields ENOENT.
 * Account callback will be called
 */
void test_nss_getpwuid_neg(void **state)
{
    errno_t ret;

    uint8_t id = 102;
    mock_input_id(nss_test_ctx, id);
    mock_account_recv_simple();

    assert_int_equal(nss_test_ctx->ncache_hits, 0);

    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWUID,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_int_equal(nss_test_ctx->ncache_hits, 0);

    /* Test that subsequent search for a nonexistent id yields
     * ENOENT and Account callback is not called, on the other hand
     * the ncache functions will be called
     */
    nss_test_ctx->tctx->done = false;

    mock_input_id(nss_test_ctx, id);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWUID,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    /* Negative cache was hit this time */
    assert_int_equal(nss_test_ctx->ncache_hits, 1);
}

static int test_nss_getpwuid_search_acct_cb(void *pvt)
{
    errno_t ret;
    struct nss_test_ctx *ctx = talloc_get_type(pvt, struct nss_test_ctx);

    ret = sysdb_add_user(ctx->tctx->dom,
                         "exampleuser_search", 107, 987, "example search",
                         "/home/examplesearch", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    return EOK;
}

static int test_nss_getpwuid_search_check(uint32_t status,
                                          uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 107);
    assert_int_equal(pwd.pw_gid, 987);
    assert_string_equal(pwd.pw_name, "exampleuser_search");
    assert_string_equal(pwd.pw_shell, "/bin/sh");
    return EOK;
}

void test_nss_getpwuid_search(void **state)
{
    errno_t ret;
    struct ldb_result *res;

    uint8_t id = 107;
    mock_input_id(nss_test_ctx, id);
    mock_account_recv(0, 0, NULL, test_nss_getpwuid_search_acct_cb, nss_test_ctx);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWUID);
    mock_fill_user();
    set_cmd_cb(test_nss_getpwuid_search_check);

    ret = sysdb_getpwuid(nss_test_ctx, nss_test_ctx->tctx->dom,
                         107, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);

    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWUID,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* test_nss_getpwuid_search_check will check the id attributes */
    ret = sysdb_getpwuid(nss_test_ctx, nss_test_ctx->tctx->dom,
                         107, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
}

/* Test that searching for an id that is expired in the cache goes to the DP
 * which updates the record and the NSS responder returns the updated record
 *
 * The user's shell attribute is updated.
 */
static int test_nss_getpwuid_update_acct_cb(void *pvt)
{
    errno_t ret;
    struct nss_test_ctx *ctx = talloc_get_type(pvt, struct nss_test_ctx);

    ret = sysdb_store_user(ctx->tctx->dom,
                           "exampleuser_update", NULL, 109, 11000, "example user",
                           "/home/exampleuser", "/bin/ksh", NULL,
                           NULL, NULL, 300, 0);
    assert_int_equal(ret, EOK);

    return EOK;
}

static int test_nss_getpwuid_update_check(uint32_t status,
                                          uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 109);
    assert_int_equal(pwd.pw_gid, 11000);
    assert_string_equal(pwd.pw_name, "exampleuser_update");
    assert_string_equal(pwd.pw_shell, "/bin/ksh");
    return EOK;
}

void test_nss_getpwuid_update(void **state)
{
    errno_t ret;
    struct ldb_result *res;
    const char *shell;

    /* Prime the cache with a valid but expired user */
    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "exampleuser_update", 109, 11000, "example user",
                         "/home/exampleuser", "/bin/sh", NULL,
                         NULL, 1, 1);
    assert_int_equal(ret, EOK);

    /* Mock client input */
    uint8_t id = 109;
    mock_input_id(nss_test_ctx, id);
    /* Mock client command */
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWUID);
    /* Call this function when id is updated by the mock DP request */
    mock_account_recv(0, 0, NULL, test_nss_getpwuid_update_acct_cb, nss_test_ctx);
    /* Call this function to check what the responder returned to the client */
    set_cmd_cb(test_nss_getpwuid_update_check);
    /* Mock output buffer */
    mock_fill_user();

    /* Fire the command */
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWUID,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Check the user was updated in the cache */
    ret = sysdb_getpwuid(nss_test_ctx, nss_test_ctx->tctx->dom,
                         109, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);

    shell = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, NULL);
    assert_string_equal(shell, "/bin/ksh");
}

/* Testsuite setup and teardown */
void test_nss_setup(struct sss_test_conf_param params[],
                    void **state)
{
    errno_t ret;

    nss_test_ctx = talloc_zero(NULL, struct nss_test_ctx);
    assert_non_null(nss_test_ctx);

    nss_test_ctx->tctx = create_dom_test_ctx(nss_test_ctx, TESTS_PATH,
                                             TEST_CONF_DB, TEST_DOM_NAME,
                                             TEST_ID_PROVIDER, params);
    assert_non_null(nss_test_ctx->tctx);

    nss_test_ctx->tctx->dom->domain_id = discard_const(TEST_DOM_SID);

    nss_test_ctx->nss_cmds = get_nss_cmds();
    assert_non_null(nss_test_ctx->nss_cmds);

    /* FIXME - perhaps this should be folded into sssd_domain_init or stricty
     * used together
     */
    ret = sss_names_init(nss_test_ctx, nss_test_ctx->tctx->confdb,
                         TEST_DOM_NAME, &nss_test_ctx->tctx->dom->names);
    assert_int_equal(ret, EOK);

    /* Initialize the NSS responder */
    nss_test_ctx->nctx = mock_nctx(nss_test_ctx);
    assert_non_null(nss_test_ctx->nctx);

    ret = sss_ad_default_names_ctx(nss_test_ctx->nctx,
                                   &nss_test_ctx->nctx->global_names);
    assert_int_equal(ret, EOK);
    assert_non_null(nss_test_ctx->nctx->global_names);

    nss_test_ctx->rctx = mock_rctx(nss_test_ctx, nss_test_ctx->tctx->ev,
                                   nss_test_ctx->tctx->dom, nss_test_ctx->nctx);
    assert_non_null(nss_test_ctx->rctx);
    nss_test_ctx->rctx->cdb = nss_test_ctx->tctx->confdb;
    nss_test_ctx->nctx->rctx = nss_test_ctx->rctx;

    /* Create client context */
    nss_test_ctx->cctx = mock_cctx(nss_test_ctx, nss_test_ctx->rctx);
    assert_non_null(nss_test_ctx->cctx);
}

static int test_nss_getgrnam_check(struct group *expected, struct group *gr, const int nmem)
{
    int i;

    assert_int_equal(gr->gr_gid, expected->gr_gid);
    assert_string_equal(gr->gr_name, expected->gr_name);
    assert_string_equal(gr->gr_passwd, expected->gr_passwd);

    for (i = 0; i < nmem; i++) {
        assert_string_equal(gr->gr_mem[i], expected->gr_mem[i]);
    }
    return EOK;
}

static int test_nss_getgrnam_no_members_check(uint32_t status,
                                              uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    struct group expected = {
        .gr_gid = 1123,
        .gr_name = discard_const("testgroup"),
        .gr_passwd = discard_const("*"),
        .gr_mem = NULL,
    };

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 0);

    ret = test_nss_getgrnam_check(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    return EOK;
}

/* Test that requesting a valid, cached group with no members returns a valid
 * group structure
 */
void test_nss_getgrnam_no_members(void **state)
{
    errno_t ret;

    /* Prime the cache with a valid group */
    ret = sysdb_add_group(nss_test_ctx->tctx->dom,
                          "testgroup", 1123,
                          NULL, 300, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testgroup");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    mock_fill_group_with_members(0);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_nss_getgrnam_no_members_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_nss_getgrnam_members_check(uint32_t status,
                                           uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    const char *exp_members[] = { "testmember1", "testmember2" };
    struct group expected = {
        .gr_gid = 1124,
        .gr_name = discard_const("testgroup_members"),
        .gr_passwd = discard_const("*"),
        .gr_mem = discard_const(exp_members)
    };

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 2);

    ret = test_nss_getgrnam_check(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    return EOK;
}

/* Test that requesting a valid, cached group with some members returns a valid
 * group structure with those members present
 */
void test_nss_getgrnam_members(void **state)
{
    errno_t ret;

    /* Prime the cache with a valid group and some members */
    ret = sysdb_add_group(nss_test_ctx->tctx->dom,
                          "testgroup_members", 1124,
                          NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testmember1", 2001, 456, "test member1",
                         "/home/testmember2", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testmember2", 2002, 456, "test member2",
                         "/home/testmember2", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group_member(nss_test_ctx->tctx->dom,
                                 "testgroup_members", "testmember1",
                                 SYSDB_MEMBER_USER, false);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group_member(nss_test_ctx->tctx->dom,
                                 "testgroup_members", "testmember2",
                                 SYSDB_MEMBER_USER, false);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testgroup_members");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    mock_fill_group_with_members(2);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_nss_getgrnam_members_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_nss_getgrnam_members_check_fqdn(uint32_t status,
                                                uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    const char *exp_members[] = { "testmember1@"TEST_DOM_NAME,
                                  "testmember2@"TEST_DOM_NAME };
    struct group expected = {
        .gr_gid = 1124,
        .gr_name = discard_const("testgroup_members@"TEST_DOM_NAME),
        .gr_passwd = discard_const("*"),
        .gr_mem = discard_const(exp_members)
    };

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 2);

    ret = test_nss_getgrnam_check(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    return EOK;
}

/* Test that requesting a valid, cached group with some members returns a valid
 * group structure with those members present as fully qualified names
 */
void test_nss_getgrnam_members_fqdn(void **state)
{
    errno_t ret;

    nss_test_ctx->tctx->dom->fqnames = true;

    mock_input_user_or_group("testgroup_members@"TEST_DOM_NAME);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    mock_fill_group_with_members(2);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_nss_getgrnam_members_check_fqdn);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);

    /* Restore FQDN settings */
    nss_test_ctx->tctx->dom->fqnames = false;
    assert_int_equal(ret, EOK);
}

static int test_nss_getgrnam_members_check_subdom(uint32_t status,
                                                  uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    const char *exp_members[] = { "submember1@"TEST_SUBDOM_NAME,
                                  "submember2@"TEST_SUBDOM_NAME };
    struct group expected = {
        .gr_gid = 2124,
        .gr_name = discard_const("testsubdomgroup@"TEST_SUBDOM_NAME),
        .gr_passwd = discard_const("*"),
        .gr_mem = discard_const(exp_members)
    };

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 2);

    ret = test_nss_getgrnam_check(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    return EOK;
}

/* Test that requesting a valid, cached group with some members returns a valid
 * group structure with those members present as fully qualified names
 */
void test_nss_getgrnam_members_subdom(void **state)
{
    errno_t ret;

    nss_test_ctx->tctx->dom->fqnames = true;

    /* Add a group from a subdomain and two members from the same subdomain
     */
    ret = sysdb_add_group(nss_test_ctx->subdom,
                          "testsubdomgroup@"TEST_SUBDOM_NAME,
                          2124, NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_user(nss_test_ctx->subdom,
                         "submember1@"TEST_SUBDOM_NAME,
                         4001, 456, "test subdomain member1",
                         "/home/submember1", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_user(nss_test_ctx->subdom,
                         "submember2@"TEST_SUBDOM_NAME,
                         2002, 456, "test subdomain member2",
                         "/home/submember2", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group_member(nss_test_ctx->subdom,
                                 "testsubdomgroup@"TEST_SUBDOM_NAME,
                                 "submember1@"TEST_SUBDOM_NAME,
                                 SYSDB_MEMBER_USER, false);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group_member(nss_test_ctx->subdom,
                                 "testsubdomgroup@"TEST_SUBDOM_NAME,
                                 "submember2@"TEST_SUBDOM_NAME,
                                 SYSDB_MEMBER_USER, false);
    assert_int_equal(ret, EOK);


    mock_input_user_or_group("testsubdomgroup@"TEST_SUBDOM_NAME);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    mock_fill_group_with_members(2);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_nss_getgrnam_members_check_subdom);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);

    /* Restore FQDN settings */
    nss_test_ctx->tctx->dom->fqnames = false;
    assert_int_equal(ret, EOK);
}

static int test_nss_getgrnam_check_mix_dom(uint32_t status,
                                           uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    const char *exp_members[] = { "testmember1",
                                  "testmember2",
                                  "submember1@"TEST_SUBDOM_NAME };
    struct group expected = {
        .gr_gid = 1124,
        .gr_name = discard_const("testgroup_members"),
        .gr_passwd = discard_const("*"),
        .gr_mem = discard_const(exp_members)
    };

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 3);

    ret = test_nss_getgrnam_check(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    return EOK;
}

void test_nss_getgrnam_mix_dom(void **state)
{
    errno_t ret;
    const char *group_strdn = NULL;
    const char *add_groups[] = { NULL, NULL };

    /* Add a subdomain user to a parent domain group */
    group_strdn = sysdb_group_strdn(nss_test_ctx,
                                    nss_test_ctx->tctx->dom->name,
                                    "testgroup_members");
    assert_non_null(group_strdn);
    add_groups[0] = group_strdn;

    ret = sysdb_update_members_dn(nss_test_ctx->subdom,
                                  "submember1@"TEST_SUBDOM_NAME,
                                  SYSDB_MEMBER_USER,
                                  add_groups, NULL);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testgroup_members");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    mock_fill_group_with_members(3);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_nss_getgrnam_check_mix_dom);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_nss_getgrnam_check_mix_dom_fqdn(uint32_t status,
                                                uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    const char *exp_members[] = { "testmember1@"TEST_DOM_NAME,
                                  "testmember2@"TEST_DOM_NAME,
                                  "submember1@"TEST_SUBDOM_NAME };
    struct group expected = {
        .gr_gid = 1124,
        .gr_name = discard_const("testgroup_members@"TEST_DOM_NAME),
        .gr_passwd = discard_const("*"),
        .gr_mem = discard_const(exp_members)
    };

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 3);

    ret = test_nss_getgrnam_check(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    return EOK;
}

void test_nss_getgrnam_mix_dom_fqdn(void **state)
{
    errno_t ret;

    nss_test_ctx->tctx->dom->fqnames = true;

    mock_input_user_or_group("testgroup_members@"TEST_DOM_NAME);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    mock_fill_group_with_members(3);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_nss_getgrnam_check_mix_dom_fqdn);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);

    /* Restore FQDN settings */
    nss_test_ctx->tctx->dom->fqnames = false;
    assert_int_equal(ret, EOK);
}

static int test_nss_getgrnam_check_mix_subdom(uint32_t status,
                                              uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    const char *exp_members[] = { "submember1@"TEST_SUBDOM_NAME,
                                  "submember2@"TEST_SUBDOM_NAME,
                                  "testmember1@"TEST_DOM_NAME };
    struct group expected = {
        .gr_gid = 2124,
        .gr_name = discard_const("testsubdomgroup@"TEST_SUBDOM_NAME),
        .gr_passwd = discard_const("*"),
        .gr_mem = discard_const(exp_members)
    };

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 3);

    ret = test_nss_getgrnam_check(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    return EOK;
}

void test_nss_getgrnam_mix_subdom(void **state)
{
    errno_t ret;
    const char *group_strdn = NULL;
    const char *add_groups[] = { NULL, NULL };

    /* Add a subdomain user to a parent domain group */
    group_strdn = sysdb_group_strdn(nss_test_ctx,
                                    nss_test_ctx->subdom->name,
                                    "testsubdomgroup@"TEST_SUBDOM_NAME);
    assert_non_null(group_strdn);
    add_groups[0] = group_strdn;

    ret = sysdb_update_members_dn(nss_test_ctx->tctx->dom,
                                  "testmember1",
                                  SYSDB_MEMBER_USER,
                                  add_groups, NULL);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testsubdomgroup@"TEST_SUBDOM_NAME);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    mock_fill_group_with_members(3);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_nss_getgrnam_check_mix_subdom);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_nss_getgrnam_space_check(uint32_t status,
                                         uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    struct group expected = {
        .gr_gid = 2123,
        .gr_name = discard_const("space group"),
        .gr_passwd = discard_const("*"),
        .gr_mem = NULL,
    };

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 0);

    ret = test_nss_getgrnam_check(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    return EOK;
}

/* Test that requesting a valid, cached group with space in its name returns a valid
 * group structure
 */
void test_nss_getgrnam_space(void **state)
{
    errno_t ret;

    /* Prime the cache with a valid group */
    ret = sysdb_add_group(nss_test_ctx->tctx->dom,
                          "space group", 2123,
                          NULL, 300, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("space group");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    mock_fill_group_with_members(0);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_nss_getgrnam_space_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_nss_getgrnam_space_sub_check(uint32_t status,
                                             uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    struct group expected = {
        .gr_gid = 2123,
        .gr_name = discard_const("space_group"),
        .gr_passwd = discard_const("*"),
        .gr_mem = NULL,
    };

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 0);

    ret = test_nss_getgrnam_check(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    return EOK;
}

/* Test that requesting a valid, cached group with space in its name returns a valid
 * group structure
 */
void test_nss_getgrnam_space_sub(void **state)
{
    errno_t ret;

    /* Set whitespace substitution */
    nss_test_ctx->rctx->override_space = '_';

    mock_input_user_or_group("space group");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    mock_fill_group_with_members(0);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_nss_getgrnam_space_sub_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    nss_test_ctx->rctx->override_space = '\0';
    assert_int_equal(ret, EOK);
}

static int test_nss_well_known_sid_check(uint32_t status,
                                         uint8_t *body, size_t blen)
{
    const char *name;
    enum sss_id_type type;
    size_t rp = 2 * sizeof(uint32_t);
    char *expected_result = sss_mock_ptr_type(char *);

    if (expected_result == NULL) {
        assert_int_equal(status, EINVAL);
        assert_int_equal(blen, 0);
    } else {
        assert_int_equal(status, EOK);

        SAFEALIGN_COPY_UINT32(&type, body+rp, &rp);

        name = (char *) body+rp;

        assert_int_equal(type, SSS_ID_TYPE_GID);
        assert_string_equal(name, expected_result);
    }

    return EOK;
}

void test_nss_well_known_getnamebysid(void **state)
{
    errno_t ret;

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, "S-1-5-32-550");
    will_return(__wrap_sss_packet_get_body, 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNAMEBYSID);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(test_nss_well_known_sid_check, "Print Operators@BUILTIN");

    set_cmd_cb(test_nss_well_known_sid_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_nss_well_known_getnamebysid_special(void **state)
{
    errno_t ret;

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, "S-1-2-0");
    will_return(__wrap_sss_packet_get_body, 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNAMEBYSID);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(test_nss_well_known_sid_check, "LOCAL@LOCAL AUTHORITY");

    set_cmd_cb(test_nss_well_known_sid_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_nss_well_known_getnamebysid_non_existing(void **state)
{
    errno_t ret;

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, "S-1-5-32-123");
    will_return(__wrap_sss_packet_get_body, 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNAMEBYSID);
    will_return(test_nss_well_known_sid_check, NULL);

    set_cmd_cb(test_nss_well_known_sid_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_nss_well_known_getidbysid_failure(void **state)
{
    errno_t ret;

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, "S-1-5-32-550");
    will_return(__wrap_sss_packet_get_body, 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETIDBYSID);
    will_return(test_nss_well_known_sid_check, NULL);

    set_cmd_cb(test_nss_well_known_sid_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETIDBYSID,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_nss_well_known_getsidbyname(void **state)
{
    errno_t ret;
    const char *names[] = { "Cryptographic Operators@BUILTIN",
                            "BUILTIN\\Cryptographic Operators", NULL};
    size_t c;

    for (c = 0; names[c] != NULL; c++) {
        will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
        will_return(__wrap_sss_packet_get_body, names[c]);
        will_return(__wrap_sss_packet_get_body, 0);
        will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYNAME);
        will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
        will_return(test_nss_well_known_sid_check, "S-1-5-32-569");

        set_cmd_cb(test_nss_well_known_sid_check);
        ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETSIDBYNAME,
                              nss_test_ctx->nss_cmds);
        assert_int_equal(ret, EOK);

        /* Wait until the test finishes with EOK */
        ret = test_ev_loop(nss_test_ctx->tctx);
        assert_int_equal(ret, EOK);
    }
}

void test_nss_well_known_getsidbyname_nonexisting(void **state)
{
    errno_t ret;
    const char *names[] = { "Abc@BUILTIN", "BUILTIN\\Abc", NULL };
    size_t c;

    for (c = 0; names[c] != NULL; c++) {
        will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
        will_return(__wrap_sss_packet_get_body, names[c]);
        will_return(__wrap_sss_packet_get_body, 0);
        will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYNAME);
        will_return(test_nss_well_known_sid_check, NULL);

        set_cmd_cb(test_nss_well_known_sid_check);
        ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETSIDBYNAME,
                              nss_test_ctx->nss_cmds);
        assert_int_equal(ret, EOK);

        /* Wait until the test finishes with EOK */
        ret = test_ev_loop(nss_test_ctx->tctx);
        assert_int_equal(ret, EOK);
    }
}

void test_nss_well_known_getsidbyname_special(void **state)
{
    errno_t ret;
    const char *names[] = { "CREATOR OWNER@CREATOR AUTHORITY",
                            "CREATOR AUTHORITY\\CREATOR OWNER", NULL };
    size_t c;

    for (c = 0; names[c] != NULL; c++) {
        will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
        will_return(__wrap_sss_packet_get_body, names[c]);
        will_return(__wrap_sss_packet_get_body, 0);
        will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYNAME);
        will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
        will_return(test_nss_well_known_sid_check, "S-1-3-0");

        set_cmd_cb(test_nss_well_known_sid_check);
        ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETSIDBYNAME,
                              nss_test_ctx->nss_cmds);
        assert_int_equal(ret, EOK);

        /* Wait until the test finishes with EOK */
        ret = test_ev_loop(nss_test_ctx->tctx);
        assert_int_equal(ret, EOK);
    }
}

static int test_nss_getorigbyname_check(uint32_t status, uint8_t *body,
                                        size_t blen)
{
    const char *s;
    enum sss_id_type id_type;
    size_t rp = 2 * sizeof(uint32_t);

    assert_int_equal(status, EOK);

    SAFEALIGN_COPY_UINT32(&id_type, body+rp, &rp);
    assert_int_equal(id_type, SSS_ID_TYPE_UID);

    /* Sequence of null terminated strings */
    s = (char *) body+rp;
    assert_string_equal(s, SYSDB_SID_STR);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "S-1-2-3-4");
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, ORIGINALAD_PREFIX SYSDB_NAME);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "orig_name");
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, ORIGINALAD_PREFIX SYSDB_UIDNUM);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "1234");
    rp += strlen(s) + 1;
    assert_int_equal(rp, blen);

    return EOK;
}

void test_nss_getorigbyname(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, "S-1-2-3-4");
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, ORIGINALAD_PREFIX SYSDB_NAME,
                                 "orig_name");
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_uint32(attrs, ORIGINALAD_PREFIX SYSDB_UIDNUM, 1234);
    assert_int_equal(ret, EOK);

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testuserorig", 1234, 5689, "test user orig",
                         "/home/testuserorig", "/bin/sh", NULL,
                         attrs, 300, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testuserorig");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETORIGBYNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_nss_getorigbyname_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETORIGBYNAME,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_nss_getorigbyname_extra_check(uint32_t status, uint8_t *body,
                                              size_t blen)
{
    const char *s;
    enum sss_id_type id_type;
    size_t rp = 2 * sizeof(uint32_t);

    assert_int_equal(status, EOK);

    SAFEALIGN_COPY_UINT32(&id_type, body+rp, &rp);
    assert_int_equal(id_type, SSS_ID_TYPE_UID);

    /* Sequence of null terminated strings */
    s = (char *) body+rp;
    assert_string_equal(s, SYSDB_SID_STR);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "S-1-2-3-4");
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, ORIGINALAD_PREFIX SYSDB_NAME);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "orig_name");
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, ORIGINALAD_PREFIX SYSDB_UIDNUM);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "1234");
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "phone");
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "+12-34 56 78");
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "mobile");
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "+98-76 54 32");
    rp += strlen(s) + 1;
    assert_int_equal(rp, blen);

    return EOK;
}

void test_nss_getorigbyname_extra_attrs(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, "S-1-2-3-4");
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, ORIGINALAD_PREFIX SYSDB_NAME,
                                 "orig_name");
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_uint32(attrs, ORIGINALAD_PREFIX SYSDB_UIDNUM, 1234);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, "phone", "+12-34 56 78");
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, "mobile", "+98-76 54 32");
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, "not_extra", "abc");
    assert_int_equal(ret, EOK);

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testuserorigextra", 2345, 6789,
                         "test user orig extra",
                         "/home/testuserorigextra", "/bin/sh", NULL,
                         attrs, 300, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testuserorigextra");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETORIGBYNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_nss_getorigbyname_extra_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETORIGBYNAME,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}


static int test_nss_getorigbyname_multi_check(uint32_t status, uint8_t *body,
                                              size_t blen)
{
    const char *s;
    enum sss_id_type id_type;
    size_t rp = 2 * sizeof(uint32_t);

    assert_int_equal(status, EOK);

    SAFEALIGN_COPY_UINT32(&id_type, body+rp, &rp);
    assert_int_equal(id_type, SSS_ID_TYPE_UID);

    /* Sequence of null terminated strings */
    s = (char *) body+rp;
    assert_string_equal(s, SYSDB_SID_STR);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "S-1-2-3-4");
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, ORIGINALAD_PREFIX SYSDB_NAME);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "orig_name");
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, ORIGINALAD_PREFIX SYSDB_UIDNUM);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "1234");
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, SYSDB_ORIG_MEMBEROF);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "cn=abc");
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, SYSDB_ORIG_MEMBEROF);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "cn=def");
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, SYSDB_ORIG_MEMBEROF);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "cn=123");
    rp += strlen(s) + 1;
    assert_int_equal(rp, blen);

    return EOK;
}
void test_nss_getorigbyname_multi_value_attrs(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, "S-1-2-3-4");
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, ORIGINALAD_PREFIX SYSDB_NAME,
                                 "orig_name");
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_uint32(attrs, ORIGINALAD_PREFIX SYSDB_UIDNUM, 1234);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, SYSDB_ORIG_MEMBEROF, "cn=abc");
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, SYSDB_ORIG_MEMBEROF, "cn=def");
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, SYSDB_ORIG_MEMBEROF, "cn=123");
    assert_int_equal(ret, EOK);

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testuserorigmulti", 3456, 7890,
                         "test user orig multi value",
                         "/home/testuserorigextra", "/bin/sh", NULL,
                         attrs, 300, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testuserorigmulti");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETORIGBYNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_nss_getorigbyname_multi_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETORIGBYNAME,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_nss_getpwnam_upn_check(uint32_t status,
                                       uint8_t *body,
                                       size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 34567);
    assert_int_equal(pwd.pw_gid, 45678);
    assert_string_equal(pwd.pw_name, "upnuser");
    assert_string_equal(pwd.pw_shell, "/bin/sh");
    assert_string_equal(pwd.pw_passwd, "*");
    return EOK;
}

void test_nss_getpwnam_upn(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, "upnuser@upndomain.test");
    assert_int_equal(ret, EOK);

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "upnuser", 34567, 45678, "up user",
                         "/home/upnuser", "/bin/sh", NULL,
                         attrs, 300, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("upnuser@upndomain.test");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_nss_getpwnam_upn_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test that searching for a nonexistant user yields ENOENT.
 * Account callback will be called
 */
void test_nss_getpwnam_upn_neg(void **state)
{
    errno_t ret;

    mock_input_user_or_group("nosuchupnuser@upndomain.test");
    mock_account_recv_simple();

    assert_int_equal(nss_test_ctx->ncache_hits, 0);

    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_int_equal(nss_test_ctx->ncache_hits, 1);

    /* Test that subsequent search for a nonexistent user yields
     * ENOENT and Account callback is not called, on the other hand
     * the ncache functions will be called
     */
    nss_test_ctx->tctx->done = false;
    nss_test_ctx->ncache_hits = 0;

    mock_input_user_or_group("nosuchupnuser@upndomain.test");
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    /* Negative cache was hit this time */
    assert_int_equal(nss_test_ctx->ncache_hits, 1);
}

static int test_nss_initgr_check(uint32_t status, uint8_t *body, size_t blen)
{
    gid_t expected_gids[] = { 3211, 3212 };

    assert_int_equal(status, EOK);
    check_initgr_packet(body, blen, expected_gids, N_ELEMENTS(expected_gids));
    return EOK;
}

void test_nss_initgroups(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE,
                                 time(NULL) + 300);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, "upninitgr@upndomain.test");
    assert_int_equal(ret, EOK);

    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testinitgr", 321, 654, "test initgroups",
                         "/home/testinitgr", "/bin/sh", NULL,
                         attrs, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group(nss_test_ctx->tctx->dom,
                          "testinitgr_gr1", 3211,
                          NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group(nss_test_ctx->tctx->dom,
                          "testinitgr_gr2", 3212,
                          NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group_member(nss_test_ctx->tctx->dom,
                                 "testinitgr_gr1", "testinitgr",
                                 SYSDB_MEMBER_USER, false);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group_member(nss_test_ctx->tctx->dom,
                                 "testinitgr_gr2", "testinitgr",
                                 SYSDB_MEMBER_USER, false);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testinitgr");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR);
    mock_fill_initgr_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_nss_initgr_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_INITGR,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test that searching for a nonexistant user yields ENOENT.
 * Account callback will be called
 */
void test_initgr_neg_by_name(const char *name, bool is_upn)
{
    errno_t ret;

    mock_input_user_or_group(name);
    mock_account_recv_simple();

    assert_int_equal(nss_test_ctx->ncache_hits, 0);

    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_INITGR,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    /* UPN lookup will first hit negcache with the username */
    assert_int_equal(nss_test_ctx->ncache_hits, is_upn ? 1 : 0);

    /* Test that subsequent search for a nonexistent user yields
     * ENOENT and Account callback is not called, on the other hand
     * the ncache functions will be called
     */
    nss_test_ctx->tctx->done = false;
    nss_test_ctx->ncache_hits = 0;

    mock_input_user_or_group(name);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_INITGR,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    /* Negative cache was hit this time */
    assert_int_equal(nss_test_ctx->ncache_hits, 1);
}

void test_nss_initgr_neg(void **state)
{
    test_initgr_neg_by_name("testinitgr_neg", false);
}

static int test_nss_initgr_search_acct_cb(void *pvt)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE,
                                 time(NULL) + 300);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testinitgr_srch", 421, 654, "test initgroups",
                         "/home/testinitgr", "/bin/sh", NULL,
                         attrs, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group(nss_test_ctx->tctx->dom,
                          "testinitgr_srch_gr1", 4211,
                          NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group(nss_test_ctx->tctx->dom,
                          "testinitgr_srch_gr2", 4212,
                          NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group_member(nss_test_ctx->tctx->dom,
                                 "testinitgr_srch_gr1", "testinitgr_srch",
                                 SYSDB_MEMBER_USER, false);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group_member(nss_test_ctx->tctx->dom,
                                 "testinitgr_srch_gr2", "testinitgr_srch",
                                 SYSDB_MEMBER_USER, false);
    assert_int_equal(ret, EOK);


    return EOK;
}

static int test_nss_initgr_search_check(uint32_t status,
                                        uint8_t *body, size_t blen)
{
    gid_t expected_gids[] = { 4211, 4212 };

    assert_int_equal(status, EOK);
    check_initgr_packet(body, blen, expected_gids, N_ELEMENTS(expected_gids));
    return EOK;
}

void test_nss_initgr_search(void **state)
{
    errno_t ret;
    struct ldb_result *res;

    mock_input_user_or_group("testinitgr_srch");
    mock_account_recv(0, 0, NULL, test_nss_initgr_search_acct_cb, nss_test_ctx);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR);
    mock_fill_initgr_user();
    set_cmd_cb(test_nss_initgr_search_check);

    ret = sysdb_getpwnam(nss_test_ctx, nss_test_ctx->tctx->dom,
                         "testinitgr_srch", &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);

    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_INITGR,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* test_nss_getpwnam_search_check will check the user attributes */
    ret = sysdb_getpwnam(nss_test_ctx, nss_test_ctx->tctx->dom,
                         "testinitgr_srch", &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
}

static int test_nss_initgr_update_acct_cb(void *pvt)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE,
                                 time(NULL) + 300);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(nss_test_ctx->tctx->dom,
                              "testinitgr_update",
                              attrs, SYSDB_MOD_REP);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group(nss_test_ctx->tctx->dom,
                          "testinitgr_check_gr2", 5212,
                          NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group_member(nss_test_ctx->tctx->dom,
                                 "testinitgr_check_gr2",
                                 "testinitgr_update",
                                 SYSDB_MEMBER_USER, false);
    assert_int_equal(ret, EOK);

    return EOK;
}

static int test_nss_initgr_update_check(uint32_t status, uint8_t *body, size_t blen)
{
    gid_t expected_gids[] = { 5211, 5212 };

    assert_int_equal(status, EOK);
    check_initgr_packet(body, blen, expected_gids, N_ELEMENTS(expected_gids));
    return EOK;
}

void test_nss_initgr_update(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE,
                                 time(NULL) - 1);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testinitgr_update", 521, 654, "test initgroups",
                         "/home/testinitgr", "/bin/sh", NULL,
                         attrs, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group(nss_test_ctx->tctx->dom,
                          "testinitgr_update_gr1", 5211,
                          NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group_member(nss_test_ctx->tctx->dom,
                                 "testinitgr_update_gr1", "testinitgr_update",
                                 SYSDB_MEMBER_USER, false);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testinitgr_update");
    mock_account_recv(0, 0, NULL, test_nss_initgr_update_acct_cb, nss_test_ctx);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR);
    mock_fill_initgr_user();
    set_cmd_cb(test_nss_initgr_update_check);


    /* Query for that user, call a callback when command finishes */
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_INITGR,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_nss_initgr_update_acct_2expire_attributes_cb(void *pvt)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE,
                                 time(NULL) + 300);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(nss_test_ctx->tctx->dom,
                              "testinitgr_2attr",
                              attrs, SYSDB_MOD_REP);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group(nss_test_ctx->tctx->dom,
                          "testinitgr_2attr_gr12", 5222,
                          NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group_member(nss_test_ctx->tctx->dom,
                                 "testinitgr_2attr_gr12",
                                 "testinitgr_2attr",
                                 SYSDB_MEMBER_USER, false);
    assert_int_equal(ret, EOK);

    return EOK;
}

static int test_nss_initgr_update_2expire_attributes_check(uint32_t status,
                                                           uint8_t *body,
                                                           size_t blen)
{
    gid_t expected_gids[] = { 5221, 5222 };

    assert_int_equal(status, EOK);
    check_initgr_packet(body, blen, expected_gids, N_ELEMENTS(expected_gids));
    return EOK;
}

/*
 * SYSDB_INITGR_EXPIRE has default value 0 => initgroups was not finished.
 * SYSDB_CACHE_EXPIRE has value from future => getpwnam finished successfully
 *
 * Test result: DP should be contacted for update.
 */
void test_nss_initgr_update_two_expire_attributes(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE,
                                 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 time(NULL) + 100);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testinitgr_2attr", 522, 655, "test initgroups2",
                         "/home/testinitgr_2attr", "/bin/sh", NULL,
                         attrs, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group(nss_test_ctx->tctx->dom,
                          "testinitgr_2attr_gr11", 5221,
                          NULL, 300, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_add_group_member(nss_test_ctx->tctx->dom,
                                 "testinitgr_2attr_gr11", "testinitgr_2attr",
                                 SYSDB_MEMBER_USER, false);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testinitgr_2attr");
    mock_account_recv(0, 0, NULL,
                      test_nss_initgr_update_acct_2expire_attributes_cb,
                      nss_test_ctx);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR);
    mock_fill_initgr_user();
    set_cmd_cb(test_nss_initgr_update_2expire_attributes_check);

    /* Query for that user, call a callback when command finishes */
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_INITGR,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_nss_initgroups_upn(void **state)
{
    errno_t ret;

    mock_input_user_or_group("upninitgr@upndomain.test");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR);
    mock_fill_initgr_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_nss_initgr_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_INITGR,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test that searching for a nonexistant user yields ENOENT.
 * Account callback will be called
 */
void test_nss_initgr_neg_upn(void **state)
{
    test_initgr_neg_by_name("upninitgr_neg@upndomain.test", true);
}

static int nss_test_setup(void **state)
{
    struct sss_test_conf_param params[] = {
        { "enumerate", "false" },
        { NULL, NULL },             /* Sentinel */
    };

    test_nss_setup(params, state);
    return 0;
}

static int nss_fqdn_test_setup(void **state)
{
    struct sss_test_conf_param params[] = {
        { "enumerate", "false" },
        { "full_name_format", "%1$s@%2$s" },
        { NULL, NULL },             /* Sentinel */
    };

    test_nss_setup(params, state);
    return 0;
}

static int nss_test_setup_extra_attr(void **state)
{
    struct sss_test_conf_param params[] = {
        { "enumerate", "false" },
        { NULL, NULL },             /* Sentinel */
    };

    test_nss_setup(params, state);

    nss_test_ctx->nctx->extra_attributes = global_extra_attrs;
    return 0;
}

static int nss_subdom_test_setup(void **state)
{
    const char *const testdom[4] = { TEST_SUBDOM_NAME, "TEST.SUB", "test", "S-3" };
    struct sss_domain_info *subdomain;
    errno_t ret;

    nss_test_setup(state);

    subdomain = new_subdomain(nss_test_ctx, nss_test_ctx->tctx->dom,
                              testdom[0], testdom[1], testdom[2], testdom[3],
                              false, false, NULL, 0);
    assert_non_null(subdomain);

    ret = sysdb_subdomain_store(nss_test_ctx->tctx->sysdb,
                                testdom[0], testdom[1], testdom[2], testdom[3],
                                false, false, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(nss_test_ctx->tctx->dom);
    assert_int_equal(ret, EOK);

    nss_test_ctx->subdom = subdomain;
    return 0;
}

static int nss_fqdn_fancy_test_setup(void **state)
{
    struct sss_test_conf_param params[] = {
        { "enumerate", "false" },
        { "full_name_format", "%1$s@@@@@%2$s" },
        { NULL, NULL },             /* Sentinel */
    };

    test_nss_setup(params, state);
    return 0;
}

static int nss_test_teardown(void **state)
{
    talloc_free(nss_test_ctx);
    return 0;
}

static int test_nss_getnamebysid_check(uint32_t status, uint8_t *body, size_t blen)
{
    size_t rp = 2 * sizeof(uint32_t); /* num_results and reserved */
    uint32_t id_type;
    const char *name;

    assert_int_equal(status, EOK);

    SAFEALIGN_COPY_UINT32(&id_type, body+rp, &rp);
    assert_int_equal(id_type, SSS_ID_TYPE_UID);

    name = (const char *) body + rp;
    assert_string_equal(name, "testsiduser");

    return EOK;
}

static void test_nss_getnamebysid(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    char *user_sid;

    attrs = sysdb_new_attrs(nss_test_ctx);
    assert_non_null(attrs);

    user_sid = talloc_asprintf(attrs, "%s-500",
                               nss_test_ctx->tctx->dom->domain_id);
    assert_non_null(user_sid);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, user_sid);
    assert_int_equal(ret, EOK);

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testsiduser", 12345, 6890, "test sid user",
                         "/home/testsiduser", "/bin/sh", NULL,
                         attrs, 300, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group(user_sid);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNAMEBYSID);
    mock_fill_bysid();

    /* Query for that user, call a callback when command finishes */
    /* Should go straight to back end, without contacting DP */
    set_cmd_cb(test_nss_getnamebysid_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test that searching for a nonexistant user yields ENOENT.
 * Account callback will be called
 */
void test_nss_getnamebysid_neg(void **state)
{
    errno_t ret;
    char *user_sid;

    user_sid = talloc_asprintf(nss_test_ctx, "%s-499",
                               nss_test_ctx->tctx->dom->domain_id);
    assert_non_null(user_sid);

    mock_input_user_or_group(user_sid);
    mock_account_recv_simple();

    assert_int_equal(nss_test_ctx->ncache_hits, 0);

    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_int_equal(nss_test_ctx->ncache_hits, 0);

    /* Test that subsequent search for a nonexistent user yields
     * ENOENT and Account callback is not called, on the other hand
     * the ncache functions will be called
     */
    nss_test_ctx->tctx->done = false;

    mock_input_user_or_group(user_sid);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    /* Negative cache was hit this time */
    assert_int_equal(nss_test_ctx->ncache_hits, 1);
}

static int test_nss_getnamebysid_update_check(uint32_t status,
                                              uint8_t *body,
                                              size_t blen)
{
    size_t rp = 2 * sizeof(uint32_t); /* num_results and reserved */
    uint32_t id_type;
    const char *name;

    assert_int_equal(status, EOK);

    SAFEALIGN_COPY_UINT32(&id_type, body+rp, &rp);
    assert_int_equal(id_type, SSS_ID_TYPE_UID);

    name = (const char *) body + rp;
    assert_string_equal(name, "testsidbyname_update");

    return EOK;
}

static int test_nss_getnamebysid_update_acct_cb(void *pvt)
{
    errno_t ret;
    struct nss_test_ctx *ctx = talloc_get_type(pvt, struct nss_test_ctx);

    ret = sysdb_store_user(ctx->tctx->dom, "testsidbyname_update", NULL,
                           123456, 789, "test user",
                           "/home/testsidbyname_update", "/bin/ksh", NULL,
                           NULL, NULL, 300, 0);
    assert_int_equal(ret, EOK);

    return EOK;
}

void test_nss_getnamebysid_update(void **state)
{
    errno_t ret;
    struct ldb_result *res;
    struct sysdb_attrs *attrs;
    const char *shell;
    char *user_sid;

    attrs = sysdb_new_attrs(nss_test_ctx);
    assert_non_null(attrs);

    user_sid = talloc_asprintf(attrs, "%s-123456",
                               nss_test_ctx->tctx->dom->domain_id);
    assert_non_null(user_sid);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, user_sid);
    assert_int_equal(ret, EOK);

    /* Prime the cache with a valid but expired user */
    ret = sysdb_add_user(nss_test_ctx->tctx->dom,
                         "testsidbyname_update", 123456, 789, "test user",
                         "/home/testsidbyname_update", "/bin/sh", NULL,
                         attrs, 1, 1);
    assert_int_equal(ret, EOK);

    /* Mock client input */
    mock_input_user_or_group(user_sid);
    /* Mock client command */
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNAMEBYSID);
    /* Call this function when user is updated by the mock DP request */
    mock_account_recv(0, 0, NULL, test_nss_getnamebysid_update_acct_cb,
                      nss_test_ctx);
    /* Call this function to check what the responder returned to the client */
    set_cmd_cb(test_nss_getnamebysid_update_check);
    /* Mock output buffer */
    mock_fill_bysid();

    /* Fire the command */
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Check the user was updated in the cache */
    ret = sysdb_getpwnam(nss_test_ctx, nss_test_ctx->tctx->dom,
                         "testsidbyname_update", &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);

    shell = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, NULL);
    assert_string_equal(shell, "/bin/ksh");
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
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nss_getpwnam,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwuid,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwnam_neg,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwuid_neg,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwnam_search,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwuid_search,
                                        nss_test_setup,
                                        nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwnam_update,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwuid_update,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwnam_fqdn,
                                        nss_fqdn_test_setup,
                                        nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwnam_fqdn_fancy,
                                        nss_fqdn_fancy_test_setup,
                                        nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwnam_space,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwnam_space_sub,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwnam_space_sub_query,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getgrnam_no_members,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getgrnam_members,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getgrnam_members_fqdn,
                                        nss_fqdn_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getgrnam_members_subdom,
                                        nss_subdom_test_setup,
                                        nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getgrnam_mix_dom,
                                        nss_subdom_test_setup,
                                        nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getgrnam_mix_dom_fqdn,
                                        nss_subdom_test_setup,
                                        nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getgrnam_mix_subdom,
                                        nss_subdom_test_setup,
                                        nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getgrnam_space,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getgrnam_space_sub,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_well_known_getnamebysid,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_well_known_getnamebysid_special,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_well_known_getnamebysid_non_existing,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_well_known_getidbysid_failure,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_well_known_getsidbyname,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_well_known_getsidbyname_nonexisting,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_well_known_getsidbyname_special,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getorigbyname,
                                        nss_test_setup,
                                        nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getorigbyname_extra_attrs,
                                        nss_test_setup_extra_attr,
                                        nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getorigbyname_multi_value_attrs,
                                        nss_test_setup_extra_attr,
                                        nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwnam_upn,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getpwnam_upn_neg,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_initgroups,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_initgr_neg,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_initgr_search,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_initgr_update,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_initgr_update_two_expire_attributes,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_initgroups_upn,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_initgr_neg_upn,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getnamebysid,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getnamebysid_neg,
                                        nss_test_setup, nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_nss_getnamebysid_update,
                                        nss_test_setup, nss_test_teardown),
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
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
    return rv;
}
