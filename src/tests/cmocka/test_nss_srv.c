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
#include <arpa/inet.h>

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"
#include "responder/common/negcache.h"
#include "responder/nss/nss_private.h"
#include "responder/nss/nss_protocol.h"
#include "providers/ipa/ipa_subdomains.h"
#include "sss_client/idmap/sss_nss_idmap.h"
#include "util/util_sss_idmap.h"
#include "util/crypto/sss_crypto.h"
#include "util/sss_endian.h"
#include "db/sysdb.h"
#include "db/sysdb_iphosts.h"
#include "db/sysdb_ipnetworks.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_nss_conf.ldb"
#define TEST_DOM_NAME "nss_test"
#define TEST_SUBDOM_NAME "test.subdomain"
#define TEST_ID_PROVIDER "ldap"
#define TEST_DOM_SID "S-1-5-21-444379608-1639770488-2995963434"

struct sss_nss_test_ctx {
    struct sss_test_ctx *tctx;
    struct sss_domain_info *subdom;

    struct resp_ctx *rctx;
    struct cli_ctx *cctx;
    struct sss_cmd_table *sss_nss_cmds;
    struct sss_nss_ctx *nctx;

    int ncache_hits;
};

#define EXTRA_ATTRS "phone", "mobile"

/* This list comes from nsssrv.c:sss_nss_get_config() and must be kept aligned */
#define ORIG_ATTRS SYSDB_SID_STR, \
                   ORIGINALAD_PREFIX SYSDB_NAME, \
                   ORIGINALAD_PREFIX SYSDB_UIDNUM, \
                   ORIGINALAD_PREFIX SYSDB_GIDNUM, \
                   ORIGINALAD_PREFIX SYSDB_HOMEDIR, \
                   ORIGINALAD_PREFIX SYSDB_GECOS, \
                   ORIGINALAD_PREFIX SYSDB_SHELL, \
                   SYSDB_UPN, \
                   SYSDB_DEFAULT_OVERRIDE_NAME, \
                   SYSDB_AD_ACCOUNT_EXPIRES, \
                   SYSDB_AD_USER_ACCOUNT_CONTROL, \
                   SYSDB_SSH_PUBKEY, \
                   SYSDB_USER_CERT, \
                   SYSDB_USER_EMAIL, \
                   SYSDB_ORIG_DN, \
                   SYSDB_ORIG_MEMBEROF


const char *global_extra_attrs[] = { EXTRA_ATTRS, NULL };
const char *global_orig_attrs[]  = { ORIG_ATTRS, NULL };
const char *global_full_attrs[]  = { ORIG_ATTRS, EXTRA_ATTRS, NULL };


struct sss_nss_test_ctx *sss_nss_test_ctx;

/* Mock NSS structure */
struct sss_nss_ctx *
mock_nctx(TALLOC_CTX *mem_ctx)
{
    struct sss_nss_ctx *nctx;
    enum idmap_error_code err;

    nctx = talloc_zero(mem_ctx, struct sss_nss_ctx);
    if (!nctx) {
        return NULL;
    }

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
    struct cli_protocol *pctx;
    struct sss_packet *packet;
    uint8_t *body;
    size_t blen;
    cmd_cb_fn_t check_cb;

    check_cb = sss_mock_ptr_type(cmd_cb_fn_t);

    if (check_cb == NULL) {
        sss_nss_test_ctx->tctx->error = ENOENT;
    } else {
        pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);
        packet = pctx->creq->out;

        __real_sss_packet_get_body(packet, &body, &blen);

        sss_nss_test_ctx->tctx->error = check_cb(sss_packet_get_status(packet),
                                             body, blen);
    }

    sss_nss_test_ctx->tctx->done = true;
    talloc_free(freectx);
}

enum sss_cli_command __wrap_sss_packet_get_cmd(struct sss_packet *packet)
{
    return sss_mock_type(enum sss_cli_command);
}

int __wrap_sss_cmd_send_empty(struct cli_ctx *cctx, TALLOC_CTX *freectx)
{
    sss_nss_test_ctx->tctx->done = true;
    sss_nss_test_ctx->tctx->error = ENOENT;
    return EOK;
}

/* Intercept negative cache lookups */
int __real_sss_ncache_check_user(struct sss_nc_ctx *ctx,
                                 struct sss_domain_info *dom, const char *name);

int __wrap_sss_ncache_check_user(struct sss_nc_ctx *ctx,
                                 struct sss_domain_info *dom, const char *name)
{
    int ret;

    ret = __real_sss_ncache_check_user(ctx, dom, name);
    if (ret == EEXIST) {
        sss_nss_test_ctx->ncache_hits++;
    }
    return ret;
}

int __real_sss_ncache_check_upn(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom, const char *name);

int __wrap_sss_ncache_check_upn(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom, const char *name)
{
    int ret;

    ret = __real_sss_ncache_check_upn(ctx, dom, name);
    if (ret == EEXIST) {
        sss_nss_test_ctx->ncache_hits++;
    }
    return ret;
}

int __real_sss_ncache_check_uid(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom, uid_t uid);

int __wrap_sss_ncache_check_uid(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom, uid_t uid)
{
    int ret;

    ret = __real_sss_ncache_check_uid(ctx, dom, uid);
    if (ret == EEXIST) {
        sss_nss_test_ctx->ncache_hits++;
    }
    return ret;
}

int __real_sss_ncache_check_sid(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom, const char *sid);

int __wrap_sss_ncache_check_sid(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom, const char *sid)
{
    int ret;

    ret = __real_sss_ncache_check_sid(ctx, dom, sid);
    if (ret == EEXIST) {
        sss_nss_test_ctx->ncache_hits++;
    }
    return ret;
}

int __real_sss_ncache_check_cert(struct sss_nc_ctx *ctx, const char *cert);

int __wrap_sss_ncache_check_cert(struct sss_nc_ctx *ctx, const char *cert)
{
    int ret;

    ret = __real_sss_ncache_check_cert(ctx, cert);
    if (ret == EEXIST) {
        sss_nss_test_ctx->ncache_hits++;
    }
    return ret;
}

/* Mock input from the client library */
static void mock_input_user_or_group(const char *input)
{
    const char *copy;
    const char *shortname;
    const char *domname;
    char *separator;

    copy = talloc_strdup(sss_nss_test_ctx, input);
    assert_non_null(copy);

    separator = strrchr(copy, '@');
    if (separator == NULL) {
        shortname = input;
        domname = NULL;
    } else {
        *separator = '\0';
        shortname = copy;
        domname = separator + 1;
    }

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, input);
    will_return(__wrap_sss_packet_get_body, 0);

    mock_parse_inp(shortname, domname, EOK);
}

static void mock_input_user_or_group_ex(bool do_parse_inp, const char *input,
                                        uint32_t flags)
{
    const char *copy;
    const char *shortname;
    const char *domname;
    char *separator;
    uint8_t *data;
    size_t len;

    len = strlen(input);
    len++;
    data = talloc_size(sss_nss_test_ctx, len + sizeof(uint32_t));
    assert_non_null(data);
    memcpy(data, input, len);
    SAFEALIGN_COPY_UINT32(data + len, &flags, NULL);

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, data);
    will_return(__wrap_sss_packet_get_body, len + sizeof(uint32_t));

    if (do_parse_inp) {
        copy = talloc_strdup(sss_nss_test_ctx, input);
        assert_non_null(copy);

        separator = strrchr(copy, '@');
        if (separator == NULL) {
            shortname = input;
            domname = NULL;
        } else {
            *separator = '\0';
            shortname = copy;
            domname = separator + 1;
        }

        mock_parse_inp(shortname, domname, EOK);
    }
}

static void mock_input_upn(const char *upn)
{
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, upn);
    will_return(__wrap_sss_packet_get_body, 0);

    mock_parse_inp(NULL, NULL, ERR_DOMAIN_NOT_FOUND);
}

static void mock_input_sid(const char *sid)
{
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, sid);
    will_return(__wrap_sss_packet_get_body, 0);
}

static void mock_input_cert(const char *cert)
{
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, cert);
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

static void mock_input_id_ex(TALLOC_CTX *mem_ctx, uint32_t id, uint32_t flags)
{
    uint8_t *body;

    body = talloc_zero_array(mem_ctx, uint8_t, 8);
    if (body == NULL) return;

    SAFEALIGN_SETMEM_UINT32(body, id, NULL);
    SAFEALIGN_SETMEM_UINT32(body + sizeof(uint32_t), flags, NULL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, body);
    will_return(__wrap_sss_packet_get_body, 2 * sizeof(uint32_t));
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

    gr->gr_mem = NULL;

    if (*nmem > 0) {
        gr->gr_mem = talloc_zero_array(sss_nss_test_ctx, char *, *nmem);
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

static errno_t store_user(struct sss_nss_test_ctx *ctx,
                          struct sss_domain_info *dom,
                          struct passwd *user,
                          struct sysdb_attrs *attrs,
                          time_t cache_update)
{
    errno_t ret;
    char *fqname;

    fqname = sss_create_internal_fqname(ctx,
                                        user->pw_name,
                                        dom->name);
    if (fqname == NULL) {
        return ENOMEM;
    }

    /* Prime the cache with a valid user */
    ret = sysdb_store_user(dom,
                           fqname,
                           user->pw_passwd,
                           user->pw_uid,
                           user->pw_gid,
                           user->pw_gecos,
                           user->pw_dir,
                           user->pw_shell,
                           NULL, attrs,
                           NULL, 300, cache_update);
    talloc_free(fqname);
    return ret;
}

static errno_t delete_user(struct sss_nss_test_ctx *ctx,
                           struct sss_domain_info *dom,
                           struct passwd *user)
{
    errno_t ret;
    char *fqname;

    fqname = sss_create_internal_fqname(ctx,
                                        user->pw_name,
                                        dom->name);
    if (fqname == NULL) {
        return ENOMEM;
    }

    ret = sysdb_delete_user(dom, fqname, user->pw_uid);

    talloc_free(fqname);
    return ret;
}

static errno_t set_user_attr(struct sss_nss_test_ctx *ctx,
                             struct sss_domain_info *dom,
                             struct passwd *user,
                             struct sysdb_attrs *attrs)
{
    errno_t ret;
    char *fqname;

    fqname = sss_create_internal_fqname(ctx,
                                        user->pw_name,
                                        dom->name);
    if (fqname == NULL) {
        return ENOMEM;
    }

    ret = sysdb_set_user_attr(sss_nss_test_ctx->tctx->dom,
                              fqname,
                              attrs, SYSDB_MOD_REP);
    talloc_free(fqname);
    return ret;
}

static int get_user(TALLOC_CTX *mem_ctx,
                    struct sss_domain_info *domain,
                    const char *shortname,
                    struct ldb_result **_res)
{
    errno_t ret;
    char *fqname;

    fqname = sss_create_internal_fqname(mem_ctx, shortname,
                                        domain->name);
    if (fqname == NULL) {
        return ENOMEM;
    }

    ret = sysdb_getpwnam(mem_ctx, domain, fqname, _res);
    talloc_free(fqname);
    return ret;
}

static void assert_users_equal(struct passwd *a, struct passwd *b)
{
    assert_int_equal(a->pw_uid, b->pw_uid);
    assert_int_equal(a->pw_gid, b->pw_gid);
    assert_string_equal(a->pw_name, b->pw_name);
    assert_string_equal(a->pw_shell, b->pw_shell);
    assert_string_equal(a->pw_passwd, b->pw_passwd);
}

static errno_t store_group(struct sss_nss_test_ctx *ctx,
                           struct sss_domain_info *dom,
                           struct group *group,
                           struct sysdb_attrs *attrs,
                           time_t cache_update)
{
    errno_t ret;
    char *fqname;

    fqname = sss_create_internal_fqname(ctx,
                                        group->gr_name,
                                        dom->name);
    if (fqname == NULL) {
        return ENOMEM;
    }

    ret = sysdb_store_group(dom,
                            fqname,
                            group->gr_gid,
                            attrs, 300, 0);
    talloc_free(fqname);
    return ret;
}

static errno_t delete_group(struct sss_nss_test_ctx *ctx,
                            struct sss_domain_info *dom,
                            struct group *group)
{
    errno_t ret;
    char *fqname;

    fqname = sss_create_internal_fqname(ctx,
                                        group->gr_name,
                                        dom->name);

    if (fqname == NULL) {
        return ENOMEM;
    }

    ret = sysdb_delete_group(dom, fqname, group->gr_gid);

    talloc_free(fqname);
    return ret;
}

static int cmp_func(const void *a, const void *b)
{
    char *str1 = *(char **)discard_const(a);
    char *str2 = *(char **)discard_const(b);

    return strcmp(str1, str2);
}

static void order_string_array(char **_list, int size)
{
    if (size < 2 || _list == NULL || *_list == NULL) {
        /* Nothing to do */
        return;
    }

    qsort(_list, size, sizeof(char *), cmp_func);
    return;
}

static void assert_groups_equal(struct group *expected,
                                struct group *gr, const int nmem)
{
    int i;

    assert_int_equal(gr->gr_gid, expected->gr_gid);
    assert_string_equal(gr->gr_name, expected->gr_name);
    assert_string_equal(gr->gr_passwd, expected->gr_passwd);

    order_string_array(gr->gr_mem, nmem);
    order_string_array(expected->gr_mem, nmem);

    for (i = 0; i < nmem; i++) {
        assert_string_equal(gr->gr_mem[i], expected->gr_mem[i]);
    }
}

static errno_t store_group_member(struct sss_nss_test_ctx *ctx,
                                  const char *shortname_group,
                                  struct sss_domain_info *group_dom,
                                  const char *shortname_member,
                                  struct sss_domain_info *member_dom,
                                  enum sysdb_member_type type)
{
    errno_t ret;
    char *group_fqname = NULL;
    char *member_fqname = NULL;

    group_fqname = sss_create_internal_fqname(ctx,
                                        shortname_group,
                                        group_dom->name);
    if (group_fqname == NULL) {
        return ENOMEM;
    }

    member_fqname = sss_create_internal_fqname(ctx,
                                        shortname_member,
                                        member_dom->name);
    if (member_fqname == NULL) {
        talloc_free(group_fqname);
        return ENOMEM;
    }

    ret = sysdb_add_group_member(group_dom,
                                 group_fqname,
                                 member_fqname,
                                 SYSDB_MEMBER_USER, false);
    talloc_free(group_fqname);
    talloc_free(member_fqname);
    return ret;
}

static errno_t remove_group_member(struct sss_nss_test_ctx *ctx,
                                   const char *shortname_group,
                                   struct sss_domain_info *group_dom,
                                   const char *shortname_member,
                                   struct sss_domain_info *member_dom,
                                   enum sysdb_member_type type)
{
    errno_t ret;
    char *group_fqname = NULL;
    char *member_fqname = NULL;

    group_fqname = sss_create_internal_fqname(ctx,
                                        shortname_group,
                                        group_dom->name);
    if (group_fqname == NULL) {
        return ENOMEM;
    }

    member_fqname = sss_create_internal_fqname(ctx,
                                        shortname_member,
                                        member_dom->name);
    if (member_fqname == NULL) {
        talloc_free(group_fqname);
        return ENOMEM;
    }

    ret = sysdb_remove_group_member(group_dom,
                                    group_fqname,
                                    member_fqname,
                                    type,
                                    false);

    talloc_free(group_fqname);
    talloc_free(member_fqname);
    return ret;
}

/* ====================== The tests =============================== */
struct passwd getpwnam_usr = {
    .pw_name = discard_const("testuser"),
    .pw_uid = 123,
    .pw_gid = 456,
    .pw_dir = discard_const("/home/testuser"),
    .pw_gecos = discard_const("test user"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

/* Check getting cached and valid user from cache. Account callback will
 * not be called and test_sss_nss_getpwnam_check will make sure the user is
 * the same as the test entered before starting
 */
static int test_sss_nss_getpwnam_check(uint32_t status, uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_users_equal(&pwd, &getpwnam_usr);
    return EOK;
}

void test_sss_nss_getpwnam(void **state)
{
    errno_t ret;

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &getpwnam_usr, NULL, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testuser");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getpwnam_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test that searching for a nonexistent user yields ENOENT.
 * Account callback will be called
 */
void test_sss_nss_getpwnam_neg(void **state)
{
    errno_t ret;

    mock_input_user_or_group("testuser_neg");
    mock_account_recv_simple();

    assert_int_equal(sss_nss_test_ctx->ncache_hits, 0);

    set_cmd_cb(NULL);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_int_equal(sss_nss_test_ctx->ncache_hits, 0);

    /* Test that subsequent search for a nonexistent user yields
     * ENOENT and Account callback is not called, on the other hand
     * the ncache functions will be called
     */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_user_or_group("testuser_neg");
    set_cmd_cb(NULL);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    /* Negative cache was hit this time */
    assert_int_equal(sss_nss_test_ctx->ncache_hits, 1);
}

struct passwd getpwnam_search_usr = {
    .pw_name = discard_const("testuser_search"),
    .pw_uid = 567,
    .pw_gid = 890,
    .pw_dir = discard_const("/home/testuser_search"),
    .pw_gecos = discard_const("test search user"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

static int test_sss_nss_getpwnam_search_acct_cb(void *pvt)
{
    struct sss_nss_test_ctx *ctx = talloc_get_type(pvt, struct sss_nss_test_ctx);

    return store_user(ctx, ctx->tctx->dom, &getpwnam_search_usr, NULL, 0);
}

static int test_sss_nss_getpwnam_search_check(uint32_t status,
                                          uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_users_equal(&pwd, &getpwnam_search_usr);
    return EOK;
}

void test_sss_nss_getpwnam_search(void **state)
{
    errno_t ret;
    struct ldb_result *res;

    mock_input_user_or_group("testuser_search");
    mock_account_recv(0, 0, NULL, test_sss_nss_getpwnam_search_acct_cb, sss_nss_test_ctx);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();
    set_cmd_cb(test_sss_nss_getpwnam_search_check);

    ret = get_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                   "testuser_search", &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);

    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* test_sss_nss_getpwnam_search_check will check the user attributes */
    ret = get_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                   "testuser_search", &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
}

/* Test that searching for a user that is expired in the cache goes to the DP
 * which updates the record and the NSS responder returns the updated record
 *
 * The user's shell attribute is updated.
 */

struct passwd getpwnam_update = {
    .pw_name = discard_const("testuser_update"),
    .pw_uid = 10,
    .pw_gid = 11,
    .pw_dir = discard_const("/home/testuser"),
    .pw_gecos = discard_const("test user"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

static int test_sss_nss_getpwnam_update_acct_cb(void *pvt)
{
    struct sss_nss_test_ctx *ctx = talloc_get_type(pvt, struct sss_nss_test_ctx);

    getpwnam_update.pw_shell = discard_const("/bin/ksh");
    return store_user(ctx, ctx->tctx->dom, &getpwnam_update, NULL, 0);
}

static int test_sss_nss_getpwnam_update_check(uint32_t status,
                                          uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_users_equal(&pwd, &getpwnam_update);
    return EOK;
}

void test_sss_nss_getpwnam_update(void **state)
{
    errno_t ret;
    struct ldb_result *res;
    const char *shell;

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &getpwnam_update, NULL, 1);
    assert_int_equal(ret, EOK);

    /* Mock client input */
    mock_input_user_or_group("testuser_update");
    /* Mock client command */
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    /* Call this function when user is updated by the mock DP request */
    mock_account_recv(0, 0, NULL, test_sss_nss_getpwnam_update_acct_cb, sss_nss_test_ctx);
    /* Call this function to check what the responder returned to the client */
    set_cmd_cb(test_sss_nss_getpwnam_update_check);
    /* Mock output buffer */
    mock_fill_user();

    /* Fire the command */
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Check the user was updated in the cache */
    ret = get_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                   "testuser_update" , &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);

    shell = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, NULL);
    assert_string_equal(shell, "/bin/ksh");
}

/* Check that a FQDN is returned if the domain is FQDN-only and a
 * FQDN is requested
 */
struct passwd getpwnam_fqdn = {
    .pw_name = discard_const("testuser_fqdn"),
    .pw_uid = 124,
    .pw_gid = 457,
    .pw_dir = discard_const("/home/testuser"),
    .pw_gecos = discard_const("test user"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

static int test_sss_nss_getpwnam_check_fqdn(uint32_t status,
                                        uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    sss_nss_test_ctx->cctx->rctx->domains[0].fqnames = false;

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    getpwnam_fqdn.pw_name = discard_const("testuser_fqdn@"TEST_DOM_NAME);
    assert_users_equal(&pwd, &getpwnam_fqdn);
    return EOK;
}

void test_sss_nss_getpwnam_fqdn(void **state)
{
    errno_t ret;

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &getpwnam_fqdn, NULL, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testuser_fqdn@"TEST_DOM_NAME);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getpwnam_check_fqdn);
    sss_nss_test_ctx->cctx->rctx->domains[0].fqnames = true;
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Check that a user with a space in his username is returned fine.
 */
struct passwd getpwnam_space = {
    .pw_name = discard_const("space user"),
    .pw_uid = 225,
    .pw_gid = 558,
    .pw_dir = discard_const("/home/testuser"),
    .pw_gecos = discard_const("test user"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

static int test_sss_nss_getpwnam_check_space(uint32_t status,
                                         uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_users_equal(&pwd, &getpwnam_space);
    return EOK;
}

void test_sss_nss_getpwnam_space(void **state)
{
    errno_t ret;

    /* Prime the cache with a valid user */
    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &getpwnam_space, NULL, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("space user");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getpwnam_check_space);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

}

static int test_sss_nss_getpwnam_check_space_sub(uint32_t status,
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

void test_sss_nss_getpwnam_space_sub(void **state)
{
    errno_t ret;

    /* Set whitespace substitution */
    sss_nss_test_ctx->rctx->override_space = '_';

    mock_input_user_or_group("space user");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getpwnam_check_space_sub);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    sss_nss_test_ctx->rctx->override_space = '\0';
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getpwnam_space_sub_query(void **state)
{
    errno_t ret;

    /* Set whitespace substitution */
    sss_nss_test_ctx->rctx->override_space = '_';

    mock_input_user_or_group("space_user");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getpwnam_check_space_sub);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    sss_nss_test_ctx->rctx->override_space = '\0';
    assert_int_equal(ret, EOK);
}

/*
 * Check that FQDN processing is able to handle arbitrarily sized
 * delimiter
 */
struct passwd getpwnam_fancy_fqdn = {
    .pw_name = discard_const("testuser_fqdn_fancy"),
    .pw_uid = 125,
    .pw_gid = 458,
    .pw_dir = discard_const("/home/testuser"),
    .pw_gecos = discard_const("test user"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

static int test_sss_nss_getpwnam_check_fancy_fqdn(uint32_t status,
                                              uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    sss_nss_test_ctx->cctx->rctx->domains[0].fqnames = false;

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 125);
    assert_int_equal(pwd.pw_gid, 458);
    assert_string_equal(pwd.pw_name, "testuser_fqdn_fancy@@@@@"TEST_DOM_NAME);
    assert_string_equal(pwd.pw_shell, "/bin/sh");
    return EOK;
}

void test_sss_nss_getpwnam_fqdn_fancy(void **state)
{
    errno_t ret;

    /* Prime the cache with a valid user */
    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &getpwnam_fancy_fqdn, NULL, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testuser_fqdn_fancy@"TEST_DOM_NAME);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getpwnam_check_fancy_fqdn);
    sss_nss_test_ctx->cctx->rctx->domains[0].fqnames = true;
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Check getting cached and valid id from cache. Account callback will
 * not be called and test_sss_nss_getpwuid_check will make sure the id is
 * the same as the test entered before starting
 */
struct passwd getpwuid_usr = {
    .pw_name = discard_const("testuser1"),
    .pw_uid = 101,
    .pw_gid = 401,
    .pw_dir = discard_const("/home/testuser1"),
    .pw_gecos = discard_const("test user1"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

static int test_sss_nss_getpwuid_check(uint32_t status, uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_users_equal(&pwd, &getpwuid_usr);
    return EOK;
}

void test_sss_nss_getpwuid(void **state)
{
    errno_t ret;
    uint32_t id = 101;

    /* Prime the cache with a valid user */
    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &getpwuid_usr, NULL, 0);
    assert_int_equal(ret, EOK);

    mock_input_id(sss_nss_test_ctx, id);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWUID);
    mock_fill_user();

    /* Query for that id, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getpwuid_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWUID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test that searching for a nonexistent id yields ENOENT.
 * Account callback will be called
 */
void test_sss_nss_getpwuid_neg(void **state)
{
    errno_t ret;
    uid_t uid_neg = 102;

    mock_input_id(sss_nss_test_ctx, uid_neg);
    mock_account_recv_simple();

    assert_int_equal(sss_nss_test_ctx->ncache_hits, 0);

    set_cmd_cb(NULL);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWUID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_int_equal(sss_nss_test_ctx->ncache_hits, 0);

    /* Test that subsequent search for a nonexistent id yields
     * ENOENT and Account callback is not called, on the other hand
     * the ncache functions will be called
     */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_id(sss_nss_test_ctx, uid_neg);
    set_cmd_cb(NULL);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWUID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    /* Negative cache was hit this time */
    assert_int_equal(sss_nss_test_ctx->ncache_hits, 1);
}

/* Test that lookup by UID for a user that does
 * not exist in the cache fetches the user from DP
 */
struct passwd getpwuid_srch = {
    .pw_name = discard_const("exampleuser_search"),
    .pw_uid = 107,
    .pw_gid = 987,
    .pw_dir = discard_const("/home/examplesearch"),
    .pw_gecos = discard_const("example search"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

static int test_sss_nss_getpwuid_search_acct_cb(void *pvt)
{
    struct sss_nss_test_ctx *ctx = talloc_get_type(pvt, struct sss_nss_test_ctx);

    return store_user(ctx, ctx->tctx->dom, &getpwuid_srch, NULL, 0);
}

static int test_sss_nss_getpwuid_search_check(uint32_t status,
                                          uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_users_equal(&pwd, &getpwuid_srch);
    return EOK;
}

void test_sss_nss_getpwuid_search(void **state)
{
    errno_t ret;
    struct ldb_result *res;

    mock_input_id(sss_nss_test_ctx, getpwuid_srch.pw_uid);
    mock_account_recv(0, 0, NULL, test_sss_nss_getpwuid_search_acct_cb, sss_nss_test_ctx);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWUID);
    mock_fill_user();
    set_cmd_cb(test_sss_nss_getpwuid_search_check);

    ret = sysdb_getpwuid(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                         getpwuid_srch.pw_uid, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);

    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWUID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* test_sss_nss_getpwuid_search_check will check the id attributes */
    ret = sysdb_getpwuid(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                         getpwuid_srch.pw_uid, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
}

/* Test that searching for an id that is expired in the cache goes to the DP
 * which updates the record and the NSS responder returns the updated record
 *
 * The user's shell attribute is updated.
 */
struct passwd getpwuid_update = {
    .pw_name = discard_const("exampleuser_update"),
    .pw_uid = 109,
    .pw_gid = 11000,
    .pw_dir = discard_const("/home/exampleuser"),
    .pw_gecos = discard_const("example user"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

static int test_sss_nss_getpwuid_update_acct_cb(void *pvt)
{
    struct sss_nss_test_ctx *ctx = talloc_get_type(pvt, struct sss_nss_test_ctx);

    getpwuid_update.pw_shell = discard_const("/bin/ksh");
    return store_user(ctx, ctx->tctx->dom, &getpwuid_update, NULL, 0);
}

static int test_sss_nss_getpwuid_update_check(uint32_t status,
                                          uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_users_equal(&pwd, &getpwuid_update);
    return EOK;
}

void test_sss_nss_getpwuid_update(void **state)
{
    errno_t ret;
    struct ldb_result *res;
    const char *shell;

    /* Prime the cache with a valid but expired user */
    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &getpwuid_update, NULL, 1);
    assert_int_equal(ret, EOK);

    /* Mock client input */
    mock_input_id(sss_nss_test_ctx, getpwuid_update.pw_uid);
    /* Mock client command */
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWUID);
    /* Call this function when id is updated by the mock DP request */
    mock_account_recv(0, 0, NULL, test_sss_nss_getpwuid_update_acct_cb, sss_nss_test_ctx);
    /* Call this function to check what the responder returned to the client */
    set_cmd_cb(test_sss_nss_getpwuid_update_check);
    /* Mock output buffer */
    mock_fill_user();

    /* Fire the command */
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWUID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Check the user was updated in the cache */
    ret = sysdb_getpwuid(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                         getpwuid_update.pw_uid, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);

    shell = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, NULL);
    assert_string_equal(shell, "/bin/ksh");
}

/* Testsuite setup and teardown */
void test_sss_nss_setup(struct sss_test_conf_param params[],
                    void **state)
{
    errno_t ret;

    sss_nss_test_ctx = talloc_zero(NULL, struct sss_nss_test_ctx);
    assert_non_null(sss_nss_test_ctx);

    sss_nss_test_ctx->tctx = create_dom_test_ctx(sss_nss_test_ctx, TESTS_PATH,
                                             TEST_CONF_DB, TEST_DOM_NAME,
                                             TEST_ID_PROVIDER, params);
    assert_non_null(sss_nss_test_ctx->tctx);

    sss_nss_test_ctx->tctx->dom->domain_id = discard_const(TEST_DOM_SID);

    sss_nss_test_ctx->sss_nss_cmds = get_sss_nss_cmds();
    assert_non_null(sss_nss_test_ctx->sss_nss_cmds);

    /* FIXME - perhaps this should be folded into sssd_domain_init or strictly
     * used together
     */
    ret = sss_names_init(sss_nss_test_ctx, sss_nss_test_ctx->tctx->confdb,
                         TEST_DOM_NAME, &sss_nss_test_ctx->tctx->dom->names);
    assert_int_equal(ret, EOK);

    /* Initialize the NSS responder */
    sss_nss_test_ctx->nctx = mock_nctx(sss_nss_test_ctx);
    assert_non_null(sss_nss_test_ctx->nctx);

    sss_nss_test_ctx->rctx = mock_rctx(sss_nss_test_ctx, sss_nss_test_ctx->tctx->ev,
                                   sss_nss_test_ctx->tctx->dom, sss_nss_test_ctx->nctx);
    assert_non_null(sss_nss_test_ctx->rctx);
    sss_nss_test_ctx->rctx->cdb = sss_nss_test_ctx->tctx->confdb;
    sss_nss_test_ctx->nctx->rctx = sss_nss_test_ctx->rctx;

    ret = sss_ad_default_names_ctx(sss_nss_test_ctx->nctx,
                                   &sss_nss_test_ctx->nctx->rctx->global_names);
    assert_int_equal(ret, EOK);
    assert_non_null(sss_nss_test_ctx->nctx->rctx->global_names);

    /* Create client context */
    sss_nss_test_ctx->cctx = mock_cctx(sss_nss_test_ctx, sss_nss_test_ctx->rctx);
    assert_non_null(sss_nss_test_ctx->cctx);

    /* Add nss specific state_ctx */
    sss_nss_connection_setup(sss_nss_test_ctx->cctx);
    assert_non_null(sss_nss_test_ctx->cctx->state_ctx);

    /* do after previous setup as the former nulls protocol_ctx */
    sss_nss_test_ctx->cctx->protocol_ctx = mock_prctx(sss_nss_test_ctx->cctx);
    assert_non_null(sss_nss_test_ctx->cctx->protocol_ctx);

    sss_nss_test_ctx->nctx->full_attribute_list = global_orig_attrs;
}

struct group getgrnam_no_members = {
    .gr_gid = 1123,
    .gr_name = discard_const("testgroup"),
    .gr_passwd = discard_const("*"),
    .gr_mem = NULL,
};

static int test_sss_nss_getgrnam_no_members_check(uint32_t status,
                                              uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 0);

    assert_groups_equal(&getgrnam_no_members, &gr, nmem);
    return EOK;
}

/* Test that requesting a valid, cached group with no members returns a valid
 * group structure
 */
void test_sss_nss_getgrnam_no_members(void **state)
{
    errno_t ret;

    /* Prime the cache with a valid group */
    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &getgrnam_no_members, NULL, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group(getgrnam_no_members.gr_name);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_no_members_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

struct passwd testmember1 = {
    .pw_name = discard_const("testmember1"),
    .pw_uid = 2001,
    .pw_gid = 456,
    .pw_dir = discard_const("/home/testmember1"),
    .pw_gecos = discard_const("test member1"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

struct passwd testmember2 = {
    .pw_name = discard_const("testmember2"),
    .pw_uid = 2002,
    .pw_gid = 456,
    .pw_dir = discard_const("/home/testmember2"),
    .pw_gecos = discard_const("test member2"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

struct group testgroup_members = {
    .gr_gid = 1124,
    .gr_name = discard_const("testgroup_members"),
    .gr_passwd = discard_const("*"),
    .gr_mem = NULL,
};

static int test_sss_nss_getgrnam_members_check(uint32_t status,
                                           uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    const char *exp_members[] = { testmember1.pw_name,
                                  testmember2.pw_name };
    struct group expected = {
        .gr_gid = testgroup_members.gr_gid,
        .gr_name = testgroup_members.gr_name,
        .gr_passwd = testgroup_members.gr_passwd,
        .gr_mem = discard_const(exp_members)
    };

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 2);

    assert_groups_equal(&expected, &gr, nmem);
    return EOK;
}

/* Test that requesting a valid, cached group with some members returns a valid
 * group structure with those members present
 */
void test_sss_nss_getgrnam_members(void **state)
{
    errno_t ret;

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &testgroup_members, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &testmember1, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &testmember2, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_group_member(sss_nss_test_ctx,
                             testgroup_members.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             testmember1.pw_name,
                             sss_nss_test_ctx->tctx->dom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    ret = store_group_member(sss_nss_test_ctx,
                             testgroup_members.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             testmember2.pw_name,
                             sss_nss_test_ctx->tctx->dom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testgroup_members");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_members_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_sss_nss_getgrnam_members_check_fqdn(uint32_t status,
                                                uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    const char *exp_members[2];
    struct group expected = {
        .gr_gid = testgroup_members.gr_gid,
        .gr_passwd = testgroup_members.gr_passwd,
        .gr_mem = discard_const(exp_members)
    };
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(sss_nss_test_ctx);
    assert_non_null(tmp_ctx);

    exp_members[0] = sss_tc_fqname(tmp_ctx, sss_nss_test_ctx->tctx->dom->names,
                                   sss_nss_test_ctx->tctx->dom, testmember1.pw_name);
    assert_non_null(exp_members[0]);
    exp_members[1] = sss_tc_fqname(tmp_ctx, sss_nss_test_ctx->tctx->dom->names,
                                   sss_nss_test_ctx->tctx->dom, testmember2.pw_name);
    assert_non_null(exp_members[1]);

    expected.gr_name = sss_tc_fqname(tmp_ctx,
                                     sss_nss_test_ctx->tctx->dom->names,
                                     sss_nss_test_ctx->tctx->dom,
                                     testgroup_members.gr_name);
    assert_non_null(expected.gr_name);

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 2);

    assert_groups_equal(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    talloc_free(tmp_ctx);
    return EOK;
}

/* Test that requesting a valid, cached group with some members returns a valid
 * group structure with those members present as fully qualified names
 */
void test_sss_nss_getgrnam_members_fqdn(void **state)
{
    errno_t ret;

    sss_nss_test_ctx->tctx->dom->fqnames = true;

    mock_input_user_or_group("testgroup_members@"TEST_DOM_NAME);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_members_check_fqdn);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);

    /* Restore FQDN settings */
    sss_nss_test_ctx->tctx->dom->fqnames = false;
    assert_int_equal(ret, EOK);
}

/* Test that requesting a valid, cached group with subdomain members returns
 * a valid * group structure with those members present as fully
 * qualified names
 */
struct passwd submember1 = {
    .pw_name = discard_const("submember1"),
    .pw_uid = 4001,
    .pw_gid = 456,
    .pw_dir = discard_const("/home/submember1"),
    .pw_gecos = discard_const("sub member1"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

struct passwd submember2 = {
    .pw_name = discard_const("submember2"),
    .pw_uid = 4002,
    .pw_gid = 456,
    .pw_dir = discard_const("/home/submember2"),
    .pw_gecos = discard_const("sub member2"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

struct group testsubdomgroup = {
    .gr_gid = 2002,
    .gr_name = discard_const("testsubdomgroup"),
    .gr_passwd = discard_const("*"),
    .gr_mem = NULL,
};

static int test_sss_nss_getgrnam_members_check_subdom(uint32_t status,
                                                  uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    const char *exp_members[2];
    struct group expected = {
        .gr_gid = testsubdomgroup.gr_gid,
        .gr_passwd = testsubdomgroup.gr_passwd,
        .gr_mem = discard_const(exp_members)
    };
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(sss_nss_test_ctx);
    assert_non_null(tmp_ctx);

    exp_members[0] = sss_tc_fqname(tmp_ctx,
                                   sss_nss_test_ctx->subdom->names,
                                   sss_nss_test_ctx->subdom,
                                   submember1.pw_name);
    assert_non_null(exp_members[0]);

    exp_members[1] = sss_tc_fqname(tmp_ctx,
                                   sss_nss_test_ctx->subdom->names,
                                   sss_nss_test_ctx->subdom,
                                   submember2.pw_name);
    assert_non_null(exp_members[1]);

    expected.gr_name = sss_tc_fqname(tmp_ctx,
                                     sss_nss_test_ctx->subdom->names,
                                     sss_nss_test_ctx->subdom,
                                     testsubdomgroup.gr_name);
    assert_non_null(expected.gr_name);

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 2);

    assert_groups_equal(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    talloc_free(tmp_ctx);
    return EOK;
}

void test_sss_nss_getgrnam_members_subdom(void **state)
{
    errno_t ret;

    mock_input_user_or_group("testsubdomgroup@"TEST_SUBDOM_NAME);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_members_check_subdom);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);

    assert_int_equal(ret, EOK);
}

void test_sss_nss_getgrnam_members_subdom_nonfqnames(void **state)
{
    errno_t ret;

    mock_input_user_or_group("testsubdomgroup");
    mock_account_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_members_check_subdom);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);

    assert_int_equal(ret, EOK);
}

static int test_sss_nss_getgrnam_check_mix_dom(uint32_t status,
                                           uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    const char *exp_members[3];
    struct group expected = {
        .gr_name = testgroup_members.gr_name,
        .gr_gid = testgroup_members.gr_gid,
        .gr_passwd = testgroup_members.gr_passwd,
        .gr_mem = discard_const(exp_members)
    };
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(sss_nss_test_ctx);
    assert_non_null(tmp_ctx);

    exp_members[0] = sss_tc_fqname(tmp_ctx,
                                   sss_nss_test_ctx->subdom->names,
                                   sss_nss_test_ctx->subdom,
                                   submember1.pw_name);
    assert_non_null(exp_members[0]);
    exp_members[1] = testmember1.pw_name;
    exp_members[2] = testmember2.pw_name;

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 3);

    assert_groups_equal(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    talloc_free(tmp_ctx);
    return EOK;
}

void test_sss_nss_getgrnam_mix_dom(void **state)
{
    errno_t ret;

    ret = store_group_member(sss_nss_test_ctx,
                             testgroup_members.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             submember1.pw_name,
                             sss_nss_test_ctx->subdom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testgroup_members");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_check_mix_dom);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getgrnam_mix_dom_nonfqnames(void **state)
{
    errno_t ret;

    ret = store_group_member(sss_nss_test_ctx,
                             testgroup_members.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             submember1.pw_name,
                             sss_nss_test_ctx->subdom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testgroup_members");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_check_mix_dom);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_sss_nss_getgrnam_check_mix_dom_fqdn(uint32_t status,
                                                uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    const char *exp_members[3];
    struct group expected = {
        .gr_gid = testgroup_members.gr_gid,
        .gr_passwd = testgroup_members.gr_passwd,
        .gr_mem = discard_const(exp_members)
    };
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(sss_nss_test_ctx);
    assert_non_null(tmp_ctx);

    exp_members[0] = sss_tc_fqname(tmp_ctx,
                                   sss_nss_test_ctx->subdom->names,
                                   sss_nss_test_ctx->subdom,
                                   submember1.pw_name);
    assert_non_null(exp_members[0]);

    if (sss_nss_test_ctx->tctx->dom->fqnames) {
        exp_members[1] = sss_tc_fqname(tmp_ctx, sss_nss_test_ctx->tctx->dom->names,
                                       sss_nss_test_ctx->tctx->dom, testmember1.pw_name);
        assert_non_null(exp_members[1]);
        exp_members[2] = sss_tc_fqname(tmp_ctx, sss_nss_test_ctx->tctx->dom->names,
                                       sss_nss_test_ctx->tctx->dom, testmember2.pw_name);
        assert_non_null(exp_members[2]);

        expected.gr_name = sss_tc_fqname(tmp_ctx,
                                         sss_nss_test_ctx->tctx->dom->names,
                                         sss_nss_test_ctx->tctx->dom,
                                         testgroup_members.gr_name);
        assert_non_null(expected.gr_name);
    } else {
        exp_members[1] = testmember1.pw_name;
        exp_members[2] = testmember2.pw_name;
        expected.gr_name = testgroup_members.gr_name;
    }

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 3);

    assert_groups_equal(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    talloc_free(tmp_ctx);
    return EOK;
}

void test_sss_nss_getgrnam_mix_dom_fqdn(void **state)
{
    errno_t ret;

    ret = store_group_member(sss_nss_test_ctx,
                             testgroup_members.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             submember1.pw_name,
                             sss_nss_test_ctx->subdom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    sss_nss_test_ctx->tctx->dom->fqnames = true;

    mock_input_user_or_group("testgroup_members@"TEST_DOM_NAME);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_check_mix_dom_fqdn);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);

    /* Restore FQDN settings */
    sss_nss_test_ctx->tctx->dom->fqnames = false;
    assert_int_equal(ret, EOK);
}


void test_sss_nss_getgrnam_mix_dom_fqdn_nonfqnames(void **state)
{
    errno_t ret;

    ret = store_group_member(sss_nss_test_ctx,
                             testgroup_members.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             submember1.pw_name,
                             sss_nss_test_ctx->subdom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testgroup_members");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_check_mix_dom_fqdn);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);

    /* Restore FQDN settings */
    sss_nss_test_ctx->tctx->dom->fqnames = false;
    assert_int_equal(ret, EOK);
}

static int test_sss_nss_getgrnam_check_mix_subdom(uint32_t status,
                                              uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;
    const char *exp_members[3];
    struct group expected = {
        .gr_gid = testsubdomgroup.gr_gid,
        .gr_passwd = testsubdomgroup.gr_passwd,
        .gr_mem = discard_const(exp_members)
    };
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(sss_nss_test_ctx);
    assert_non_null(tmp_ctx);

    exp_members[0] = sss_tc_fqname(tmp_ctx,
                                   sss_nss_test_ctx->subdom->names,
                                   sss_nss_test_ctx->subdom,
                                   submember1.pw_name);
    assert_non_null(exp_members[0]);

    exp_members[1] = sss_tc_fqname(tmp_ctx,
                                   sss_nss_test_ctx->subdom->names,
                                   sss_nss_test_ctx->subdom,
                                   submember2.pw_name);
    assert_non_null(exp_members[1]);

    /* Important: this member is from a non-qualified domain, so his name will
     * not be qualified either
     */
    exp_members[2] = testmember1.pw_name;

    expected.gr_name = sss_tc_fqname(tmp_ctx,
                                     sss_nss_test_ctx->subdom->names,
                                     sss_nss_test_ctx->subdom,
                                     testsubdomgroup.gr_name);
    assert_non_null(expected.gr_name);

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 3);

    assert_groups_equal(&expected, &gr, nmem);
    assert_int_equal(ret, EOK);

    talloc_free(tmp_ctx);
    return EOK;
}

void test_sss_nss_getgrnam_mix_subdom(void **state)
{
    errno_t ret;

    ret = store_group_member(sss_nss_test_ctx,
                             testsubdomgroup.gr_name,
                             sss_nss_test_ctx->subdom,
                             testmember1.pw_name,
                             sss_nss_test_ctx->tctx->dom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testsubdomgroup@"TEST_SUBDOM_NAME);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_check_mix_subdom);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getgrnam_mix_subdom_nonfqnames(void **state)
{
    errno_t ret;

    ret = store_group_member(sss_nss_test_ctx,
                             testsubdomgroup.gr_name,
                             sss_nss_test_ctx->subdom,
                             testmember1.pw_name,
                             sss_nss_test_ctx->tctx->dom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testsubdomgroup");
    mock_account_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_check_mix_subdom);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

struct group space_group = {
    .gr_gid = 2123,
    .gr_name = discard_const("space group"),
    .gr_passwd = discard_const("*"),
    .gr_mem = NULL,
};

static int test_sss_nss_getgrnam_space_check(uint32_t status,
                                         uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 0);

    assert_groups_equal(&space_group, &gr, nmem);
    assert_int_equal(ret, EOK);

    return EOK;
}

/* Test that requesting a valid, cached group with space in its name returns a valid
 * group structure
 */
void test_sss_nss_getgrnam_space(void **state)
{
    errno_t ret;

    /* Prime the cache with a valid group */
    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &space_group, NULL, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("space group");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_space_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_sss_nss_getgrnam_space_sub_check(uint32_t status,
                                             uint8_t *body, size_t blen)
{
    int ret;
    uint32_t nmem;
    struct group gr;

    assert_int_equal(status, EOK);

    ret = parse_group_packet(body, blen, &gr, &nmem);
    assert_int_equal(ret, EOK);
    assert_int_equal(nmem, 0);

    space_group.gr_name = discard_const("space_group");
    assert_groups_equal(&space_group, &gr, nmem);
    assert_int_equal(ret, EOK);

    return EOK;
}

/* Test that requesting a valid, cached group with space in its name returns a valid
 * group structure
 */
void test_sss_nss_getgrnam_space_sub(void **state)
{
    errno_t ret;

    /* Set whitespace substitution */
    sss_nss_test_ctx->rctx->override_space = '_';

    mock_input_user_or_group("space group");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_space_sub_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    sss_nss_test_ctx->rctx->override_space = '\0';
    assert_int_equal(ret, EOK);
}

static int test_sss_nss_well_known_sid_check(uint32_t status,
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

void test_sss_nss_well_known_getnamebysid(void **state)
{
    errno_t ret;

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, "S-1-5-32-550");
    will_return(__wrap_sss_packet_get_body, 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNAMEBYSID);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(test_sss_nss_well_known_sid_check, "Print Operators@BUILTIN");

    set_cmd_cb(test_sss_nss_well_known_sid_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_well_known_getnamebysid_special(void **state)
{
    errno_t ret;

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, "S-1-2-0");
    will_return(__wrap_sss_packet_get_body, 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNAMEBYSID);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(test_sss_nss_well_known_sid_check, "LOCAL@LOCAL AUTHORITY");

    set_cmd_cb(test_sss_nss_well_known_sid_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_well_known_getnamebysid_non_existing(void **state)
{
    errno_t ret;

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, "S-1-5-32-123");
    will_return(__wrap_sss_packet_get_body, 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNAMEBYSID);
    will_return(test_sss_nss_well_known_sid_check, NULL);

    set_cmd_cb(test_sss_nss_well_known_sid_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_well_known_getidbysid_failure(void **state)
{
    errno_t ret;

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, "S-1-5-32-550");
    will_return(__wrap_sss_packet_get_body, 0);
    will_return_always(__wrap_sss_packet_get_cmd, SSS_NSS_GETIDBYSID);
    will_return(test_sss_nss_well_known_sid_check, NULL);

    set_cmd_cb(test_sss_nss_well_known_sid_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETIDBYSID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_well_known_getsidbyname(void **state)
{
    errno_t ret;
    const char *names[] = { "Cryptographic Operators@BUILTIN",
                            "BUILTIN\\Cryptographic Operators", NULL};
    size_t c;

    for (c = 0; names[c] != NULL; c++) {
        sss_nss_test_ctx->tctx->done = false;

        will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
        will_return(__wrap_sss_packet_get_body, names[c]);
        will_return(__wrap_sss_packet_get_body, 0);
        will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYNAME);
        will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
        will_return(test_sss_nss_well_known_sid_check, "S-1-5-32-569");

        set_cmd_cb(test_sss_nss_well_known_sid_check);
        ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYNAME,
                              sss_nss_test_ctx->sss_nss_cmds);
        assert_int_equal(ret, EOK);

        /* Wait until the test finishes with EOK */
        ret = test_ev_loop(sss_nss_test_ctx->tctx);
        assert_int_equal(ret, EOK);
    }
}

void test_sss_nss_well_known_getsidbyname_nonexisting(void **state)
{
    errno_t ret;
    const char *names[] = { "Abc@BUILTIN", "BUILTIN\\Abc", NULL };
    size_t c;

    for (c = 0; names[c] != NULL; c++) {
        sss_nss_test_ctx->tctx->done = false;

        will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
        will_return(__wrap_sss_packet_get_body, names[c]);
        will_return(__wrap_sss_packet_get_body, 0);
        will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYNAME);
        will_return(test_sss_nss_well_known_sid_check, NULL);

        set_cmd_cb(test_sss_nss_well_known_sid_check);
        ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYNAME,
                              sss_nss_test_ctx->sss_nss_cmds);
        assert_int_equal(ret, EOK);

        /* Wait until the test finishes with EOK */
        ret = test_ev_loop(sss_nss_test_ctx->tctx);
        assert_int_equal(ret, EOK);
    }
}

void test_sss_nss_well_known_getsidbyname_special(void **state)
{
    errno_t ret;
    const char *names[] = { "CREATOR OWNER@CREATOR AUTHORITY",
                            "CREATOR AUTHORITY\\CREATOR OWNER", NULL };
    size_t c;

    for (c = 0; names[c] != NULL; c++) {
        sss_nss_test_ctx->tctx->done = false;

        will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
        will_return(__wrap_sss_packet_get_body, names[c]);
        will_return(__wrap_sss_packet_get_body, 0);
        will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYNAME);
        will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
        will_return(test_sss_nss_well_known_sid_check, "S-1-3-0");

        set_cmd_cb(test_sss_nss_well_known_sid_check);
        ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYNAME,
                              sss_nss_test_ctx->sss_nss_cmds);
        assert_int_equal(ret, EOK);

        /* Wait until the test finishes with EOK */
        ret = test_ev_loop(sss_nss_test_ctx->tctx);
        assert_int_equal(ret, EOK);
    }
}

static int test_sss_nss_getorigbyname_check(uint32_t status, uint8_t *body,
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
    assert_string_equal(s, SYSDB_UPN);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "testuserorig@upndomain.test");
    rp += strlen(s) + 1;
    assert_int_equal(rp, blen);

    return EOK;
}

struct passwd orig_name = {
    .pw_name = discard_const("testuserorig"),
    .pw_uid = 1234,
    .pw_gid = 5678,
    .pw_dir = discard_const("/home/testuserorig"),
    .pw_gecos = discard_const("test user"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

void test_sss_nss_getorigbyname(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *test_upn = "testuserorig@upndomain.test";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, "S-1-2-3-4");
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, ORIGINALAD_PREFIX SYSDB_NAME,
                                 "orig_name");
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_uint32(attrs, ORIGINALAD_PREFIX SYSDB_UIDNUM, 1234);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, test_upn);
    assert_int_equal(ret, EOK);

    /* Prime the cache with a valid user */
    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &orig_name, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testuserorig");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETORIGBYNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getorigbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETORIGBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Also test looking up the same stuff with UPN */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_upn(test_upn);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETORIGBYNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getorigbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETORIGBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_sss_nss_getorigbyname_extra_check(uint32_t status, uint8_t *body,
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

struct passwd orig_extra = {
    .pw_name = discard_const("testuserorigextra"),
    .pw_uid = 2345,
    .pw_gid = 6789,
    .pw_dir = discard_const("/home/testuserorigextra"),
    .pw_gecos = discard_const("test user"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

void test_sss_nss_getorigbyname_extra_attrs(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
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

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &orig_extra, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testuserorigextra");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETORIGBYNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getorigbyname_extra_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETORIGBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int test_sss_nss_getorigbyname_multi_check(uint32_t status, uint8_t *body,
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

struct passwd orig_multi = {
    .pw_name = discard_const("testuserorigmulti"),
    .pw_uid = 3456,
    .pw_gid = 7890,
    .pw_dir = discard_const("/home/testuserorigmulti"),
    .pw_gecos = discard_const("test user"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

void test_sss_nss_getorigbyname_multi_value_attrs(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
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

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &orig_multi, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testuserorigmulti");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETORIGBYNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getorigbyname_multi_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETORIGBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

struct passwd orig_user_dup = {
    .pw_name = discard_const("testdup"),
    .pw_uid = 3478,
    .pw_gid = 3478,
    .pw_dir = discard_const("/home/testdup"),
    .pw_gecos = discard_const("test dup"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

struct group orig_group_dup = {
    .gr_gid = 3478,
    .gr_name = discard_const("testdup"),
    .gr_passwd = discard_const("*"),
    .gr_mem = NULL,
};

static int test_sss_nss_getorigbyusername_check(uint32_t status, uint8_t *body,
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
    assert_int_equal(rp, blen);

    return EOK;
}

static int test_sss_nss_getorigbygroupname_check(uint32_t status, uint8_t *body,
                                             size_t blen)
{
    const char *s;
    enum sss_id_type id_type;
    size_t rp = 2 * sizeof(uint32_t);

    assert_int_equal(status, EOK);

    SAFEALIGN_COPY_UINT32(&id_type, body+rp, &rp);
    assert_int_equal(id_type, SSS_ID_TYPE_GID);

    /* Sequence of null terminated strings */
    s = (char *) body+rp;
    assert_string_equal(s, SYSDB_SID_STR);
    rp += strlen(s) + 1;
    assert_true(rp < blen);

    s = (char *) body+rp;
    assert_string_equal(s, "S-1-2-3-5");
    rp += strlen(s) + 1;
    assert_int_equal(rp, blen);

    return EOK;
}

static void test_sss_nss_getorigbyname_dup_add(void)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, "S-1-2-3-4");
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, ORIGINALAD_PREFIX SYSDB_NAME,
                                 "orig_name");
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &orig_user_dup, attrs, 0);
    assert_int_equal(ret, EOK);
    talloc_free(attrs);

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, "S-1-2-3-5");
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &orig_group_dup, attrs, 0);
    assert_int_equal(ret, EOK);
    talloc_free(attrs);
}


static int test_sss_nss_EINVAL_check(uint32_t status, uint8_t *body, size_t blen);
/* test_sss_nss_getorigbyname_dup is expected to fail because there are a user and
 * a group with the same name in the cache. */
void test_sss_nss_getorigbyname_dup(void **state)
{
    errno_t ret;

    test_sss_nss_getorigbyname_dup_add();

    mock_input_user_or_group("testdup");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETORIGBYNAME);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETORIGBYNAME);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_EINVAL_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETORIGBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getorigbyusername(void **state)
{
    errno_t ret;

    test_sss_nss_getorigbyname_dup_add();

    mock_input_user_or_group("testdup");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETORIGBYUSERNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getorigbyusername_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETORIGBYUSERNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getorigbygroupname(void **state)
{
    errno_t ret;

    test_sss_nss_getorigbyname_dup_add();

    mock_input_user_or_group("testdup");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETORIGBYGROUPNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getorigbygroupname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETORIGBYGROUPNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

struct passwd upn_user = {
    .pw_name = discard_const("upnuser"),
    .pw_uid = 34567,
    .pw_gid = 45678,
    .pw_dir = discard_const("/home/testuserorig"),
    .pw_gecos = discard_const("test user"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

static int test_sss_nss_getpwnam_upn_check(uint32_t status,
                                       uint8_t *body,
                                       size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_users_equal(&pwd, &upn_user);
    return EOK;
}

void test_sss_nss_getpwnam_upn(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, "upnuser@upndomain.test");
    assert_int_equal(ret, EOK);

    /* Prime the cache with a valid user */
    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &upn_user, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_upn("upnuser@upndomain.test");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getpwnam_upn_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getpwnam_upn_same_domain(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, "upnuser_upn@" TEST_DOM_NAME);
    assert_int_equal(ret, EOK);

    /* Prime the cache with a valid user */
    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &upn_user, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("upnuser_upn@" TEST_DOM_NAME);
    mock_account_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getpwnam_upn_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test that searching for a nonexistent user yields ENOENT.
 * Account callback will be called
 */
void test_sss_nss_getpwnam_upn_neg(void **state)
{
    errno_t ret;

    mock_input_upn("nosuchupnuser@upndomain.test");
    mock_account_recv_simple();

    assert_int_equal(sss_nss_test_ctx->ncache_hits, 0);

    set_cmd_cb(NULL);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_int_equal(sss_nss_test_ctx->ncache_hits, 0);

    /* Test that subsequent search for a nonexistent user yields
     * ENOENT and Account callback is not called, on the other hand
     * the ncache functions will be called
     */
    sss_nss_test_ctx->tctx->done = false;
    sss_nss_test_ctx->ncache_hits = 0;

    mock_input_upn("nosuchupnuser@upndomain.test");
    set_cmd_cb(NULL);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    /* Negative cache was hit this time */
    assert_int_equal(sss_nss_test_ctx->ncache_hits, 1);
}

static int test_sss_nss_initgr_check(uint32_t status, uint8_t *body, size_t blen)
{
    gid_t expected_gids[] = { 3211, 3212 };

    assert_int_equal(status, EOK);
    check_initgr_packet(body, blen, expected_gids, N_ELEMENTS(expected_gids));
    return EOK;
}

struct passwd testinitgr_usr = {
    .pw_name = discard_const("testinitgr"),
    .pw_uid = 321,
    .pw_gid = 654,
    .pw_dir = discard_const("/home/testinitgr"),
    .pw_gecos = discard_const("test initgroups"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

struct group testinitgr_gr1 = {
    .gr_gid = 3211,
    .gr_name = discard_const("testinitgr_gr1"),
    .gr_passwd = discard_const("*"),
    .gr_mem = NULL,
};

struct group testinitgr_gr2 = {
    .gr_gid = 3212,
    .gr_name = discard_const("testinitgr_gr2"),
    .gr_passwd = discard_const("*"),
    .gr_mem = NULL,
};

void test_sss_nss_initgroups(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE,
                                 time(NULL) + 300);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, "upninitgr@upndomain.test");
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &testinitgr_usr, attrs, 0);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &testinitgr_gr1, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &testinitgr_gr2, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_group_member(sss_nss_test_ctx,
                             testinitgr_gr1.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             testinitgr_usr.pw_name,
                             sss_nss_test_ctx->tctx->dom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    ret = store_group_member(sss_nss_test_ctx,
                             testinitgr_gr2.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             testinitgr_usr.pw_name,
                             sss_nss_test_ctx->tctx->dom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testinitgr");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_initgr_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_INITGR,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test that searching for a nonexistent user yields ENOENT.
 * Account callback will be called
 */
void test_initgr_neg_by_name(const char *name, bool is_upn)
{
    errno_t ret;

    if (is_upn) {
        mock_input_upn(name);
    } else {
        mock_input_user_or_group(name);
    }
    mock_account_recv_simple();

    assert_int_equal(sss_nss_test_ctx->ncache_hits, 0);

    set_cmd_cb(NULL);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_INITGR,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_int_equal(sss_nss_test_ctx->ncache_hits, 0);

    /* Test that subsequent search for a nonexistent user yields
     * ENOENT and Account callback is not called, on the other hand
     * the ncache functions will be called
     */
    sss_nss_test_ctx->tctx->done = false;
    sss_nss_test_ctx->ncache_hits = 0;

    if (is_upn) {
        mock_input_upn(name);
    } else {
        mock_input_user_or_group(name);
    }
    set_cmd_cb(NULL);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_INITGR,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    /* Negative cache was hit this time */
    assert_int_equal(sss_nss_test_ctx->ncache_hits, 1);
}

void test_sss_nss_initgr_neg(void **state)
{
    test_initgr_neg_by_name("testinitgr_neg", false);
}

struct passwd testinitgr_srch_usr = {
    .pw_name = discard_const("testinitgr_srch"),
    .pw_uid = 421,
    .pw_gid = 654,
    .pw_dir = discard_const("/home/testinitgr_srch"),
    .pw_gecos = discard_const("test initgroups"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

struct group testinitgr_srch_gr1 = {
    .gr_gid = 4211,
    .gr_name = discard_const("testinitgr_srch_gr1"),
    .gr_passwd = discard_const("*"),
    .gr_mem = NULL,
};

struct group testinitgr_srch_gr2 = {
    .gr_gid = 4212,
    .gr_name = discard_const("testinitgr_srch_gr2"),
    .gr_passwd = discard_const("*"),
    .gr_mem = NULL,
};

static int test_sss_nss_initgr_search_acct_cb(void *pvt)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE,
                                 time(NULL) + 300);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &testinitgr_srch_usr, attrs, 0);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &testinitgr_srch_gr1, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &testinitgr_srch_gr2, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_group_member(sss_nss_test_ctx,
                             testinitgr_srch_gr1.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             testinitgr_srch_usr.pw_name,
                             sss_nss_test_ctx->tctx->dom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    ret = store_group_member(sss_nss_test_ctx,
                             testinitgr_srch_gr2.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             testinitgr_srch_usr.pw_name,
                             sss_nss_test_ctx->tctx->dom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    return EOK;
}

static int test_sss_nss_initgr_search_check(uint32_t status,
                                        uint8_t *body, size_t blen)
{
    gid_t expected_gids[] = { 4211, 4212 };

    assert_int_equal(status, EOK);
    check_initgr_packet(body, blen, expected_gids, N_ELEMENTS(expected_gids));
    return EOK;
}

void test_sss_nss_initgr_search(void **state)
{
    errno_t ret;
    struct ldb_result *res;

    mock_input_user_or_group("testinitgr_srch");
    mock_account_recv(0, 0, NULL, test_sss_nss_initgr_search_acct_cb, sss_nss_test_ctx);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    set_cmd_cb(test_sss_nss_initgr_search_check);

    ret = get_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                   "testinitgr_srch", &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);

    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_INITGR,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* test_sss_nss_getpwnam_search_check will check the user attributes */
    ret = get_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                   "testinitgr_srch", &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
}

struct passwd testinitgr_update_usr = {
    .pw_name = discard_const("testinitgr_update"),
    .pw_uid = 521,
    .pw_gid = 654,
    .pw_dir = discard_const("/home/testinitgr_update"),
    .pw_gecos = discard_const("test initgroups"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

struct group testinitgr_update_gr1 = {
    .gr_gid = 5211,
    .gr_name = discard_const("testinitgr_update_gr1"),
    .gr_passwd = discard_const("*"),
    .gr_mem = NULL,
};

struct group testinitgr_update_gr2 = {
    .gr_gid = 5212,
    .gr_name = discard_const("testinitgr_update_gr2"),
    .gr_passwd = discard_const("*"),
    .gr_mem = NULL,
};

static int test_sss_nss_initgr_update_acct_cb(void *pvt)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE,
                                 time(NULL) + 300);
    assert_int_equal(ret, EOK);

    ret = set_user_attr(sss_nss_test_ctx,
                        sss_nss_test_ctx->tctx->dom,
                        &testinitgr_update_usr,
                        attrs);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &testinitgr_update_gr2, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_group_member(sss_nss_test_ctx,
                             testinitgr_update_gr2.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             testinitgr_update_usr.pw_name,
                             sss_nss_test_ctx->tctx->dom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    return EOK;
}

static int test_sss_nss_initgr_update_check(uint32_t status, uint8_t *body, size_t blen)
{
    gid_t expected_gids[] = { 5211, 5212 };

    assert_int_equal(status, EOK);
    check_initgr_packet(body, blen, expected_gids, N_ELEMENTS(expected_gids));
    return EOK;
}

void test_sss_nss_initgr_update(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE,
                                 time(NULL) - 1);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &testinitgr_update_usr, attrs, 0);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &testinitgr_update_gr1, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_group_member(sss_nss_test_ctx,
                             testinitgr_update_gr1.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             testinitgr_update_usr.pw_name,
                             sss_nss_test_ctx->tctx->dom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testinitgr_update");
    mock_account_recv(0, 0, NULL, test_sss_nss_initgr_update_acct_cb, sss_nss_test_ctx);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    set_cmd_cb(test_sss_nss_initgr_update_check);

    /* Query for that user, call a callback when command finishes */
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_INITGR,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

struct passwd testinitgr_2attr_usr = {
    .pw_name = discard_const("testinitgr_2attr"),
    .pw_uid = 521,
    .pw_gid = 654,
    .pw_dir = discard_const("/home/testinitgr_2attr"),
    .pw_gecos = discard_const("test initgroups"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

struct group testinitgr_2attr_gr1 = {
    .gr_gid = 5221,
    .gr_name = discard_const("testinitgr_2attr_gr11"),
    .gr_passwd = discard_const("*"),
    .gr_mem = NULL,
};

struct group testinitgr_2attr_gr2 = {
    .gr_gid = 5222,
    .gr_name = discard_const("testinitgr_2attr_gr12"),
    .gr_passwd = discard_const("*"),
    .gr_mem = NULL,
};

static int test_sss_nss_initgr_update_acct_2expire_attributes_cb(void *pvt)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE,
                                 time(NULL) + 300);
    assert_int_equal(ret, EOK);

    ret = set_user_attr(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                        &testinitgr_2attr_usr, attrs);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &testinitgr_2attr_gr2, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_group_member(sss_nss_test_ctx,
                             testinitgr_2attr_gr2.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             testinitgr_2attr_usr.pw_name,
                             sss_nss_test_ctx->tctx->dom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    return EOK;
}

static int test_sss_nss_initgr_update_2expire_attributes_check(uint32_t status,
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
void test_sss_nss_initgr_update_two_expire_attributes(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE,
                                 0);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 time(NULL) + 100);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &testinitgr_2attr_usr, attrs, 0);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &testinitgr_2attr_gr1, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_group_member(sss_nss_test_ctx,
                             testinitgr_2attr_gr1.gr_name,
                             sss_nss_test_ctx->tctx->dom,
                             testinitgr_2attr_usr.pw_name,
                             sss_nss_test_ctx->tctx->dom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testinitgr_2attr");
    mock_account_recv(0, 0, NULL,
                      test_sss_nss_initgr_update_acct_2expire_attributes_cb,
                      sss_nss_test_ctx);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    set_cmd_cb(test_sss_nss_initgr_update_2expire_attributes_check);

    /* Query for that user, call a callback when command finishes */
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_INITGR,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_initgroups_upn(void **state)
{
    errno_t ret;

    mock_input_upn("upninitgr@upndomain.test");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR);
    will_return_always(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_initgr_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_INITGR,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test that searching for a nonexistent user yields ENOENT.
 * Account callback will be called
 */
void test_sss_nss_initgr_neg_upn(void **state)
{
    test_initgr_neg_by_name("upninitgr_neg@upndomain.test", true);
}

static int sss_nss_test_setup(void **state)
{
    struct sss_test_conf_param params[] = {
        { "enumerate", "false" },
        { NULL, NULL },             /* Sentinel */
    };

    test_sss_nss_setup(params, state);
    return 0;
}

static int sss_nss_fqdn_test_setup(void **state)
{
    struct sss_test_conf_param params[] = {
        { "enumerate", "false" },
        { "full_name_format", "%1$s@%2$s" },
        { NULL, NULL },             /* Sentinel */
    };

    test_sss_nss_setup(params, state);
    return 0;
}

static int sss_nss_test_setup_extra_attr(void **state)
{
    struct sss_test_conf_param params[] = {
        { "enumerate", "false" },
        { NULL, NULL },             /* Sentinel */
    };

    test_sss_nss_setup(params, state);

    sss_nss_test_ctx->nctx->extra_attributes = global_extra_attrs;
    sss_nss_test_ctx->nctx->full_attribute_list = global_full_attrs;

    return 0;
}

static int sss_nss_subdom_test_setup_common(void **state, bool nonfqnames)
{
    const char *const testdom[4] = { TEST_SUBDOM_NAME, "TEST.SUB", "test", "S-3" };
    struct sss_domain_info *dom;

    struct sss_domain_info *subdomain;
    errno_t ret;

    sss_nss_test_setup(state);

    subdomain = new_subdomain(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                              testdom[0], testdom[1], testdom[2], testdom[0],
                              testdom[3], false, false, NULL, NULL, 0,
                              IPA_TRUST_UNKNOWN, sss_nss_test_ctx->tctx->confdb,
                              true);
    assert_non_null(subdomain);

    ret = sysdb_subdomain_store(sss_nss_test_ctx->tctx->sysdb,
                                testdom[0], testdom[1], testdom[2], testdom[0],
                                testdom[3], MPG_DISABLED, false, NULL, 0,
                                IPA_TRUST_UNKNOWN, NULL);
    assert_int_equal(ret, EOK);

    ret = sysdb_update_subdomains(sss_nss_test_ctx->tctx->dom,
                                  sss_nss_test_ctx->tctx->confdb);
    assert_int_equal(ret, EOK);

    if (nonfqnames) {
        for (dom = sss_nss_test_ctx->rctx->domains;
             dom != NULL;
             dom = get_next_domain(dom, SSS_GND_ALL_DOMAINS)) {
            if (strcmp(dom->name, subdomain->name) == 0) {
                dom->fqnames = false;
                break;
            }
        }
    }

    ret = sss_resp_populate_cr_domains(sss_nss_test_ctx->rctx);
    assert_int_equal(ret, EOK);
    assert_non_null(sss_nss_test_ctx->rctx->cr_domains);

    sss_nss_test_ctx->subdom = sss_nss_test_ctx->tctx->dom->subdomains;

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->subdom,
                      &testsubdomgroup, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->subdom,
                     &submember1, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->subdom,
                     &submember2, NULL, 0);
    assert_int_equal(ret, EOK);

    ret = store_group_member(sss_nss_test_ctx,
                             testsubdomgroup.gr_name,
                             sss_nss_test_ctx->subdom,
                             submember1.pw_name,
                             sss_nss_test_ctx->subdom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    ret = store_group_member(sss_nss_test_ctx,
                             testsubdomgroup.gr_name,
                             sss_nss_test_ctx->subdom,
                             submember2.pw_name,
                             sss_nss_test_ctx->subdom,
                             SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    return 0;

}

static int sss_nss_subdom_test_setup(void **state)
{
    return sss_nss_subdom_test_setup_common(state, false);
}

static int sss_nss_subdom_test_setup_nonfqnames(void **state)
{
    return sss_nss_subdom_test_setup_common(state, true);
}

static int sss_nss_fqdn_fancy_test_setup(void **state)
{
    struct sss_test_conf_param params[] = {
        { "enumerate", "false" },
        { "full_name_format", "%1$s@@@@@%2$s" },
        { NULL, NULL },             /* Sentinel */
    };

    test_sss_nss_setup(params, state);
    return 0;
}

static int sss_nss_test_teardown(void **state)
{
    talloc_free(sss_nss_test_ctx);
    return 0;
}

static int sss_nss_subdom_test_teardown(void **state)
{
    errno_t ret;

    ret = remove_group_member(sss_nss_test_ctx,
                              testsubdomgroup.gr_name,
                              sss_nss_test_ctx->subdom,
                              submember2.pw_name,
                              sss_nss_test_ctx->subdom,
                              SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    ret = remove_group_member(sss_nss_test_ctx,
                              testsubdomgroup.gr_name,
                              sss_nss_test_ctx->subdom,
                              submember1.pw_name,
                              sss_nss_test_ctx->subdom,
                              SYSDB_MEMBER_USER);
    assert_int_equal(ret, EOK);

    ret = delete_user(sss_nss_test_ctx, sss_nss_test_ctx->subdom, &submember2);
    assert_int_equal(ret, EOK);

    ret = delete_user(sss_nss_test_ctx, sss_nss_test_ctx->subdom, &submember1);
    assert_int_equal(ret, EOK);

    ret = delete_group(sss_nss_test_ctx, sss_nss_test_ctx->subdom, &testsubdomgroup);
    assert_int_equal(ret, EOK);

    return sss_nss_test_teardown(state);
}

struct passwd testbysid = {
    .pw_name = discard_const("testsiduser"),
    .pw_uid = 12345,
    .pw_gid = 6890,
    .pw_dir = discard_const("/home/testsiduser"),
    .pw_gecos = discard_const("test bysid lookup"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

static int test_sss_nss_getnamebysid_check(uint32_t status, uint8_t *body, size_t blen)
{
    size_t rp = 2 * sizeof(uint32_t); /* num_results and reserved */
    uint32_t id_type;
    const char *name;

    assert_int_equal(status, EOK);

    SAFEALIGN_COPY_UINT32(&id_type, body+rp, &rp);
    assert_int_equal(id_type, SSS_ID_TYPE_UID);

    name = (const char *) body + rp;
    assert_string_equal(name, testbysid.pw_name);

    return EOK;
}

static void test_sss_nss_getnamebysid(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    char *user_sid;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    user_sid = talloc_asprintf(attrs, "%s-500",
                               sss_nss_test_ctx->tctx->dom->domain_id);
    assert_non_null(user_sid);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, user_sid);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &testbysid, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_sid(user_sid);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNAMEBYSID);
    mock_fill_bysid();

    /* Query for that user, call a callback when command finishes */
    /* Should go straight to back end, without contacting DP */
    set_cmd_cb(test_sss_nss_getnamebysid_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test that searching for a nonexistent user yields ENOENT.
 * Account callback will be called
 */
void test_sss_nss_getnamebysid_neg(void **state)
{
    errno_t ret;
    char *user_sid;

    user_sid = talloc_asprintf(sss_nss_test_ctx, "%s-499",
                               sss_nss_test_ctx->tctx->dom->domain_id);
    assert_non_null(user_sid);

    mock_input_sid(user_sid);
    mock_account_recv_simple();

    assert_int_equal(sss_nss_test_ctx->ncache_hits, 0);

    set_cmd_cb(NULL);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_int_equal(sss_nss_test_ctx->ncache_hits, 0);

    /* Test that subsequent search for a nonexistent user yields
     * ENOENT and Account callback is not called, on the other hand
     * the ncache functions will be called
     */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_sid(user_sid);
    set_cmd_cb(NULL);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    /* Negative cache was hit this time */
    assert_int_equal(sss_nss_test_ctx->ncache_hits, 1);
}

struct passwd testbysid_update = {
    .pw_name = discard_const("testsidbyname_update"),
    .pw_uid = 123456,
    .pw_gid = 789,
    .pw_dir = discard_const("/home/testsidbyname_update"),
    .pw_gecos = discard_const("test bysid lookup"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

static int test_sss_nss_getnamebysid_update_check(uint32_t status,
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

static int test_sss_nss_getnamebysid_update_acct_cb(void *pvt)
{
    errno_t ret;
    struct sss_nss_test_ctx *ctx = talloc_get_type(pvt, struct sss_nss_test_ctx);

    testbysid_update.pw_shell = discard_const("/bin/ksh");
    ret = store_user(ctx, sss_nss_test_ctx->tctx->dom,
                     &testbysid_update, NULL, 0);
    assert_int_equal(ret, EOK);

    return EOK;
}

void test_sss_nss_getnamebysid_update(void **state)
{
    errno_t ret;
    struct ldb_result *res;
    struct sysdb_attrs *attrs;
    const char *shell;
    char *user_sid;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    user_sid = talloc_asprintf(attrs, "%s-123456",
                               sss_nss_test_ctx->tctx->dom->domain_id);
    assert_non_null(user_sid);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, user_sid);
    assert_int_equal(ret, EOK);

    /* Prime the cache with a valid but expired user */
    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &testbysid_update, attrs, 1);
    assert_int_equal(ret, EOK);

    /* Mock client input */
    mock_input_sid(user_sid);
    /* Mock client command */
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNAMEBYSID);
    /* Call this function when user is updated by the mock DP request */
    mock_account_recv(0, 0, NULL, test_sss_nss_getnamebysid_update_acct_cb,
                      sss_nss_test_ctx);
    /* Call this function to check what the responder returned to the client */
    set_cmd_cb(test_sss_nss_getnamebysid_update_check);
    /* Mock output buffer */
    mock_fill_bysid();

    /* Fire the command */
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNAMEBYSID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Check the user was updated in the cache */
    ret = get_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                   testbysid_update.pw_name, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);

    shell = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, NULL);
    assert_string_equal(shell, "/bin/ksh");
}

struct passwd testbycert = {
    .pw_name = discard_const("testcertuser"),
    .pw_uid = 23456,
    .pw_gid = 6890,
    .pw_dir = discard_const("/home/testcertuser"),
    .pw_gecos = discard_const("test cert user"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

struct passwd testbycert2 = {
    .pw_name = discard_const("testcertuser2"),
    .pw_uid = 23457,
    .pw_gid = 6890,
    .pw_dir = discard_const("/home/testcertuser2"),
    .pw_gecos = discard_const("test cert user2"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

#define TEST_TOKEN_CERT \
"MIIECTCCAvGgAwIBAgIBCDANBgkqhkiG9w0BAQsFADA0MRIwEAYDVQQKDAlJUEEu" \
"REVWRUwxHjAcBgNVBAMMFUNlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xNTA2MjMx" \
"NjMyMDdaFw0xNzA2MjMxNjMyMDdaMDIxEjAQBgNVBAoMCUlQQS5ERVZFTDEcMBoG" \
"A1UEAwwTaXBhLWRldmVsLmlwYS5kZXZlbDCCASIwDQYJKoZIhvcNAQEBBQADggEP" \
"ADCCAQoCggEBALXUq56VlY+Z0aWLLpFAjFfbElPBXGQsbZb85J3cGyPjaMHC9wS+" \
"wjB6Ve4HmQyPLx8hbINdDmbawMHYQvTScLYfsqLtj0Lqw20sUUmedk+Es5Oh9VHo" \
"nd8MavYx25Du2u+T0iSgNIDikXguiwCmtAj8VC49ebbgITcjJGzMmiiuJkV3o93Y" \
"vvYF0VjLGDQbQWOy7IxzYJeNVJnZWKo67CHdok6qOrm9rxQt81rzwV/mGLbCMUbr" \
"+N4M8URtd7EmzaYZQmNm//s2owFrCYMxpLiURPj+URZVuB72504/Ix7X0HCbA/AV" \
"26J27fPY5nc8DMwfhUDCbTqPH/JEjd3mvY8CAwEAAaOCASYwggEiMB8GA1UdIwQY" \
"MBaAFJOq+KAQmPEnNp8Wok23eGTdE7aDMDsGCCsGAQUFBwEBBC8wLTArBggrBgEF" \
"BQcwAYYfaHR0cDovL2lwYS1jYS5pcGEuZGV2ZWwvY2Evb2NzcDAOBgNVHQ8BAf8E" \
"BAMCBPAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMHQGA1UdHwRtMGsw" \
"aaAxoC+GLWh0dHA6Ly9pcGEtY2EuaXBhLmRldmVsL2lwYS9jcmwvTWFzdGVyQ1JM" \
"LmJpbqI0pDIwMDEOMAwGA1UECgwFaXBhY2ExHjAcBgNVBAMMFUNlcnRpZmljYXRl" \
"IEF1dGhvcml0eTAdBgNVHQ4EFgQUFaDNd5a53QGpaw5m63hnwXicMQ8wDQYJKoZI" \
"hvcNAQELBQADggEBADH7Nj00qqGhGJeXJQAsepqSskz/wooqXh8vgVyb8SS4N0/c" \
"0aQtVmY81xamlXE12ZFpwDX43d+EufBkwCUKFX/+8JFDd2doAyeJxv1xM22kKRpc" \
"AqITPgMsa9ToGMWxjbVpc/X/5YfZixWPF0/eZUTotBj9oaR039UrhGfyN7OguF/G" \
"rzmxtB5y4ZrMpcD/Oe90mkd9HY7sA/fB8OWOUgeRfQoh97HNS0UiDWsPtfxmjQG5" \
"zotpoBIZmdH+ipYsu58HohHVlM9Wi5H4QmiiXl+Soldkq7eXYlafcmT7wv8+cKwz" \
"Nz0Tm3+eYpFqRo3skr6QzXi525Jkg3r6r+kkhxU="

static int test_sss_nss_getnamebycert_check(uint32_t status, uint8_t *body, size_t blen)
{
    size_t rp = 2 * sizeof(uint32_t); /* num_results and reserved */
    uint32_t id_type;
    const char *name;

    assert_int_equal(status, EOK);

    SAFEALIGN_COPY_UINT32(&id_type, body + rp, &rp);
    assert_int_equal(id_type, SSS_ID_TYPE_UID);

    name = (const char *)body + rp;
    assert_string_equal(name, testbycert.pw_name);

    return EOK;
}

static int test_sss_nss_getlistbycert_check_exp(uint32_t status, uint8_t *body,
                                            size_t blen, size_t exp)
{
    size_t rp = 0;
    uint32_t id_type;
    uint32_t num;
    uint32_t reserved;
    const char *name;
    int found = 0;
    const char *fq_name1 = "testcertuser@"TEST_DOM_NAME ;
    const char *fq_name2 = "testcertuser2@"TEST_SUBDOM_NAME;

    assert_int_equal(status, EOK);

    /* num_results and reserved */
    SAFEALIGN_COPY_UINT32(&num, body + rp, &rp);
    assert_int_equal(num, exp);
    SAFEALIGN_COPY_UINT32(&reserved, body + rp, &rp);
    assert_int_equal(reserved, 0);

    SAFEALIGN_COPY_UINT32(&id_type, body + rp, &rp);
    assert_int_equal(id_type, SSS_ID_TYPE_UID);

    name = (const char *)body + rp;
    if (num == 1) {
        assert_string_equal(name, fq_name1);
        return EOK;
    }

    rp += strlen(name) + 1;
    if (strcmp(name, fq_name1) == 0) {
        found = 1;
    } else if (strcmp(name, fq_name2) == 0) {
        found = 2;
    }
    assert_in_range(found, 1, 2);

    SAFEALIGN_COPY_UINT32(&id_type, body + rp, &rp);
    assert_int_equal(id_type, SSS_ID_TYPE_UID);

    name = (const char *)body + rp;
    if (found == 1) {
        assert_string_equal(name, fq_name2);
    } else {
        assert_string_equal(name, fq_name1);
    }


    return EOK;
}

static int test_sss_nss_getlistbycert_check_one(uint32_t status, uint8_t *body,
                                            size_t blen)
{
    return test_sss_nss_getlistbycert_check_exp(status, body, blen, 1);
}

static int test_sss_nss_getlistbycert_check_two(uint32_t status, uint8_t *body,
                                            size_t blen)
{
    return test_sss_nss_getlistbycert_check_exp(status, body, blen, 2);
}

static void test_sss_nss_getnamebycert(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    unsigned char *der = NULL;
    size_t der_size;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    der = sss_base64_decode(sss_nss_test_ctx, TEST_TOKEN_CERT, &der_size);
    assert_non_null(der);

    ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_MAPPED_CERT, der, der_size);
    talloc_free(der);
    assert_int_equal(ret, EOK);

    /* Prime the cache with a valid user */
    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &testbycert, attrs, 0);
    assert_int_equal(ret, EOK);
    talloc_free(attrs);

    mock_input_cert(TEST_TOKEN_CERT);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNAMEBYCERT);
    mock_fill_bysid();

    /* Query for that user, call a callback when command finishes */
    /* Should go straight to back end, without contacting DP */
    set_cmd_cb(test_sss_nss_getnamebycert_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNAMEBYCERT,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getnamebycert_neg(void **state)
{
    errno_t ret;

    mock_input_cert(TEST_TOKEN_CERT);
    mock_account_recv_simple();

    assert_int_equal(sss_nss_test_ctx->ncache_hits, 0);

    set_cmd_cb(NULL);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNAMEBYCERT,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_int_equal(sss_nss_test_ctx->ncache_hits, 0);

    /* Test that subsequent search for a nonexistent user yields
     * ENOENT and Account callback is not called, on the other hand
     * the ncache functions will be called
     */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_cert(TEST_TOKEN_CERT);
    set_cmd_cb(NULL);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNAMEBYCERT,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    /* Negative cache was hit this time */
    assert_int_equal(sss_nss_test_ctx->ncache_hits, 1);
}

static void test_sss_nss_getlistbycert(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    unsigned char *der = NULL;
    size_t der_size;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    der = sss_base64_decode(sss_nss_test_ctx, TEST_TOKEN_CERT, &der_size);
    assert_non_null(der);

    ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_MAPPED_CERT, der, der_size);
    talloc_free(der);
    assert_int_equal(ret, EOK);

    /* Prime the cache with a valid user */
    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &testbycert, attrs, 0);
    assert_int_equal(ret, EOK);
    talloc_free(attrs);

    mock_input_cert(TEST_TOKEN_CERT);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETLISTBYCERT);
    mock_fill_bysid();

    /* Query for that user, call a callback when command finishes */
    /* Should go straight to back end, without contacting DP. */
    /* If there is only a single user mapped the result will look like the */
    /* result of getnamebycert. */
    set_cmd_cb(test_sss_nss_getlistbycert_check_one);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETLISTBYCERT,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static void test_sss_nss_getlistbycert_multi(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    unsigned char *der = NULL;
    size_t der_size;

    der = sss_base64_decode(sss_nss_test_ctx, TEST_TOKEN_CERT, &der_size);
    assert_non_null(der);

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_MAPPED_CERT, der, der_size);
    assert_int_equal(ret, EOK);

    /* Prime the cache with two valid user */
    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &testbycert, attrs, 0);
    assert_int_equal(ret, EOK);
    talloc_free(attrs);

    /* Looks like attrs is modified during store_user() makes sure we start
     * with fresh data. */
    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_mem(attrs, SYSDB_USER_MAPPED_CERT, der, der_size);
    talloc_free(der);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->subdom,
                     &testbycert2, attrs, 0);
    assert_int_equal(ret, EOK);
    talloc_free(attrs);

    mock_input_cert(TEST_TOKEN_CERT);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETLISTBYCERT);
    mock_fill_bysid();

    /* Query for that user, call a callback when command finishes */
    /* Should go straight to back end, without contacting DP */
    set_cmd_cb(test_sss_nss_getlistbycert_check_two);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETLISTBYCERT,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

struct passwd sid_user = {
    .pw_name = discard_const("testusersid"),
    .pw_uid = 1234,
    .pw_gid = 5678,
    .pw_dir = discard_const("/home/testusersid"),
    .pw_gecos = discard_const("test user"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

struct passwd sid_user_upg = {
    .pw_name = discard_const("testusersidupg"),
    .pw_uid = 5678,
    .pw_gid = 5678,
    .pw_dir = discard_const("/home/testusersidupg"),
    .pw_gecos = discard_const("test user upg"),
    .pw_shell = discard_const("/bin/sh"),
    .pw_passwd = discard_const("*"),
};

struct group sid_user_group = {
    .gr_name = discard_const("testusersidupg"),
    .gr_gid = 5678,
};

struct group sid_group = {
    .gr_name = discard_const("testgroupsid"),
    .gr_gid = 5555,
};

static int test_sss_nss_getsidbyname_check(uint32_t status,
                                       uint8_t *body,
                                       size_t blen)
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

        assert_int_equal(type, SSS_ID_TYPE_UID);
        assert_string_equal(name, expected_result);
    }

    return EOK;
}

static int test_sss_nss_getsidbygroupname_check(uint32_t status,
                                                uint8_t *body,
                                                size_t blen)
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

void test_sss_nss_getsidbyname(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testuser_sid = "S-1-2-3-4";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testuser_sid);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &sid_user, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testusersid");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    will_return(test_sss_nss_getsidbyname_check, testuser_sid);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getsidbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getsidbyname_ipa_upg(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testuser_sid = "S-1-2-3-4";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testuser_sid);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &sid_user_upg, attrs, 0);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &sid_user_group, NULL, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testusersid");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    will_return(test_sss_nss_getsidbyname_check, testuser_sid);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getsidbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getsidbyname_ipa_upg_manual(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testuser_sid = "S-1-2-3-4";
    const char *testgroup_sid = "S-1-2-3-5";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testuser_sid);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &sid_user_upg, attrs, 0);
    assert_int_equal(ret, EOK);

    talloc_free(attrs);
    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testgroup_sid);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &sid_user_group, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testusersid");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    will_return(test_sss_nss_getsidbyname_check, testuser_sid);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getsidbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getsidbyusername_user(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testuser_sid = "S-1-2-3-4";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testuser_sid);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &sid_user, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testusersid");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYUSERNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    will_return(test_sss_nss_getsidbyname_check, testuser_sid);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getsidbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYUSERNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getsidbyusername_group(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testgroup_sid = "S-1-2-3-4";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testgroup_sid);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &sid_group, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testgroupsid");
    mock_account_recv_simple();
    set_cmd_cb(NULL);

    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYUSERNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
}

void test_sss_nss_getsidbygroupname_group(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testgroup_sid = "S-1-2-3-4";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testgroup_sid);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &sid_group, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testgroupsid");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYGROUPNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    will_return(test_sss_nss_getsidbygroupname_check, testgroup_sid);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getsidbygroupname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYGROUPNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getsidbygroupname_user(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testuser_sid = "S-1-2-3-4";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testuser_sid);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &sid_user, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testusersid");
    mock_account_recv_simple();
    set_cmd_cb(NULL);

    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYGROUPNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
}

void test_sss_nss_getsidbyid(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testuser_sid = "S-1-2-3-4";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testuser_sid);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &sid_user, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_id(sss_nss_test_ctx, 1234);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYID);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    will_return(test_sss_nss_getsidbyname_check, testuser_sid);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getsidbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getsidbyuid(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testuser_sid = "S-1-2-3-4";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testuser_sid);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &sid_user, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_id(sss_nss_test_ctx, 1234);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYUID);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    will_return(test_sss_nss_getsidbyname_check, testuser_sid);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getsidbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYUID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getsidbygid_no_group(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testuser_sid = "S-1-2-3-4";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testuser_sid);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &sid_user, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_id(sss_nss_test_ctx, 1234);
    mock_account_recv_simple();
    set_cmd_cb(NULL);

    /* Query for that user, call a callback when command finishes */
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYGID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT (because there is no such
     * group) */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
}

static int test_sss_nss_getsidbyname_group_check(uint32_t status,
                                             uint8_t *body,
                                             size_t blen)
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

void test_sss_nss_getsidbyname_group(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testgroup_sid = "S-1-2-3-5";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testgroup_sid);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &sid_group, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group("testgroupsid");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    will_return(test_sss_nss_getsidbyname_group_check, testgroup_sid);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getsidbyname_group_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getsidbyid_group(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testgroup_sid = "S-1-2-3-5";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testgroup_sid);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &sid_group, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_id(sss_nss_test_ctx, 5555);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYID);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    will_return(test_sss_nss_getsidbyname_group_check, testgroup_sid);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getsidbyname_group_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getsidbygid_group(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testgroup_sid = "S-1-2-3-5";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testgroup_sid);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &sid_group, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_id(sss_nss_test_ctx, 5555);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYGID);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    will_return(test_sss_nss_getsidbyname_group_check, testgroup_sid);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getsidbyname_group_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYGID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getsidbyuid_no_user(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testgroup_sid = "S-1-2-3-5";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testgroup_sid);
    assert_int_equal(ret, EOK);

    ret = store_group(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                      &sid_group, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_id(sss_nss_test_ctx, 5555);
    mock_account_recv_simple();
    set_cmd_cb(NULL);

    /* Query for that user, call a callback when command finishes */
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYUID,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT (because there is no such
     * user) */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
}

void test_sss_nss_getsidbyupn(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;
    const char *testuser_sid = "S-1-2-3-4";
    const char *testuser_upn = "testusersid@upndomain.test";

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, testuser_sid);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, testuser_upn);
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &sid_user, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_upn(testuser_upn);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETSIDBYNAME);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    will_return(test_sss_nss_getsidbyname_check, testuser_sid);

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getsidbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getsidbyname_neg(void **state)
{
    errno_t ret;

    mock_input_user_or_group("testnosuchsid");
    mock_account_recv_simple();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(NULL);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETSIDBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT (because there is no such SID */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
}

static int test_sss_nss_EINVAL_check(uint32_t status, uint8_t *body, size_t blen)
{
    assert_int_equal(status, EINVAL);
    assert_int_equal(blen, 0);

    return EOK;
}

#define RESET_TCTX do { \
    sss_nss_test_ctx->tctx->done = false; \
    sss_nss_test_ctx->tctx->error = EIO; \
} while (0)

void test_sss_nss_getpwnam_ex(void **state)
{
    errno_t ret;

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &getpwnam_usr, NULL, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group_ex(true, "testuser", 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM_EX);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getpwnam_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use old input format, expect EINVAL */
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, "testuser");
    will_return(__wrap_sss_packet_get_body, 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM_EX);

    set_cmd_cb(test_sss_nss_EINVAL_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use unsupported flag combination, expect EINVAL */
    mock_input_user_or_group_ex(false, "testuser",
                                SSS_NSS_EX_FLAG_NO_CACHE
                                    |SSS_NSS_EX_FLAG_INVALIDATE_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM_EX);

    set_cmd_cb(test_sss_nss_EINVAL_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use flag SSS_NSS_EX_FLAG_NO_CACHE,
     * will cause a backend lookup -> mock_account_recv_simple() */
    mock_input_user_or_group_ex(true, "testuser", SSS_NSS_EX_FLAG_NO_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM_EX);
    mock_fill_user();
    mock_account_recv_simple();

    set_cmd_cb(test_sss_nss_getpwnam_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use flag SSS_NSS_EX_FLAG_INVALIDATE_CACHE */
    mock_input_user_or_group_ex(true, "testuser",
                                SSS_NSS_EX_FLAG_INVALIDATE_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM_EX);
    mock_fill_user();

    set_cmd_cb(test_sss_nss_getpwnam_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWNAM_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getpwuid_ex(void **state)
{
    errno_t ret;
    uint32_t id = 101;

    /* Prime the cache with a valid user */
    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &getpwuid_usr, NULL, 0);
    assert_int_equal(ret, EOK);

    mock_input_id_ex(sss_nss_test_ctx, id, 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWUID_EX);
    mock_fill_user();

    /* Query for that id, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getpwuid_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWUID_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use old input format, expect failure */
    mock_input_id(sss_nss_test_ctx, id);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWUID_EX);

    set_cmd_cb(test_sss_nss_EINVAL_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWUID_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use unsupported flag combination, expect EINVAL */
    mock_input_id_ex(sss_nss_test_ctx, id, SSS_NSS_EX_FLAG_NO_CACHE
                                            |SSS_NSS_EX_FLAG_INVALIDATE_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWUID_EX);

    set_cmd_cb(test_sss_nss_EINVAL_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWUID_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use flag SSS_NSS_EX_FLAG_NO_CACHE,
     * will cause a backend lookup -> mock_account_recv_simple() */
    mock_input_id_ex(sss_nss_test_ctx, id, SSS_NSS_EX_FLAG_NO_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWUID_EX);
    mock_fill_user();
    mock_account_recv_simple();

    set_cmd_cb(test_sss_nss_getpwuid_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWUID_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use flag SSS_NSS_EX_FLAG_INVALIDATE_CACHE */
    mock_input_id_ex(sss_nss_test_ctx, id, SSS_NSS_EX_FLAG_INVALIDATE_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWUID_EX);
    mock_fill_user();

    set_cmd_cb(test_sss_nss_getpwuid_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETPWUID_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getgrnam_ex_no_members(void **state)
{
    errno_t ret;

    /* Test group is still in the cache */

    mock_input_user_or_group_ex(true, getgrnam_no_members.gr_name, 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM_EX);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_no_members_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use old input format, expect failure */
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, "testgroup");
    will_return(__wrap_sss_packet_get_body, 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM_EX);

    set_cmd_cb(test_sss_nss_EINVAL_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use unsupported flag combination, expect EINVAL */
    mock_input_user_or_group_ex(false, getgrnam_no_members.gr_name,
                                SSS_NSS_EX_FLAG_NO_CACHE
                                    |SSS_NSS_EX_FLAG_INVALIDATE_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM_EX);

    set_cmd_cb(test_sss_nss_EINVAL_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use flag SSS_NSS_EX_FLAG_NO_CACHE,
     * will cause a backend lookup -> mock_account_recv_simple() */
    mock_input_user_or_group_ex(true, getgrnam_no_members.gr_name,
                                SSS_NSS_EX_FLAG_NO_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM_EX);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    mock_account_recv_simple();

    set_cmd_cb(test_sss_nss_getgrnam_no_members_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use flag SSS_NSS_EX_FLAG_INVALIDATE_CACHE */
    mock_input_user_or_group_ex(true, getgrnam_no_members.gr_name,
                                SSS_NSS_EX_FLAG_INVALIDATE_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRNAM_EX);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);

    set_cmd_cb(test_sss_nss_getgrnam_no_members_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRNAM_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getgrgid_ex_no_members(void **state)
{
    errno_t ret;

    /* Test group is still in the cache */

    mock_input_id_ex(sss_nss_test_ctx, getgrnam_no_members.gr_gid, 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRGID_EX);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    mock_account_recv_simple();

    /* Query for that group, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getgrnam_no_members_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRGID_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use old input format, expect failure */
    mock_input_id(sss_nss_test_ctx, getgrnam_no_members.gr_gid);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRGID_EX);

    set_cmd_cb(test_sss_nss_EINVAL_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRGID_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use unsupported flag combination, expect EINVAL */
    mock_input_id_ex(sss_nss_test_ctx, getgrnam_no_members.gr_gid,
                     SSS_NSS_EX_FLAG_NO_CACHE
                        |SSS_NSS_EX_FLAG_INVALIDATE_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRGID_EX);

    set_cmd_cb(test_sss_nss_EINVAL_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRGID_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use flag SSS_NSS_EX_FLAG_NO_CACHE,
     * will cause a backend lookup -> mock_account_recv_simple() */
    mock_input_id_ex(sss_nss_test_ctx, getgrnam_no_members.gr_gid,
                     SSS_NSS_EX_FLAG_NO_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETGRGID_EX);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    mock_account_recv_simple();

    set_cmd_cb(test_sss_nss_getgrnam_no_members_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRGID_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use flag SSS_NSS_EX_FLAG_INVALIDATE_CACHE */
    mock_input_id_ex(sss_nss_test_ctx, getgrnam_no_members.gr_gid,
                     SSS_NSS_EX_FLAG_INVALIDATE_CACHE);

    set_cmd_cb(test_sss_nss_getgrnam_no_members_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETGRGID_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_initgroups_ex(void **state)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(sss_nss_test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE,
                                 time(NULL) + 300);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, "upninitgr@upndomain.test");
    assert_int_equal(ret, EOK);

    ret = store_user(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                     &testinitgr_usr, attrs, 0);
    assert_int_equal(ret, EOK);

    mock_input_user_or_group_ex(true, "testinitgr", 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR_EX);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_initgr_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_INITGR_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use old input format, expect failure */
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, "testinitgr");
    will_return(__wrap_sss_packet_get_body, 0);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR_EX);

    set_cmd_cb(test_sss_nss_EINVAL_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_INITGR_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use unsupported flag combination, expect EINVAL */
    mock_input_user_or_group_ex(false, "testinitgr",
                                SSS_NSS_EX_FLAG_NO_CACHE
                                    |SSS_NSS_EX_FLAG_INVALIDATE_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR_EX);

    set_cmd_cb(test_sss_nss_EINVAL_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_INITGR_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use flag SSS_NSS_EX_FLAG_NO_CACHE,
     * will cause a backend lookup -> mock_account_recv_simple() */
    mock_input_user_or_group_ex(true, "testinitgr",
                                SSS_NSS_EX_FLAG_NO_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR_EX);
    mock_fill_user();
    mock_account_recv_simple();

    set_cmd_cb(test_sss_nss_initgr_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_INITGR_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
    RESET_TCTX;

    /* Use flag SSS_NSS_EX_FLAG_INVALIDATE_CACHE */
    mock_input_user_or_group_ex(true, "testinitgr",
                                SSS_NSS_EX_FLAG_INVALIDATE_CACHE);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_INITGR_EX);
    mock_fill_user();

    set_cmd_cb(test_sss_nss_initgr_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_INITGR_EX,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

const char *test_hostent_aliases[] = {
    "testhost_alias1",
    "testhost_alias2",
    "testhost_alias3",
    NULL
};

const char *test_hostent_addrlist[] = {
    "1.2.3.4",
    "9.8.7.6",
    "2001:db8:1234::",
    "2001:db8::1234",
    NULL
};

struct hostent test_hostent = {
    .h_name = discard_const("testhost"),
    .h_aliases = discard_const(test_hostent_aliases),
    .h_addrtype = AF_INET,
    .h_length = 4,
    .h_addr_list = discard_const(test_hostent_addrlist),
};

static void mock_input_hostbyname(const char *hostname)
{
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, hostname);
    will_return(__wrap_sss_packet_get_body, 0);
    mock_parse_inp(hostname, NULL, EOK);
}

static int parse_host_packet(int af, uint8_t *body, size_t blen, struct hostent *hent)
{
    size_t rp = 2 * sizeof(uint32_t); /* Number of results and reserved */
    unsigned int num_aliases;
    unsigned int num_addresses;
    unsigned int i;

    SAFEALIGN_COPY_UINT32(&num_aliases, body+rp, &rp);
    SAFEALIGN_COPY_UINT32(&num_addresses, body+rp, &rp);

    hent->h_addrtype = af;
    hent->h_length = (af == AF_INET6 ? 16 : 4);

    hent->h_name = talloc_strdup(sss_nss_test_ctx, (char *) body+rp);
    rp += strlen(hent->h_name) + 1;

    if (num_aliases > 0) {
        hent->h_aliases = talloc_zero_array(sss_nss_test_ctx, char *, num_aliases + 1);
        for (i=0; i<num_aliases; i++) {
            hent->h_aliases[i] = talloc_strdup(hent->h_aliases, (char *) body+rp);
            hent->h_aliases[i + 1] = NULL;
            rp += strlen(hent->h_aliases[i]) + 1;
        }
    }

    if (num_addresses > 0) {
        hent->h_addr_list = talloc_zero_array(sss_nss_test_ctx, char *, num_addresses + 1);
        for (i=0; i<num_addresses; i++) {
            hent->h_addr_list[i] = talloc_strdup(hent->h_addr_list, (char *) body+rp);
            hent->h_addr_list[i + 1] = NULL;
            rp += strlen(hent->h_addr_list[i]) + 1;
        }
    }

    /* Make sure we exactly matched the end of the packet */
    if (rp != blen) {
        return EINVAL;
    }

    return EOK;
}

static void assert_host_equal(int af, struct hostent *ref, struct hostent *b)
{
    unsigned int i;

    assert_string_equal(ref->h_name, b->h_name);
    assert_int_equal(af, b->h_addrtype);
    assert_int_equal(af == AF_INET6 ? 16 : 4, b->h_length);
    for (i=0; ref->h_aliases[i] != NULL; i++) {
        assert_non_null(b->h_aliases[i]);
        assert_string_equal(ref->h_aliases[i], b->h_aliases[i]);
    }
    assert_null(b->h_aliases[i]);

    for (i=0; ref->h_addr_list[i] != NULL; i++) {
        assert_string_equal(ref->h_addr_list[i], b->h_addr_list[i]);
    }
    assert_null(b->h_addr_list[i]);
}

static int test_sss_nss_gethostbyname_check(uint32_t status, uint8_t *body, size_t blen)
{
    struct hostent hostent = { 0 };
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_host_packet(AF_INET, body, blen, &hostent);
    assert_int_equal(ret, EOK);

    assert_host_equal(AF_INET, &test_hostent, &hostent);

    return EOK;
}

static int test_sss_nss_gethostbyaddr_v6_check(uint32_t status, uint8_t *body, size_t blen)
{
    struct hostent hostent = { 0 };
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_host_packet(AF_INET6, body, blen, &hostent);
    assert_int_equal(ret, EOK);

    assert_host_equal(AF_INET6, &test_hostent, &hostent);

    return EOK;
}

void test_sss_nss_gethostbyname(void **state)
{
    errno_t ret;

    mock_input_hostbyname("testhost");
    mock_resolver_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETHOSTBYNAME);
    will_return_count(__wrap_sss_packet_get_body, WRAP_CALL_REAL, 9);

    /* Query for that host, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_gethostbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETHOSTBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Test search by aliases */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_hostbyname("testhost_alias1");
    mock_resolver_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETHOSTBYNAME);
    will_return_count(__wrap_sss_packet_get_body, WRAP_CALL_REAL, 9);

    set_cmd_cb(test_sss_nss_gethostbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETHOSTBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Test search by aliases */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_hostbyname("testhost_alias2");
    mock_resolver_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETHOSTBYNAME);
    will_return_count(__wrap_sss_packet_get_body, WRAP_CALL_REAL, 9);

    set_cmd_cb(test_sss_nss_gethostbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETHOSTBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Test search by aliases */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_hostbyname("testhost_alias3");
    mock_resolver_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETHOSTBYNAME);
    will_return_count(__wrap_sss_packet_get_body, WRAP_CALL_REAL, 9);

    set_cmd_cb(test_sss_nss_gethostbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETHOSTBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static void mock_input_netaddr(TALLOC_CTX *mem_ctx, int af, const char *addrstr)
{
    uint8_t *body;
    size_t blen;
    size_t addrlen;
    errno_t ret;
    char addr[16];

    ret = inet_pton(af, addrstr, addr);
    assert_int_equal(ret, 1);

    addrlen = (af == AF_INET6 ? 16 : 4);
    blen = sizeof(uint32_t) * 2 + addrlen;

    body = talloc_zero_array(mem_ctx, uint8_t, blen);
    if (body == NULL) {
        return;
    }

    SAFEALIGN_SETMEM_UINT32(body, af, NULL);
    SAFEALIGN_SETMEM_UINT32(body + sizeof(uint32_t), addrlen, NULL);
    SAFEALIGN_SETMEM_STRING(body + sizeof(uint32_t) * 2, addr, addrlen, NULL);

    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, body);
    will_return(__wrap_sss_packet_get_body, blen);
}

void test_sss_nss_gethostbyaddr(void **state)
{
    errno_t ret;

    /* Host stored by previous tests */
    mock_input_netaddr(sss_nss_test_ctx, AF_INET, "1.2.3.4");
    mock_resolver_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETHOSTBYADDR);
    will_return_count(__wrap_sss_packet_get_body, WRAP_CALL_REAL, 9);

    /* Query for that host, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_gethostbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETHOSTBYADDR,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Test search by aliases */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_netaddr(sss_nss_test_ctx, AF_INET, "9.8.7.6");
    mock_resolver_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETHOSTBYADDR);
    will_return_count(__wrap_sss_packet_get_body, WRAP_CALL_REAL, 9);

    /* Query for that host, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_gethostbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETHOSTBYADDR,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Test search by aliases */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_netaddr(sss_nss_test_ctx, AF_INET6, "2001:DB8:1234:0::0000");
    mock_resolver_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETHOSTBYADDR);
    will_return_count(__wrap_sss_packet_get_body, WRAP_CALL_REAL, 9);

    /* Query for that host, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_gethostbyaddr_v6_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETHOSTBYADDR,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Test search by aliases */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_netaddr(sss_nss_test_ctx, AF_INET6, "2001:DB8:0000::1234");
    mock_resolver_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETHOSTBYADDR);
    will_return_count(__wrap_sss_packet_get_body, WRAP_CALL_REAL, 9);

    /* Query for that host, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_gethostbyaddr_v6_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETHOSTBYADDR,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int sss_nss_host_test_setup(void **state)
{
    const char **aliases = NULL;
    const char **addrs = NULL;
    errno_t ret;
    unsigned int i;

    sss_nss_test_setup(state);

    /* sysdb_host_add expects a talloc_array of aliases and addresses */
    for (i = 0; test_hostent.h_aliases[i]; i++) {
        aliases = talloc_realloc(sss_nss_test_ctx, aliases, const char *, i + 2);
        assert_non_null(aliases);

        aliases[i] = talloc_strdup(aliases, test_hostent.h_aliases[i]);
        assert_non_null(aliases[i]);

        aliases[i + 1] = NULL;
    }

    for (i = 0; test_hostent.h_addr_list[i]; i++) {
        addrs = talloc_realloc(sss_nss_test_ctx, addrs, const char *, i + 2);
        assert_non_null(addrs);

        addrs[i] = talloc_strdup(addrs, test_hostent.h_addr_list[i]);
        assert_non_null(addrs[i]);

        addrs[i + 1] = NULL;
    }

    ret = sysdb_host_add(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                         test_hostent.h_name, aliases, addrs,
                         NULL);
    assert_int_equal(ret, EOK);

    return 0;
}

static int sss_nss_host_test_teardown(void **state)
{
    errno_t ret;

    ret = sysdb_host_delete(sss_nss_test_ctx->tctx->dom,
                            test_hostent.h_name, NULL);
    assert_int_equal(ret, EOK);

    return sss_nss_test_teardown(state);
}

const char *test_netent_aliases[] = {
    "test_network_alias1",
    "test_network_alias2",
    "test_network_alias3",
    NULL
};

struct netent test_netent = {
    .n_name = discard_const("test_network"),
    .n_aliases = discard_const(test_netent_aliases),
    .n_addrtype = AF_INET,
#if (__BYTE_ORDER == __LITTLE_ENDIAN)
    .n_net = 0x04030201 /* 1.2.3.4 */
#elif (__BYTE_ORDER == __BIG_ENDIAN)
    .n_net = 0x01020304 /* 1.2.3.4 */
#else
 #error "unknow endianess"
#endif
};

static void mock_input_netbyname(const char *name)
{
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, name);
    will_return(__wrap_sss_packet_get_body, 0);
    mock_parse_inp(name, NULL, EOK);
}

static int parse_network_packet(int type, uint8_t *body, size_t blen,
                                struct netent *netent)
{
    size_t rp = 2 * sizeof(uint32_t); /* Number of results and reserved */
    char *address;
    unsigned int num_aliases;
    unsigned int i;
    int ret;

    SAFEALIGN_COPY_UINT32(&num_aliases, body+rp, &rp);

    netent->n_addrtype = type;

    netent->n_name = talloc_strdup(sss_nss_test_ctx, (char *) body+rp);
    rp += strlen(netent->n_name) + 1;

    address = (char *) body+rp;
    ret = inet_pton(AF_INET, address, &netent->n_net);
    if (ret != 1) {
        return EINVAL;
    }
    rp += strlen(address) + 1;

    if (num_aliases > 0) {
        netent->n_aliases = talloc_zero_array(sss_nss_test_ctx, char *,
                                              num_aliases + 1);
        for (i=0; i<num_aliases; i++) {
            netent->n_aliases[i] = talloc_strdup(netent->n_aliases,
                                                 (char *) body+rp);
            netent->n_aliases[i + 1] = NULL;
            rp += strlen(netent->n_aliases[i]) + 1;
        }
    }

    /* Make sure we exactly matched the end of the packet */
    if (rp != blen) {
        return EINVAL;
    }

    return EOK;
}

static void assert_network_equal(int type, struct netent *ref, struct netent *b)
{
    unsigned int i;

    assert_string_equal(ref->n_name, b->n_name);
    assert_int_equal(type, b->n_addrtype);
    assert_int_equal(ref->n_addrtype, b->n_addrtype);
    assert_int_equal(ref->n_net, b->n_net);
    for (i=0; ref->n_aliases[i] != NULL; i++) {
        assert_non_null(b->n_aliases[i]);
        assert_string_equal(ref->n_aliases[i], b->n_aliases[i]);
    }
    assert_null(b->n_aliases[i]);
}

static int test_sss_nss_getnetbyname_check(uint32_t status, uint8_t *body, size_t blen)
{
    struct netent netent = { 0 };
    errno_t ret;

    assert_int_equal(status, EOK);

    ret = parse_network_packet(AF_INET, body, blen, &netent);
    assert_int_equal(ret, EOK);

    assert_network_equal(AF_INET, &test_netent, &netent);

    return EOK;
}

void test_sss_nss_getnetbyname(void **state)
{
    errno_t ret;

    mock_input_netbyname("test_network");
    mock_resolver_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNETBYNAME);
    will_return_count(__wrap_sss_packet_get_body, WRAP_CALL_REAL, 5);

    /* Query for that network, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getnetbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNETBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Test search by aliases */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_netbyname("test_network_alias1");
    mock_resolver_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNETBYNAME);
    will_return_count(__wrap_sss_packet_get_body, WRAP_CALL_REAL, 5);

    set_cmd_cb(test_sss_nss_getnetbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNETBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Test search by aliases */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_netbyname("test_network_alias2");
    mock_resolver_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNETBYNAME);
    will_return_count(__wrap_sss_packet_get_body, WRAP_CALL_REAL, 5);

    set_cmd_cb(test_sss_nss_getnetbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNETBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Test search by aliases */
    sss_nss_test_ctx->tctx->done = false;

    mock_input_netbyname("test_network_alias3");
    mock_resolver_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNETBYNAME);
    will_return_count(__wrap_sss_packet_get_body, WRAP_CALL_REAL, 5);

    set_cmd_cb(test_sss_nss_getnetbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNETBYNAME,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

void test_sss_nss_getnetbyaddr(void **state)
{
    errno_t ret;

    mock_input_netaddr(sss_nss_test_ctx, AF_INET, "1.2.3.4");
    mock_resolver_recv_simple();
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETNETBYADDR);
    will_return_count(__wrap_sss_packet_get_body, WRAP_CALL_REAL, 5);

    /* Query for that network, call a callback when command finishes */
    set_cmd_cb(test_sss_nss_getnetbyname_check);
    ret = sss_cmd_execute(sss_nss_test_ctx->cctx, SSS_NSS_GETNETBYADDR,
                          sss_nss_test_ctx->sss_nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(sss_nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static int sss_nss_network_test_setup(void **state)
{
    const char **aliases = NULL;
    errno_t ret;
    unsigned int i;

    sss_nss_test_setup(state);

    /* sysdb_ipnetwork_add expects a talloc_array of aliases */
    for (i = 0; test_netent.n_aliases[i]; i++) {
        aliases = talloc_realloc(sss_nss_test_ctx, aliases, const char *, i + 2);
        assert_non_null(aliases);

        aliases[i] = talloc_strdup(aliases, test_netent.n_aliases[i]);
        assert_non_null(aliases[i]);

        aliases[i + 1] = NULL;
    }

    ret = sysdb_ipnetwork_add(sss_nss_test_ctx, sss_nss_test_ctx->tctx->dom,
                              test_netent.n_name, aliases, "1.2.3.4",
                              NULL);
    assert_int_equal(ret, EOK);

    return 0;
}

static int sss_nss_network_test_teardown(void **state)
{
    errno_t ret;

    ret = sysdb_ipnetwork_delete(sss_nss_test_ctx->tctx->dom,
                                 test_netent.n_name, NULL);
    assert_int_equal(ret, EOK);

    return sss_nss_test_teardown(state);
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
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwnam,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwuid,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwnam_neg,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwuid_neg,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwnam_search,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwuid_search,
                                        sss_nss_test_setup,
                                        sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwnam_update,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwuid_update,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwnam_fqdn,
                                        sss_nss_fqdn_test_setup,
                                        sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwnam_fqdn_fancy,
                                        sss_nss_fqdn_fancy_test_setup,
                                        sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwnam_space,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwnam_space_sub,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwnam_space_sub_query,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_no_members,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_members,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_members_fqdn,
                                        sss_nss_fqdn_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_members_subdom,
                                        sss_nss_subdom_test_setup,
                                        sss_nss_subdom_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_members_subdom_nonfqnames,
                                        sss_nss_subdom_test_setup_nonfqnames,
                                        sss_nss_subdom_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_mix_dom,
                                        sss_nss_subdom_test_setup,
                                        sss_nss_subdom_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_mix_dom_nonfqnames,
                                        sss_nss_subdom_test_setup_nonfqnames,
                                        sss_nss_subdom_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_mix_dom_fqdn,
                                        sss_nss_subdom_test_setup,
                                        sss_nss_subdom_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_mix_dom_fqdn_nonfqnames,
                                        sss_nss_subdom_test_setup_nonfqnames,
                                        sss_nss_subdom_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_mix_subdom,
                                        sss_nss_subdom_test_setup,
                                        sss_nss_subdom_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_mix_subdom_nonfqnames,
                                        sss_nss_subdom_test_setup_nonfqnames,
                                        sss_nss_subdom_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_space,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_space_sub,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_well_known_getnamebysid,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_well_known_getnamebysid_special,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_well_known_getnamebysid_non_existing,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_well_known_getidbysid_failure,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_well_known_getsidbyname,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_well_known_getsidbyname_nonexisting,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_well_known_getsidbyname_special,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getorigbyname,
                                        sss_nss_test_setup,
                                        sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getorigbyname_extra_attrs,
                                        sss_nss_test_setup_extra_attr,
                                        sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getorigbyname_multi_value_attrs,
                                        sss_nss_test_setup_extra_attr,
                                        sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getorigbyname,
                                        sss_nss_test_setup,
                                        sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getorigbyusername,
                                        sss_nss_test_setup,
                                        sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getorigbygroupname,
                                        sss_nss_test_setup,
                                        sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getorigbyname_dup,
                                        sss_nss_test_setup,
                                        sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwnam_upn,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwnam_upn_same_domain,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwnam_upn_neg,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_initgroups,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_initgr_neg,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_initgr_search,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_initgr_update,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_initgr_update_two_expire_attributes,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_initgroups_upn,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_initgr_neg_upn,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getnamebysid,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getnamebysid_neg,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getnamebysid_update,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getnamebycert_neg,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getnamebycert,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getlistbycert,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getlistbycert_multi,
                                        sss_nss_subdom_test_setup,
                                        sss_nss_subdom_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbyname,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbyname_ipa_upg,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbyusername_user,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbyusername_group,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbygroupname_user,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbygroupname_group,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbyid,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbyuid,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbygid_no_group,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbyname_group,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbyid_group,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbygid_group,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbyuid_no_user,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbyupn,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbyname_neg,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getsidbyname_ipa_upg_manual,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwnam_ex,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getpwuid_ex,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrnam_ex_no_members,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getgrgid_ex_no_members,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_initgroups_ex,
                                        sss_nss_test_setup, sss_nss_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_gethostbyname,
                                        sss_nss_host_test_setup,
                                        sss_nss_host_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_gethostbyaddr,
                                        sss_nss_host_test_setup,
                                        sss_nss_host_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getnetbyname,
                                        sss_nss_network_test_setup,
                                        sss_nss_network_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_nss_getnetbyaddr,
                                        sss_nss_network_test_setup,
                                        sss_nss_network_test_teardown),
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
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
