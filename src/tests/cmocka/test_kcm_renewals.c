/*
    Copyright (C) 2020 Red Hat

    SSSD tests: Test KCM Renewals

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

#include "config.h"

#include <stdio.h>
#include <popt.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "util/util.h"
#include "util/util_creds.h"
#include "tests/cmocka/common_mock.h"
#include "responder/kcm/kcmsrv_ccache.h"
#include "responder/kcm/kcm_renew.h"
#include "responder/kcm/kcmsrv_ccache_be.h"
#include "responder/kcm/kcmsrv_ccache_pvt.h"
#include "responder/kcm/kcmsrv_pvt.h"
#include "responder/kcm/kcmsrv_ccache_secdb.c"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_kcm_renewals_conf.ldb"
#define TEST_DB_FULL_PATH  TESTS_PATH "/secrets.ldb"

errno_t sss_sec_init_with_path(TALLOC_CTX *mem_ctx,
                               struct sss_sec_quota *quota,
                               const char *dbpath,
                               struct sss_sec_ctx **_sec_ctx);

errno_t kcm_renew_all_tgts(TALLOC_CTX *mem_ctx,
                           struct kcm_renew_tgt_ctx *renew_tgt_ctx,
                           struct kcm_ccache **cc_list);

const struct kcm_ccdb_ops ccdb_mem_ops;
const struct kcm_ccdb_ops ccdb_secdb_ops;

struct test_ctx {
    struct krb5_ctx *krb5_ctx;
    struct tevent_context *ev;
    struct kcm_ccdb *ccdb;
};

/* register_cli_protocol_version is required in test since it links with
 * responder_common.c module
 */
struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version responder_test_cli_protocol_version[] = {
        { 0, NULL, NULL }
    };

    return responder_test_cli_protocol_version;
}

static int setup_kcm_renewals(void **state)
{
    struct test_ctx *tctx;

    tctx = talloc_zero(NULL, struct test_ctx);
    assert_non_null(tctx);

    tctx->ev = tevent_context_init(tctx);
    assert_non_null(tctx->ev);

    tctx->ccdb = talloc_zero(tctx, struct kcm_ccdb);
    assert_non_null(tctx->ccdb);
    tctx->ccdb->ev = tctx->ev;

    tctx->ccdb->ops = &ccdb_secdb_ops;
    assert_non_null(tctx->ccdb->ops);

    *state = tctx;
    return 0;
}

static int teardown_kcm_renewals(void **state)
{
    struct test_ctx *tctx = talloc_get_type(*state, struct test_ctx);

    unlink(TEST_DB_FULL_PATH);

    rmdir(TESTS_PATH);
    talloc_free(tctx);
    return 0;
}

static void test_kcm_renewals_tgt(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    errno_t ret;
    struct ccdb_secdb *secdb = NULL;
    struct kcm_renew_tgt_ctx *renew_tgt_ctx = NULL;
    struct kcm_ccache **cc_list;
    struct kcm_ccache *cc;

    secdb = talloc_zero(test_ctx, struct ccdb_secdb);

    assert_non_null(secdb);

    ret = mkdir(TESTS_PATH, 0700);
    assert_int_equal(ret, 0);

    open(TEST_DB_FULL_PATH, O_CREAT|O_EXCL|O_WRONLY, 0600);

    ret = sss_sec_init_with_path(test_ctx->ccdb, NULL, TEST_DB_FULL_PATH,
                                 &secdb->sctx);

    /* Create renew ctx */
    renew_tgt_ctx = talloc_zero(test_ctx, struct kcm_renew_tgt_ctx);
    renew_tgt_ctx->ev = test_ctx->ev;

    /* Create cc list */
    cc_list = talloc_zero_array(test_ctx, struct kcm_ccache *, 2);
    assert_non_null(cc_list);

    cc = talloc_zero(cc_list, struct kcm_ccache);
    assert_non_null(cc);

    cc->name = talloc_strdup(test_ctx, "1000:1001");
    cc->owner.uid = 1000;
    cc->owner.gid = 1000;

    cc_list[0] = cc;
    cc_list[1] = NULL;

    ret = kcm_renew_all_tgts(test_ctx, renew_tgt_ctx, cc_list);
    assert_int_equal(ret, EOK);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int rv;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_kcm_renewals_tgt,
                                        setup_kcm_renewals,
                                        teardown_kcm_renewals),
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
     * they might not after a failed run. Remove the old DB to be sure
     */
    tests_set_cwd();

    rv = cmocka_run_group_tests(tests, NULL, NULL);

    return rv;
}
