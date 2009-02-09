/*
   SSSD

   System Database

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#include <stdlib.h>
#include <check.h>
#include <talloc.h>
#include <tevent.h>
#include <popt.h>
#include "util/util.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"

struct sysdb_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct event_context *ev;
};

static int setup_sysdb_tests(TALLOC_CTX *mem_ctx, struct sysdb_test_ctx **ctx)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;

    test_ctx = talloc_zero(mem_ctx, struct sysdb_test_ctx);
    if (test_ctx == NULL) {
        fail("Could not allocate memory for test context");
        return ENOMEM;
    }

    /* Create an event context
     * It will not be used except in confdb_init and sysdb_init
     */
    test_ctx->ev = event_context_init(test_ctx);
    if (test_ctx->ev == NULL) {
        fail("Could not create event context");
        talloc_free(test_ctx);
        return EIO;
    }

    /* Connect to the conf db */
    ret = confdb_init(mem_ctx, test_ctx->ev, &test_ctx->confdb);
    if(ret != EOK) {
        fail("Could not initialize connection to the confdb");
        talloc_free(test_ctx);
        return ret;
    }

    ret = sysdb_init(test_ctx, test_ctx->ev, test_ctx->confdb, &test_ctx->sysdb);
    if(ret != EOK) {
        fail("Could not initialize connection to the sysdb");
        talloc_free(test_ctx);
        return ret;
    }

    *ctx = test_ctx;
    return EOK;
}

START_TEST (test_sysdb_store_group_posix)
{
    int ret;
    struct sysdb_test_ctx *test_ctx;
    TALLOC_CTX *mem_ctx;

    /* Setup */
    mem_ctx = talloc_new(NULL);
    ret = setup_sysdb_tests(mem_ctx, &test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    ret = sysdb_store_group_posix(test_ctx, test_ctx->sysdb,
                            "LOCAL", "sysdbtestgroup", 67000);
    fail_if(ret != EOK, "Could not store sysdbtestgroup");

    talloc_free(mem_ctx);
}
END_TEST

START_TEST (test_sysdb_replace_group_posix)
{
    int ret;
    struct sysdb_test_ctx *test_ctx;
    TALLOC_CTX *mem_ctx;

    /* Setup */
    mem_ctx = talloc_new(NULL);
    ret = setup_sysdb_tests(mem_ctx, &test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    ret = sysdb_store_group_posix(test_ctx, test_ctx->sysdb,
                            "LOCAL", "sysdbtestgroup", 67001);
    fail_if(ret != EOK, "Could not store sysdbtestgroup");

    talloc_free(mem_ctx);
}
END_TEST

Suite *create_sysdb_suite(void)
{
    Suite *s = suite_create("sysdb");

    /* POSIX Group test case */
    TCase *tc_posix_gr = tcase_create("\tPOSIX Groups");
    tcase_add_test(tc_posix_gr, test_sysdb_store_group_posix);
    tcase_add_test(tc_posix_gr, test_sysdb_replace_group_posix);
    suite_add_tcase(s, tc_posix_gr);

    return s;
}

int main(int argc, const char *argv[]) {
    int opt;
    poptContext pc;
    int failure_count;
    Suite *sysdb_suite;
    SRunner *sr;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        { NULL }
    };

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

    sysdb_suite = create_sysdb_suite();
    sr = srunner_create(sysdb_suite);
    srunner_run_all(sr, CK_VERBOSE);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failure_count==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
