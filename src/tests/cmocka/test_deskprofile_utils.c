/*
    Authors:
        Fabiano Fidêncio <fidencio@redhat.com>

    Copyright (C) 2018 Red Hat

    SSSD tests: Tests for desktop profile utilities functions

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

#define _GNU_SOURCE
#include <stdio.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "src/providers/ipa/ipa_deskprofile_rules_util.h"

#define RULES_DIR "/var/lib/sss/deskprofile"
#define DOMAIN "domain.example"
#define USERNAME "user"
#define PRIO "000420"
#define RULE_NAME "rule"
#define EXTENSION "json"
#define USER "000420"
#define GROUP "000000"
#define HOST "000000"
#define HOSTGROUP "000420"

void test_deskprofile_get_filename_path(void **state)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    char *result = NULL;
    const char *results[24];

    /* All the results are based as:
     * user and hostgroup match the rules;
     * group and host don't match the rules;
     */

    /* 1 = user, group, host, hostgroup */
    results[0] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"USER"_"GROUP"_"HOST"_"HOSTGROUP"_"RULE_NAME"."EXTENSION;
    /*  2 = user, group, hostgroup, host */
    results[1] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"USER"_"GROUP"_"HOSTGROUP"_"HOST"_"RULE_NAME"."EXTENSION;
    /*  3 = user, host, group, hostgroup */
    results[2] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"USER"_"HOST"_"GROUP"_"HOSTGROUP"_"RULE_NAME"."EXTENSION;
    /*  4 = user, host, hostgroup, group */
    results[3] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"USER"_"HOST"_"HOSTGROUP"_"GROUP"_"RULE_NAME"."EXTENSION;
    /*  5 = user, hostgroup, group, host */
    results[4] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"USER"_"HOSTGROUP"_"GROUP"_"HOST"_"RULE_NAME"."EXTENSION;
    /*  6 = user, hostgroup, host, group */
    results[5] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"USER"_"HOSTGROUP"_"HOST"_"GROUP"_"RULE_NAME"."EXTENSION;
    /*  7 = group, user, host, hostgroup */
    results[6] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"GROUP"_"USER"_"HOST"_"HOSTGROUP"_"RULE_NAME"."EXTENSION;
    /*  8 = group, user, hostgroup, host */
    results[7] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"GROUP"_"USER"_"HOSTGROUP"_"HOST"_"RULE_NAME"."EXTENSION;
    /*  9 = group, host, user, hostgroup */
    results[8] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"GROUP"_"HOST"_"USER"_"HOSTGROUP"_"RULE_NAME"."EXTENSION;
    /* 10 = group, host, hostgroup, user */
    results[9] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"GROUP"_"HOST"_"HOSTGROUP"_"USER"_"RULE_NAME"."EXTENSION;
    /* 11 = group, hostgroup, user, host */
    results[10] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"GROUP"_"HOSTGROUP"_"USER"_"HOST"_"RULE_NAME"."EXTENSION;
    /* 12 = group, hostgroup, host, user */
    results[11] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"GROUP"_"HOSTGROUP"_"HOST"_"USER"_"RULE_NAME"."EXTENSION;
    /* 13 = host, user, group, hostgroup */
    results[12] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"HOST"_"USER"_"GROUP"_"HOSTGROUP"_"RULE_NAME"."EXTENSION;
    /* 14 = host, user, hostgroup, group */
    results[13] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"HOST"_"USER"_"HOSTGROUP"_"GROUP"_"RULE_NAME"."EXTENSION;
    /* 15 = host, group, user, hostgroup */
    results[14] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"HOST"_"GROUP"_"USER"_"HOSTGROUP"_"RULE_NAME"."EXTENSION;
    /* 16 = host, group, hostgroup, user */
    results[15] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"HOST"_"GROUP"_"HOSTGROUP"_"USER"_"RULE_NAME"."EXTENSION;
    /* 17 = host, hostgroup, user, group */
    results[16] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"HOST"_"HOSTGROUP"_"USER"_"GROUP"_"RULE_NAME"."EXTENSION;
    /* 18 = host, hostgroup, group, user */
    results[17] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"HOST"_"HOSTGROUP"_"GROUP"_"USER"_"RULE_NAME"."EXTENSION;
    /* 19 = hostgroup, user, group, host */
    results[18] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"HOSTGROUP"_"USER"_"GROUP"_"HOST"_"RULE_NAME"."EXTENSION;
    /* 20 = hostgroup, user, host, group */
    results[19] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"HOSTGROUP"_"USER"_"HOST"_"GROUP"_"RULE_NAME"."EXTENSION;
    /* 21 = hostgroup, group, user, host */
    results[20] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"HOSTGROUP"_"GROUP"_"USER"_"HOST"_"RULE_NAME"."EXTENSION;
    /* 22 = hostgroup, group, host, user */
    results[21] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"HOSTGROUP"_"GROUP"_"HOST"_"USER"_"RULE_NAME"."EXTENSION;
    /* 23 = hostgroup, host, user, group */
    results[22] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"HOSTGROUP"_"HOST"_"USER"_"GROUP"_"RULE_NAME"."EXTENSION;
    /* 24 = hostgroup, host, group, user */
    results[23] = RULES_DIR"/"DOMAIN"/"USERNAME"/"PRIO"_"HOSTGROUP"_"HOST"_"GROUP"_"USER"_"RULE_NAME"."EXTENSION;

    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    for (uint16_t i = 0; i < 24; i++) {
        ret = ipa_deskprofile_get_filename_path(tmp_ctx,
                                                i + 1,
                                                RULES_DIR,
                                                DOMAIN,
                                                USERNAME,
                                                PRIO,
                                                USER,
                                                GROUP,
                                                HOST,
                                                HOSTGROUP,
                                                RULE_NAME,
                                                EXTENSION,
                                                &result);
        assert_int_equal(ret, EOK);
        assert_string_equal(results[i], result);

        talloc_zfree(result);
    }

    talloc_free(tmp_ctx);
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
        cmocka_unit_test(test_deskprofile_get_filename_path),
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

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    return rv;
}
