/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2022 Red Hat

    SSSD tests: common helpers

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

#include "tests/cmocka/common_mock.h"

static struct CMUnitTest select_test(const struct CMUnitTest tests[],
                                     size_t test_count, const char *name)
{
    size_t c;
    struct CMUnitTest empty = { 0 };

    for (c = 0; c < test_count; c++) {
        if (strcmp(tests[c].name, name) == 0) {
            return tests[c];
        }
    }

    return empty;
}

void list_tests(FILE *file, const char *pref,
                const struct CMUnitTest tests[], size_t test_count)
{
    size_t c;
    for (c = 0; c < test_count; c++) {
        fprintf(file, "%s %s\n", pref == NULL ? "" : pref, tests[c].name);
    }
}

int sss_cmocka_run_group_tests(const struct CMUnitTest * const tests,
                               const size_t num_tests,
                               const char *single)
{
    struct CMUnitTest single_test[1];

    if (single != NULL) {
        single_test[0] = select_test(tests, num_tests, single);
        if (single_test[0].name == NULL) {
            fprintf(stderr, "\nTest [%s] not available.\n\n", single);
            return ENOENT;
        }

        return _cmocka_run_group_tests("single_test", single_test, 1,
                                      NULL, NULL);
    }
    return _cmocka_run_group_tests("tests", tests, num_tests, NULL, NULL);
}
