/*
   SSSD

   Common utilities for check-based tests using talloc.

   Authors:
        Martin Nagy <mnagy@redhat.com>

   Copyright (C) Red Hat, Inc 2009

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

#include <stdio.h>
#include "tests/common.h"
#include "util/util.h"

void
tests_set_cwd(void)
{
    int ret;

    ret = chdir(TEST_DIR);
    if (ret == -1) {
        fprintf(stderr, "Could not chdir to [%s].\n"
                "Attempting to continue with current dir\n", TEST_DIR);
    }
}

void test_dom_suite_setup(const char *tests_path)
{
    errno_t ret;

    /* Create tests directory if it doesn't exist */
    /* (relative to current dir) */
    ret = mkdir(tests_path, 0775);
    if (ret != 0 && errno != EEXIST) {
        fprintf(stderr, "Could not create test directory\n");
    }
}

/* Check that the option names of the two maps are the same
 * and appear in the same order.
 */
errno_t
compare_dp_options(struct dp_option *map1, size_t size1,
                   struct dp_option *map2)
{
    size_t i;

    for (i = 0; i < size1; i++) {
        /* Check for a valid option */
        if (map1[i].opt_name == NULL) return EINVAL;

        /* Check whether we've gone past the end of map2 */
        if (map2[i].opt_name == NULL) return ERANGE;

        /* Ensure that the option names are the same */
        if(strcmp(map1[i].opt_name, map2[i].opt_name) != 0) {
            fprintf(stderr, "Expected [%s], got [%s]\n",
                    map1[i].opt_name, map2[i].opt_name);
            return EINVAL;
        }
    }

    /* Leftover options in map2 */
    if (map2[i].opt_name != NULL) return ERANGE;

    return EOK;
}

/* Check that the option names of the two maps are the same
 * and appear in the same order.
 */
errno_t
compare_sdap_attr_maps(struct sdap_attr_map *map1, size_t size1,
                       struct sdap_attr_map *map2)
{
    size_t i;

    for (i = 0; i < size1; i++) {
        /* Check for a valid option */
        if (map1[i].opt_name == NULL) return EINVAL;

        /* Check whether we've gone past the end of map2 */
        if (map2[i].opt_name == NULL) return ERANGE;

        /* Ensure that the option names are the same */
        if(strcmp(map1[i].opt_name, map2[i].opt_name) != 0) {
            fprintf(stderr, "Expected [%s], got [%s]\n",
                    map1[i].opt_name, map2[i].opt_name);
            return EINVAL;
        }
    }

    /* Leftover options in map2 */
    if (map2[i].opt_name != NULL) return ERANGE;

    return EOK;
}

bool ldb_modules_path_is_set(void)
{
    if (getenv("LDB_MODULES_PATH")) {
        return true;
    }

    return false;
}

/* Returns true if all values are in array (else returns false) */
bool are_values_in_array(const char **values, size_t values_len,
                         const char **array, size_t array_len)
{
    bool is_value_in_element = false;
    bool is_value_in_array = false;
    bool ret = true;

    for (size_t i = 0; i < values_len; i++) {
        is_value_in_array = false;
        for (size_t j = 0; j < array_len; j++) {
            is_value_in_element = strcmp(values[i], array[j]) == 0 ? \
                                 true : false;
            is_value_in_array = is_value_in_array || is_value_in_element;
        }
        ret = ret && is_value_in_array;
    }

    return ret;
}
