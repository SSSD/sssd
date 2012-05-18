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
        if (strlen(TEST_DIR)) {
            fprintf(stderr,
                    "Could not chdir to [%s].\n"
                    "Attempting to continue with current dir\n",
                    TEST_DIR);
        }
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
