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
