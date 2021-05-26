/*
   SSSD

   Memory leak/growth checks for check-based tests using talloc.

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

#include <check.h>

#include "tests/common.h"
#include "tests/common_check.h"

void ck_leak_check_setup(void)
{
    ck_assert_msg(leak_check_setup() == true,
                "Cannot set up leaks test: %s\n", check_leaks_err_msg());
}

void ck_leak_check_teardown(void)
{
    ck_assert_msg(leak_check_teardown() == true,
                "Cannot tear down leaks test: %s\n", check_leaks_err_msg());
}
