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

#ifndef __TESTS_COMMON_CHECK_H__
#define __TESTS_COMMON_CHECK_H__

#include "tests/common.h"

void ck_leak_check_setup(void);
void ck_leak_check_teardown(void);

#define ck_leaks_push(ctx) check_leaks_push(ctx)
#define ck_leaks_pop(ctx) ck_assert_msg(check_leaks_pop(ctx) == true, "%s", check_leaks_err_msg())

#define sss_ck_fail_if_msg(expr, ...) \
  (expr) ? \
     _ck_assert_failed(__FILE__, __LINE__, "Assertion '"#expr"' failed" , ## __VA_ARGS__) : \
     _mark_point(__FILE__, __LINE__)

#endif /* __TESTS_COMMON_CHECK_H__ */
