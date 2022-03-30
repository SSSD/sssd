/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: Common utilities for tests that exercise domains

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

#ifndef __COMMON_MOCK_H_
#define __COMMON_MOCK_H_

/*
 * from cmocka.c:
 * These headers or their equivalents should be included prior to
 * including
 * this header file.
 *
 * #include <stdarg.h>
 * #include <stddef.h>
 * #include <setjmp.h>
 *
 * This allows test applications to use custom definitions of C standard
 * library functions and types.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "tests/common.h"

#define sss_mock_type(type) ((type) mock())
#define sss_mock_ptr_type(type) ((type) (uintptr_t) mock())

#define sss_will_return_always(fn, value) will_return_count(fn, (value), -1)

enum sss_test_wrapper_call {
    WRAP_CALL_WRAPPER,
    WRAP_CALL_REAL
};

void list_tests(FILE *file, const char *pref,
                const struct CMUnitTest tests[], size_t test_count);

int sss_cmocka_run_group_tests(const struct CMUnitTest * const tests,
                               const size_t num_tests,
                               const char *single);
#endif /* __COMMON_MOCK_H_ */
