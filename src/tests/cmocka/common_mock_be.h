/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests: Fake back end

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

#ifndef __COMMON_MOCK_BE_H_
#define __COMMON_MOCK_BE_H_

#include "tests/cmocka/common_mock.h"

struct be_ctx *mock_be_ctx(TALLOC_CTX *mem_ctx, struct sss_test_ctx *tctx);

#endif /* __COMMON_MOCK_BE_H_ */
