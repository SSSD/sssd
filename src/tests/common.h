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

#ifndef __TESTS_COMMON_H__
#define __TESTS_COMMON_H__

#include <talloc.h>

extern TALLOC_CTX *global_talloc_context;

#define check_leaks(ctx, bytes) _check_leaks((ctx), (bytes), __location__)
void _check_leaks(TALLOC_CTX *ctx,
                  size_t bytes,
                  const char *location);

void check_leaks_push(TALLOC_CTX *ctx);

#define check_leaks_pop(ctx) _check_leaks_pop((ctx), __location__)
void _check_leaks_pop(TALLOC_CTX *ctx, const char *location);

void leak_check_setup(void);
void leak_check_teardown(void);

void tests_set_cwd(void);

#endif /* !__TESTS_COMMON_H__ */
