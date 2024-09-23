/*
    Copyright (C) 2024 Red Hat

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

#include "config.h"
#include <string.h>

#ifndef HAVE_EXPLICIT_BZERO

typedef void *(*_sss_memset_t)(void *, int, size_t);

static volatile _sss_memset_t memset_func = memset;

static void explicit_bzero(void *s, size_t n)
{
    memset_func(s, 0, n);
}

#endif


void sss_erase_mem_securely(void *p, size_t size)
{
    if ((p == NULL) || (size == 0)) {
        return;
    }

    explicit_bzero(p, size);
}
