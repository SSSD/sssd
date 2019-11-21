/*
    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <talloc.h>

#include "util/util.h"

int password_destructor(void *memctx)
{
    char *password = (char *)memctx;
    int i;

    /* zero out password */
    for (i = 0; password[i]; i++) password[i] = '\0';

    return 0;
}

struct mem_holder {
    void *mem;
    void_destructor_fn_t *fn;
};

static int mem_holder_destructor(void *ptr)
{
    struct mem_holder *h;

    h = talloc_get_type(ptr, struct mem_holder);
    return h->fn(h->mem);
}

int sss_mem_attach(TALLOC_CTX *mem_ctx, void *ptr, void_destructor_fn_t *fn)
{
    struct mem_holder *h;

    if (!ptr || !fn) return EINVAL;

    h = talloc(mem_ctx, struct mem_holder);
    if (!h) return ENOMEM;

    h->mem = ptr;
    h->fn = fn;
    talloc_set_destructor((TALLOC_CTX *)h, mem_holder_destructor);

    return EOK;
}
