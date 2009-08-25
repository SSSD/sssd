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

#include "talloc.h"
#include "util/util.h"

/*
 * sssd_mem_attach
 * This function will take a non-talloc pointer and "attach" it to a talloc
 * memory context. It will accept a destructor for the original pointer
 * so that when the parent memory context is freed, the non-talloc
 * pointer will also be freed properly.
 */

int password_destructor(void *memctx)
{
    char *password = (char *)memctx;
    int i;

    /* zero out password */
    for (i = 0; password[i]; i++) password[i] = '\0';

    return 0;
}

static int mem_holder_destructor(void *ptr)
{
    struct mem_holder *h;

    h = talloc_get_type(ptr, struct mem_holder);
    return h->fn(h->mem);
}

void *sss_mem_attach(TALLOC_CTX *mem_ctx,
                     void *ptr,
                     void_destructor_fn_t *fn)
{
    struct mem_holder *h;

    if (!ptr || !fn) return NULL;

    h = talloc(mem_ctx, struct mem_holder);
    if (!h) return NULL;

    h->mem = ptr;
    h->fn = fn;
    talloc_set_destructor((TALLOC_CTX *)h, mem_holder_destructor);

    return h;
}
