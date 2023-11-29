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


#ifdef HAVE_EXPLICIT_BZERO

#include <string.h>

#else

typedef void *(*_sss_memset_t)(void *, int, size_t);

static volatile _sss_memset_t memset_func = memset;

static void explicit_bzero(void *s, size_t n)
{
    memset_func(s, 0, n);
}

#endif


void sss_erase_krb5_data_securely(krb5_data *data)
{
    if (data != NULL) {
        sss_erase_mem_securely(data->data, data->length);
    }
}

void sss_erase_krb5_creds_securely(krb5_creds *cred)
{
    if (cred != NULL) {
        sss_erase_krb5_data_securely(&cred->ticket);
        sss_erase_krb5_data_securely(&cred->second_ticket);
    }
}

int sss_erase_talloc_mem_securely(void *p)
{
    if (p == NULL) {
        return 0;
    }

    size_t size = talloc_get_size(p);
    if (size == 0) {
        return 0;
    }

    explicit_bzero(p, size);

    return 0;
}

void sss_erase_mem_securely(void *p, size_t size)
{
    if ((p == NULL) || (size == 0)) {
        return;
    }

    explicit_bzero(p, size);
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
