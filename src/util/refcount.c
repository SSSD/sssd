/*
   SSSD

   Simple reference counting wrappers for talloc.

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

#include <talloc.h>

#include "refcount.h"
#include "util/util.h"

struct wrapper {
    int *refcount;
    void *ptr;
};

static int
refcount_destructor(struct wrapper *wrapper)
{
    (*wrapper->refcount)--;
    if (*wrapper->refcount == 0) {
        talloc_free(wrapper->ptr);
    };

    return 0;
}

void *
_rc_alloc(const void *context, size_t size, size_t refcount_offset,
          const char *type_name)
{
    struct wrapper *wrapper;
    char *refcount_pos;

    wrapper = talloc(context, struct wrapper);
    if (wrapper == NULL) {
        return NULL;
    }

    wrapper->ptr = talloc_named_const(NULL, size, type_name);
    if (wrapper->ptr == NULL) {
        talloc_free(wrapper);
        return NULL;
    };

    refcount_pos = (char *)wrapper->ptr + refcount_offset;
    wrapper->refcount = DISCARD_ALIGN(refcount_pos, int *);
    *wrapper->refcount = 1;

    talloc_set_destructor(wrapper, refcount_destructor);

    return wrapper->ptr;
}

void *
_rc_reference(const void *context, size_t refcount_offset, void *source)
{
    struct wrapper *wrapper;
    char *refcount_pos;

    wrapper = talloc(context, struct wrapper);
    if (wrapper == NULL) {
        return NULL;
    }

    wrapper->ptr = source;
    refcount_pos = (char *)wrapper->ptr + refcount_offset;
    wrapper->refcount = DISCARD_ALIGN(refcount_pos, int *);
    (*wrapper->refcount)++;

    talloc_set_destructor(wrapper, refcount_destructor);

    return wrapper->ptr;
}
