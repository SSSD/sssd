/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2018 Red Hat

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
#include "util/dlinklist.h"
#include "util/sss_ptr_list.h"

struct sss_ptr_list {
    struct sss_ptr_list_item *head;
    bool in_destructor;
    bool free_data;
};

struct sss_ptr_list_spy {
    struct sss_ptr_list_item *item;
};

static int
sss_ptr_list_spy_destructor(struct sss_ptr_list_spy *spy)
{
    spy->item->ptr = NULL;
    spy->item->spy = NULL;
    talloc_free(spy->item);
    return 0;
}

static int
sss_ptr_list_item_destructor(struct sss_ptr_list_item *item)
{
    if (item->spy != NULL) {
        talloc_set_destructor(item->spy, NULL);
        talloc_free(item->spy);
    }

    if (item->list == NULL) {
        return 0;
    }

    if (item->list->free_data && item->ptr != NULL) {
        talloc_free(item->ptr);
    }

    if (item->list->in_destructor) {
        return 0;
    }

    DLIST_REMOVE(item->list->head, item);
    return 0;
}

static int
sss_ptr_list_destructor(struct sss_ptr_list *list)
{
    list->in_destructor = true;

    return 0;
}

static struct sss_ptr_list_spy *
sss_ptr_list_spy_create(struct sss_ptr_list_item *item, void *ptr)
{
    struct sss_ptr_list_spy *spy;

    spy = talloc_zero(ptr, struct sss_ptr_list_spy);
    if (spy == NULL) {
        return NULL;
    }

    spy->item = item;

    talloc_set_destructor(spy, sss_ptr_list_spy_destructor);

    return spy;
}

struct sss_ptr_list *
sss_ptr_list_create(TALLOC_CTX *mem_ctx, bool free_data_on_removal)
{
    struct sss_ptr_list *list;

    list = talloc_zero(mem_ctx, struct sss_ptr_list);
    if (list == NULL) {
        return NULL;
    }

    list->free_data = free_data_on_removal;

    talloc_set_destructor(list, sss_ptr_list_destructor);
    return list;
}

errno_t
sss_ptr_list_add(struct sss_ptr_list *list, void *ptr)
{
    struct sss_ptr_list_item *item;

    item = talloc_zero(list, struct sss_ptr_list_item);
    if (item == NULL) {
        return ENOMEM;
    }

    item->ptr = ptr;
    item->list = list;
    item->spy = sss_ptr_list_spy_create(item, ptr);
    if (item->spy == NULL) {
        talloc_free(item);
        return ENOMEM;
    }

    DLIST_ADD(list->head, item);

    talloc_set_destructor(item, sss_ptr_list_item_destructor);

    return EOK;
}

void
sss_ptr_list_remove(struct sss_ptr_list *list, void *ptr)
{
    struct sss_ptr_list_item *item;

    item = sss_ptr_list_find(list, ptr);
    if (item == NULL) {
        return;
    }

    talloc_free(item);
}

struct sss_ptr_list_item *
sss_ptr_list_find(struct sss_ptr_list *list, void *ptr)
{
    struct sss_ptr_list_item *item;

    DLIST_FOR_EACH(item, list->head) {
        if (item->ptr == ptr) {
            return item;
        }
    }

    return NULL;
}

struct sss_ptr_list_item *
sss_ptr_list_head(struct sss_ptr_list *list)
{
    return list->head;
}

bool
sss_ptr_list_is_empty(struct sss_ptr_list *list)
{
    return list == NULL || list->head == NULL;
}
