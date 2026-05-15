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

#ifndef _SSS_PTR_LIST_H_
#define _SSS_PTR_LIST_H_

#include <talloc.h>

#include "util/util.h"
#include "util/dlinklist.h"

struct sss_ptr_list;
struct sss_ptr_list_spy;

struct sss_ptr_list_item {
    void *ptr;

    struct sss_ptr_list *list;
    struct sss_ptr_list_spy *spy;
    struct sss_ptr_list_item *prev;
    struct sss_ptr_list_item *next;
};

/**
 * Create new linked list.
 *
 * @param mem_ctx              Memory context.
 * @param free_data_on_removal If true than the stored pointer is freed when
 *                             it is being removed from the list or when
 *                             the list is freed.
 * @return New list or NULL on failure.
 */
struct sss_ptr_list *
sss_ptr_list_create(TALLOC_CTX *mem_ctx, bool free_data_on_removal);

/**
 * Obtain head of the list that can be used with DLIST_* macros.
 *
 * @return Head of the list or NULL if it is empty.
 */
struct sss_ptr_list_item *
sss_ptr_list_head(struct sss_ptr_list *list);

/**
 * @return True if the list is empty, false otherwise.
 */
bool
sss_ptr_list_is_empty(struct sss_ptr_list *list);

/**
 * Add new item (must be a talloc context) to the list.
 *
 * The list item will be automatically removed from the list if @ptr is freed.
 * To remove the item from the list, call talloc_free(item).
 *
 * @param list Linked list.
 * @param ptr  Talloc pointer to add to the list.
 *
 * @return New EOK on success, other errno code on error.
 */
errno_t
sss_ptr_list_add(struct sss_ptr_list *list, void *ptr);

/**
 * Remove stored pointer from the list.
 *
 * If @free_data_on_removal was true when creating the list, the pointer will
 * be automatically freed.
 *
 * @param list Linked list.
 * @param ptr  Talloc pointer to remove from the list.
 */
void
sss_ptr_list_remove(struct sss_ptr_list *list, void *ptr);

/**
 * Find pointer in the list and return list item containing it.
 *
 * @param list Linked list.
 * @param ptr  Talloc pointer to search for.
 *
 * @return List item if found, NULL otherwise..
 */
struct sss_ptr_list_item *
sss_ptr_list_find(struct sss_ptr_list *list, void *ptr);

/**
 * Return value stored inside linked list item.
 *
 * @param item Linked list item.
 * @param type Type to look for.
 *
 * @return The value.
 */
#define sss_ptr_list_value(item, type) \
    talloc_get_type(item->ptr, type)

#define SSS_PTR_LIST_FOR_EACH(list, value, type)                              \
    for (struct sss_ptr_list_item *__item = sss_ptr_list_head(list);          \
         __item != NULL && (((value) = sss_ptr_list_value(__item, type)), 1); \
         __item = __item->next)

#endif /* _SSS_PTR_LIST_H_ */
