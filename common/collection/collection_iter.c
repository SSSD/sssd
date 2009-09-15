/*
    COLLECTION LIBRARY

    Implementation of the collection library iterator functions.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

    Collection Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Collection Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Collection Library.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include "config.h"
#include "trace.h"

/* The collection should use the real structures */
#include "collection_priv.h"
#include "collection.h"



/* Grow iteration stack */
static int col_grow_stack(struct collection_iterator *iterator, unsigned desired)
{
    int grow_by = 0;
    struct collection_item **temp;

    TRACE_FLOW_STRING("col_grow_stack", "Entry.");

    if (desired > iterator->stack_size) {
        grow_by = (((desired - iterator->stack_size) / STACK_DEPTH_BLOCK) + 1) * STACK_DEPTH_BLOCK;
        temp = (struct collection_item **)realloc(iterator->stack, grow_by * sizeof(struct collection_item *));
        if (temp == NULL) {
            TRACE_ERROR_NUMBER("Failed to allocate memory", ENOMEM);
            return ENOMEM;
        }
        iterator->stack = temp;
        iterator->stack_size += grow_by;
    }
    TRACE_FLOW_STRING("col_grow_stack", "Exit.");
    return EOK;
}



/* Bind iterator to a collection */
int col_bind_iterator(struct collection_iterator **iterator,
                      struct collection_item *ci,
                      int mode_flags)
{
    int error;
    struct collection_header *header;
    struct collection_iterator *iter = NULL;

    TRACE_FLOW_STRING("col_bind_iterator", "Entry.");

    /* Do some argument checking first */
    if ((iterator == NULL) || (ci == NULL)) {
        TRACE_ERROR_NUMBER("Invalid parameter.", EINVAL);
        return EINVAL;
    }

    iter = (struct collection_iterator *)malloc(sizeof(struct collection_iterator));
    if (iter == NULL) {
        TRACE_ERROR_NUMBER("Error allocating memory for the iterator.", ENOMEM);
        return ENOMEM;
    }

    /* Allocate memory for the stack */
    iter->stack = NULL;
    iter->stack_size = 0;
    iter->stack_depth = 0;
    iter->item_level = 0;
    iter->flags = mode_flags;
    iter->pin_level = 0;
    iter->can_break = 0;

    TRACE_INFO_NUMBER("Iterator flags", iter->flags);

    /* Allocate memory for stack */
    error = col_grow_stack(iter, 1);
    if(error) {
        free(iter);
        TRACE_ERROR_NUMBER("Error growing stack.", error);
        return error;
    }

    /* Create a special end item */
    error = col_allocate_item(&(iter->end_item), "", NULL, 0, COL_TYPE_END);
    if(error) {
        free(iter);
        TRACE_ERROR_NUMBER("Error allocating end item.", error);
        return error;
    }

    /* Make sure that we tie iterator to the collection */
    header = (struct collection_header *)ci->data;
    header->reference_count++;
    iter->top = ci;
    iter->pin = ci;
    *(iter->stack) = ci;
    iter->stack_depth++;

    *iterator = iter;

    TRACE_FLOW_STRING("col_bind_iterator", "Exit");
    return EOK;
}

/* Stop processing this subcollection and move to the next item in the
 * collection 'level' levels up.*/
int col_iterate_up(struct collection_iterator *iterator, unsigned level)
{
    TRACE_FLOW_STRING("iterate_up", "Entry");

    if (iterator == NULL) {
        TRACE_ERROR_NUMBER("Invalid parameter.", EINVAL);
        return EINVAL;
    }

    TRACE_INFO_NUMBER("Going up:", level);
    TRACE_INFO_NUMBER("Current stack depth:", iterator->stack_depth);

    /* If level is big just move to the top,
     * that will end the iteration process.
     */
    if (level >= iterator->stack_depth) iterator->stack_depth = 0;
    else iterator->stack_depth -= level;

    TRACE_INFO_NUMBER("Stack depth at the end:", iterator->stack_depth);
    TRACE_FLOW_STRING("col_iterate_up", "Exit");
    return EOK;
}

/* How deep are we relative to the top level.*/
int col_get_iterator_depth(struct collection_iterator *iterator, int *depth)
{
    TRACE_FLOW_STRING("col_get_iterator_depth", "Entry");

    if ((iterator == NULL) || (depth == NULL)) {
        TRACE_ERROR_NUMBER("Invalid parameter.", EINVAL);
        return EINVAL;
    }

    *depth = iterator->stack_depth - 1;

    TRACE_INFO_NUMBER("Stack depth at the end:", iterator->stack_depth);
    TRACE_FLOW_STRING("col_get_iterator_depth","Exit");
    return EOK;
}

/* What was the level of the last item we got? */
int col_get_item_depth(struct collection_iterator *iterator, int *depth)
{
    TRACE_FLOW_STRING("col_get_item_depth", "Entry");

    if ((iterator == NULL) || (depth == NULL)) {
        TRACE_ERROR_NUMBER("Invalid parameter.", EINVAL);
        return EINVAL;
    }

    *depth = iterator->item_level;

    TRACE_INFO_NUMBER("Item level at the end:", iterator->item_level);
    TRACE_FLOW_STRING("col_get_item_depth","Exit");
    return EOK;
}



/* Unbind the iterator from the collection */
void col_unbind_iterator(struct collection_iterator *iterator)
{
    TRACE_FLOW_STRING("col_unbind_iterator", "Entry.");
    if (iterator != NULL) {
        col_destroy_collection(iterator->top);
        col_delete_item(iterator->end_item);
        free(iterator->stack);
        free(iterator);
    }
    TRACE_FLOW_STRING("col_unbind_iterator", "Exit");
}

/* Get items from the collection one by one following the tree */
int col_iterate_collection(struct collection_iterator *iterator,
                           struct collection_item **item)
{
    int error;
    struct collection_item *current;
    struct collection_item *other;

    TRACE_FLOW_STRING("col_iterate_collection", "Entry.");

    /* Check if we have storage for item */
    if (item == NULL) {
        TRACE_ERROR_NUMBER("Invalid parameter.", EINVAL);
        return EINVAL;
    }

    while (1) {

        TRACE_INFO_NUMBER("Stack depth:", iterator->stack_depth);

        if (iterator->stack_depth == 0) {
            /* Re-init so if we continue looping we start over */
            iterator->stack[0] = iterator->top;
            iterator->stack_depth++;
            iterator->item_level = 0;
        }

        /* Is current item available */
        current = iterator->stack[iterator->stack_depth - 1];
        iterator->item_level = iterator->stack_depth - 1;

        /* Are we done? */
        if (((iterator->stack_depth - 1) == iterator->pin_level) &&
            (iterator->pin == current)) {
            if (iterator->can_break) {
                TRACE_FLOW_STRING("We are done.", "");
                *item = NULL;
                iterator->can_break = 0;
                return EOK;
            }
            else iterator->can_break = 1;
        }

        /* We are not done so check if we have an item  */
        if (current != NULL) {

            TRACE_INFO_STRING("Current item:", current->property);
            TRACE_INFO_NUMBER("Current item type:", current->type);

            /* Is this a collection reference */
            if (current->type == COL_TYPE_COLLECTIONREF) {
                /* We do follow references? */
                TRACE_INFO_STRING("Current item:", "collection reference");
                if ((iterator->flags & COL_TRAVERSE_IGNORE) == 0) {
                    /* We should not ignore - then move on */
                    TRACE_INFO_STRING("Collection references are not ignored", "");
                    error = col_grow_stack(iterator, iterator->stack_depth + 1);
                    if (error) {
                        TRACE_ERROR_NUMBER("Error growing stack.", error);
                        return error;
                    }
                    /* Do we need to go deeper than one level ? */
                    if ((iterator->flags & COL_TRAVERSE_ONELEVEL) == 0) {
                        TRACE_INFO_STRING("Need to go deeper", "");
                        /* We need to go deeper... */
                        /* Do we need to show headers but not reference? */
                        if ((iterator->flags & COL_TRAVERSE_ONLYSUB) != 0) {
                            TRACE_INFO_STRING("Instructed to show header not reference", "");
                            other = *((struct collection_item **)current->data);
                            iterator->stack[iterator->stack_depth] = other->next;
                            iterator->item_level = iterator->stack_depth;
                            *item = other;
                        }
                        /* Do we need to show both? */
                        else if ((iterator->flags & COL_TRAVERSE_SHOWSUB) != 0) {
                            TRACE_INFO_STRING("Instructed to show header and reference","");
                            iterator->stack[iterator->stack_depth] = *((struct collection_item **)(current->data));
                            *item = current;
                            /* Do not need to adjust level here */
                        }
                        /* Do not show either */
                        else if ((iterator->flags & COL_TRAVERSE_FLAT) != 0) {
                            TRACE_INFO_STRING("Instructed not to show header and reference","");
                            other = *((struct collection_item **)current->data);
                            iterator->stack[iterator->stack_depth] = other->next;
                            iterator->stack[iterator->stack_depth - 1] = current->next;
                            iterator->stack_depth++;
                            /* Do not need to adjust level here */
                            continue;
                        }
                        /* We need to show reference only */
                        else {
                            TRACE_INFO_STRING("Instructed to show reference only", "");
                            other = *((struct collection_item **)current->data);
                            TRACE_INFO_STRING("Sub collection:", other->property);
                            TRACE_INFO_NUMBER("Sub collection type:", other->type);
                            iterator->stack[iterator->stack_depth] = other->next;
                            if (other->next != NULL) {
                                TRACE_INFO_STRING("Will show this item next time:", other->next->property);
                                TRACE_INFO_NUMBER("Will show this item next time type:", other->next->type);
                            }
                            *item = current;
                            TRACE_INFO_NUMBER("Level of the reference:", iterator->item_level);
                            /* Do not need to adjust level here */
                        }

                        TRACE_INFO_STRING("We return item:", (*item)->property);
                        TRACE_INFO_NUMBER("We return item type:", (*item)->type);
                        TRACE_INFO_STRING("Moving to the next item on the previous item in stack", "");
                        iterator->stack[iterator->stack_depth - 1] = current->next;
                        iterator->stack_depth++;

                    }
                    else {
                        TRACE_INFO_STRING("Instructed to parse just one level", "");
                        /* On one level - just return current */
                        *item = current;
                        TRACE_INFO_STRING("Moving to the next item on one level", "");
                        iterator->stack[iterator->stack_depth - 1] = current->next;
                    }
                    break;
                }
                else {
                    /* We need to ignore references so move to the next item */
                    TRACE_INFO_STRING("Stepping over the reference", "");
                    iterator->stack[iterator->stack_depth - 1] = current->next;
                    continue;
                }
            }
            else {
                /* Got a normal item - return it and move to the next one */
                if ((current->type == COL_TYPE_COLLECTION) &&
                    ((iterator->flags & COL_TRAVERSE_FLAT) != 0) &&
                    (iterator->stack_depth > 1)) {
                    TRACE_INFO_STRING("Header of the sub collection in flat case ", "");
                    iterator->stack[iterator->stack_depth - 1] = current->next;
                    continue;
                }
                else {
                    TRACE_INFO_STRING("Simple item", "");
                    *item = current;
                    iterator->stack[iterator->stack_depth - 1] = current->next;
                }
                break;
            }
        }
        else {
            /* Item is NULL */
            TRACE_INFO_STRING("Finished level", "moving to upper level");
            iterator->stack_depth--;
            /* Remember that item_level is zero based while depth is size
             * so we decrease and then assign. */
            TRACE_INFO_NUMBER("Stack depth at the end:", iterator->stack_depth);
            if ((iterator->flags & COL_TRAVERSE_END) != 0) {

                /* Show end element
                 * a) If we are flattening but at the top
                 * b) We are not flattening
                 */
                if ((((iterator->flags & COL_TRAVERSE_FLAT) != 0) &&
                     (iterator->stack_depth == 0)) ||
                    ((iterator->flags & COL_TRAVERSE_FLAT) == 0)) {

                    /* Return dummy entry to indicate the end of the collection */
                    TRACE_INFO_STRING("Finished level", "told to return END");
                    *item = iterator->end_item;
                    break;
                }
            }
            else {
                /* Move to next level */
                continue;
            }
        }
    }

    TRACE_FLOW_STRING("col_iterate_collection", "Exit");
    return EOK;
}


/* Pins down the iterator to loop around this point */
void col_pin_iterator(struct collection_iterator *iterator)
{
    TRACE_FLOW_STRING("col_iterator_add_pin", "Entry");

    while ((iterator->stack[iterator->stack_depth - 1] == NULL) &&
            (iterator->stack_depth)) {
        iterator->stack_depth--;
    }

    if (iterator->stack_depth == 0) {
        iterator->pin = iterator->top;
        iterator->pin_level = 0;
    }
    else {
        iterator->pin = iterator->stack[iterator->stack_depth - 1];
        iterator->pin_level = iterator->stack_depth - 1;
    }
    iterator->can_break = 0;

    TRACE_FLOW_STRING("col_iterator_add_pin", "Exit");
}
