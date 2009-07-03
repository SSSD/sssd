/*
    STACK

    Implementation of the stack on top of collection library interface.

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

#include "stdlib.h"
#include "errno.h"
#include "collection_stack.h"
#include "trace.h"

/* Function that creates a stack object */
int col_create_stack(struct collection_item **stack)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_create_stack", "Entry point.");

    error = col_create_collection(stack, COL_NAME_STACK, COL_CLASS_STACK);

    TRACE_FLOW_STRING("col_create_stack", "Exit.");
    return error;
}

/* Function that destroys a stack object */
void col_destroy_stack(struct collection_item *stack)
{
    TRACE_FLOW_STRING("col_destroy_stack", "Entry point.");

    col_destroy_collection(stack);

    TRACE_FLOW_STRING("col_destroy_stack", "Exit");
}



int col_push_str_property(struct collection_item *stack,
                          const char *property, const char *string, int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_push_str_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!col_is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_str_property(stack, NULL, property, string, length);

    TRACE_FLOW_STRING("col_push_str_property", "Exit.");
    return error;
}

/* Push a binary property to stack.  */
int col_push_binary_property(struct collection_item *stack,
                             const char *property,
                             void *binary_data,
                             int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_push_binary_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!col_is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_binary_property(stack, NULL, property, binary_data, length);

    TRACE_FLOW_STRING("col_push_binary_property", "Exit.");
    return error;
}


/* Push an int property to stack. */
int col_push_int_property(struct collection_item *stack,
                          const char *property,
                          int number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_push_int_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!col_is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_int_property(stack, NULL, property, number);

    TRACE_FLOW_STRING("col_push_int_property", "Exit.");
    return error;
}

/* Push an unsigned int property to stack. */
int col_push_unsigned_property(struct collection_item *stack,
                               const char *property,
                               unsigned int number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_push_unsigned_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!col_is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_unsigned_property(stack, NULL, property, number);

    TRACE_FLOW_STRING("col_push_unsigned_property", "Exit.");
    return error;
}


/* Push a long property. */
int col_push_long_property(struct collection_item *stack,
                           const char *property,
                           long number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_push_long_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!col_is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_long_property(stack, NULL, property, number);

    TRACE_FLOW_STRING("col_push_long_property", "Exit.");
    return error;
}

/* Push an unsigned long property. */
int col_push_ulong_property(struct collection_item *stack,
                            const char *property,
                            unsigned long number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_push_ulong_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!col_is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_ulong_property(stack, NULL, property, number);

    TRACE_FLOW_STRING("col_push_ulong_property", "Exit.");
    return error;
}

/* Push a double property. */
int col_push_double_property(struct collection_item *stack,
                             const char *property,
                             double number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_push_double_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!col_is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_double_property(stack, NULL, property, number);

    TRACE_FLOW_STRING("col_push_double_property", "Exit.");
    return error;
}

/* Push a bool property. */
int col_push_bool_property(struct collection_item *stack,
                           const char *property,
                           unsigned char logical)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_push_bool_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!col_is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_bool_property(stack, NULL, property, logical);

    TRACE_FLOW_STRING("push_double_property", "Exit.");
    return error;
}

/* Push any property */
int col_push_any_property(struct collection_item *stack,
                          const char *property,
                          int type,
                          void *data,
                          int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_push_any_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!col_is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_any_property(stack, NULL, property, type, data, length);

    TRACE_FLOW_STRING("col_push_any_property", "Exit.");
    return error;
}

/* Push item */
int col_push_item(struct collection_item *stack,
                  struct collection_item *item)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_push_item", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!col_is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_insert_item_into_current(stack,
                                         item,
                                         COL_DSP_END,
                                         NULL,
                                         0,
                                         COL_INSERT_NOCHECK);

    TRACE_FLOW_STRING("col_push_item", "Exit.");
    return error;
}

/* Pop_item */
int col_pop_item(struct collection_item *stack,
                 struct collection_item **item)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_pop_item", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!col_is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_extract_item_from_current(stack,
                                          COL_DSP_END,
                                          NULL,
                                          0,
                                          0,
                                          item);

    TRACE_FLOW_STRING("col_pop_item", "Exit.");
    return error;
}
