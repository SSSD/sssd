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
int create_stack(struct collection_item **stack)
{
    int error = EOK;

    TRACE_FLOW_STRING("create_stack", "Entry point.");

    error = create_collection(stack, COL_NAME_STACK, COL_CLASS_STACK);

    TRACE_FLOW_STRING("create_stack", "Exit.");
    return error;
}

/* Function that destroys a stack object */
void destroy_stack(struct collection_item *stack)
{
    TRACE_FLOW_STRING("destroy_stack", "Entry point.");

    destroy_collection(stack);

    TRACE_FLOW_STRING("destroy_stack", "Exit");
}



int push_str_property(struct collection_item *stack,
                      const char *property, char *string, int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("push_str_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = add_str_property(stack, NULL, property, string, length);

    TRACE_FLOW_STRING("push_str_property", "Exit.");
    return error;
}

/* Push a binary property to stack.  */
int push_binary_property(struct collection_item *stack,
                         const char *property, void *binary_data, int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("push_binary_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = add_binary_property(stack, NULL, property, binary_data, length);

    TRACE_FLOW_STRING("push_binary_property", "Exit.");
    return error;
}


/* Push an int property to stack. */
int push_int_property(struct collection_item *stack,
                      const char *property, int number)
{
    int error = EOK;

    TRACE_FLOW_STRING("push_int_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = add_int_property(stack, NULL, property, number);

    TRACE_FLOW_STRING("push_int_property", "Exit.");
    return error;
}

/* Push an unsigned int property to stack. */
int push_unsigned_property(struct collection_item *stack,
                           const char *property, unsigned int number)
{
    int error = EOK;

    TRACE_FLOW_STRING("push_unsigned_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = add_unsigned_property(stack, NULL, property, number);

    TRACE_FLOW_STRING("push_unsigned_property", "Exit.");
    return error;
}


/* Push a long property. */
int push_long_property(struct collection_item *stack,
                       const char *property, long number)
{
    int error = EOK;

    TRACE_FLOW_STRING("push_long_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = add_long_property(stack, NULL, property, number);

    TRACE_FLOW_STRING("push_long_property", "Exit.");
    return error;
}

/* Push an unsigned long property. */
int push_ulong_property(struct collection_item *stack,
                        const char *property, unsigned long number)
{
    int error = EOK;

    TRACE_FLOW_STRING("push_ulong_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = add_ulong_property(stack, NULL, property, number);

    TRACE_FLOW_STRING("push_ulong_property", "Exit.");
    return error;
}

/* Push a double property. */
int push_double_property(struct collection_item *stack,
                         const char *property, double number)
{
    int error = EOK;

    TRACE_FLOW_STRING("push_double_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = add_double_property(stack, NULL, property, number);

    TRACE_FLOW_STRING("push_double_property", "Exit.");
    return error;
}

/* Push a bool property. */
int push_bool_property(struct collection_item *stack,
                       const char *property, unsigned char logical)
{
    int error = EOK;

    TRACE_FLOW_STRING("push_bool_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = add_bool_property(stack, NULL, property, logical);

    TRACE_FLOW_STRING("push_double_property", "Exit.");
    return error;
}

/* Push any property */
int push_any_property(struct collection_item *stack,
                      const char *property,
                      int type,
                      void *data,
                      int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("push_bool_property", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = add_any_property(stack, NULL, property, type, data, length);

    TRACE_FLOW_STRING("push_bool_property", "Exit.");
    return error;
}

/* Push item */
int push_item(struct collection_item *stack,
              struct collection_item *item)
{
    int error = EOK;

    TRACE_FLOW_STRING("push_item", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = insert_item_into_current(stack,
                                     item,
                                     COL_DSP_END,
                                     NULL,
                                     0,
                                     COL_INSERT_NOCHECK);

    TRACE_FLOW_STRING("push_item", "Exit.");
    return error;
}

/* Pop_item */
int pop_item(struct collection_item *stack,
             struct collection_item **item)
{
    int error = EOK;

    TRACE_FLOW_STRING("pop_item", "Entry point.");

    /* Check that stack is not empty */
    if (stack == NULL) {
        TRACE_ERROR_STRING("Stack can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a stack */
    if (!is_of_class(stack, COL_CLASS_STACK)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = extract_item_from_current(stack,
                                      COL_DSP_END,
                                      NULL,
                                      0,
                                      0,
                                      item);

    TRACE_FLOW_STRING("pop_item", "Exit.");
    return error;
}
