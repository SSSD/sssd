/*
    QUEUE

    Implementation of the queue on top of collection library interface.

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
#include "collection_queue.h"
#include "trace.h"

/* Function that creates a queue object */
int col_create_queue(struct collection_item **queue)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_create_queue", "Entry point.");

    error = col_create_collection(queue, COL_NAME_QUEUE, COL_CLASS_QUEUE);

    TRACE_FLOW_STRING("col_create_queue", "Exit.");
    return error;
}

/* Function that destroys a queue object */
void col_destroy_queue(struct collection_item *queue)
{
    TRACE_FLOW_STRING("col_destroy_queue", "Entry point.");

    col_destroy_collection(queue);

    TRACE_FLOW_STRING("col_destroy_queue", "Exit");
}


/* Put a string property into a queue.  */
int col_enqueue_str_property(struct collection_item *queue,
                             const char *property,
                             char *string,
                             int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_enqueue_str_property", "Entry point.");

    /* Check that queue is not empty */
    if (queue == NULL) {
        TRACE_ERROR_STRING("queue can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a queue */
    if (!col_is_of_class(queue, COL_CLASS_QUEUE)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_str_property(queue, NULL, property, string, length);

    TRACE_FLOW_STRING("col_enqueue_str_property", "Exit.");
    return error;
}

/* Put a binary property into a queue.  */
int col_enqueue_binary_property(struct collection_item *queue,
                                const char *property,
                                void *binary_data,
                                int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_enqueue_binary_property", "Entry point.");

    /* Check that queue is not empty */
    if (queue == NULL) {
        TRACE_ERROR_STRING("queue can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a queue */
    if (!col_is_of_class(queue, COL_CLASS_QUEUE)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_binary_property(queue, NULL, property, binary_data, length);

    TRACE_FLOW_STRING("col_enqueue_binary_property", "Exit.");
    return error;
}


/* Put an int property into a queue. */
int col_enqueue_int_property(struct collection_item *queue,
                             const char *property,
                             int number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_enqueue_int_property", "Entry point.");

    /* Check that queue is not empty */
    if (queue == NULL) {
        TRACE_ERROR_STRING("queue can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a queue */
    if (!col_is_of_class(queue, COL_CLASS_QUEUE)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_int_property(queue, NULL, property, number);

    TRACE_FLOW_STRING("col_enqueue_int_property", "Exit.");
    return error;
}

/* Put an unsigned int property into a queue. */
int col_enqueue_unsigned_property(struct collection_item *queue,
                                  const char *property,
                                  unsigned int number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_enqueue_unsigned_property", "Entry point.");

    /* Check that queue is not empty */
    if (queue == NULL) {
        TRACE_ERROR_STRING("queue can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a queue */
    if (!col_is_of_class(queue, COL_CLASS_QUEUE)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_unsigned_property(queue, NULL, property, number);

    TRACE_FLOW_STRING("col_enqueue_unsigned_property", "Exit.");
    return error;
}


/* Put a long property. */
int col_enqueue_long_property(struct collection_item *queue,
                              const char *property,
                              long number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_enqueue_long_property", "Entry point.");

    /* Check that queue is not empty */
    if (queue == NULL) {
        TRACE_ERROR_STRING("queue can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a queue */
    if (!col_is_of_class(queue, COL_CLASS_QUEUE)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_long_property(queue, NULL, property, number);

    TRACE_FLOW_STRING("col_enqueue_long_property", "Exit.");
    return error;
}

/* Put an unsigned long property. */
int col_enqueue_ulong_property(struct collection_item *queue,
                               const char *property,
                               unsigned long number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_enqueue_ulong_property", "Entry point.");

    /* Check that queue is not empty */
    if (queue == NULL) {
        TRACE_ERROR_STRING("queue can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a queue */
    if (!col_is_of_class(queue, COL_CLASS_QUEUE)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_ulong_property(queue, NULL, property, number);

    TRACE_FLOW_STRING("col_enqueue_ulong_property", "Exit.");
    return error;
}

/* Put a double property. */
int col_enqueue_double_property(struct collection_item *queue,
                                const char *property,
                                double number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_enqueue_double_property", "Entry point.");

    /* Check that queue is not empty */
    if (queue == NULL) {
        TRACE_ERROR_STRING("queue can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a queue */
    if (!col_is_of_class(queue, COL_CLASS_QUEUE)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_double_property(queue, NULL, property, number);

    TRACE_FLOW_STRING("enqueue_double_property", "Exit.");
    return error;
}

/* Put a bool property. */
int col_enqueue_bool_property(struct collection_item *queue,
                              const char *property,
                              unsigned char logical)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_enqueue_bool_property", "Entry point.");

    /* Check that queue is not empty */
    if (queue == NULL) {
        TRACE_ERROR_STRING("queue can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a queue */
    if (!col_is_of_class(queue, COL_CLASS_QUEUE)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_bool_property(queue, NULL, property, logical);

    TRACE_FLOW_STRING("col_enqueue_bool_property", "Exit.");
    return error;
}

/* Put any property */
int col_enqueue_any_property(struct collection_item *queue,
                             const char *property,
                             int type,
                             void *data,
                             int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_enqueue_any_property", "Entry point.");

    /* Check that queue is not empty */
    if (queue == NULL) {
        TRACE_ERROR_STRING("queue can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a queue */
    if (!col_is_of_class(queue, COL_CLASS_QUEUE)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_add_any_property(queue, NULL, property, type, data, length);

    TRACE_FLOW_STRING("col_enqueue_any_property", "Exit.");
    return error;
}

/* Enqueue item */
int col_enqueue_item(struct collection_item *queue,
                     struct collection_item *item)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_enqueue_item", "Entry point.");

    /* Check that queue is not empty */
    if (queue == NULL) {
        TRACE_ERROR_STRING("queue can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a queue */
    if (!col_is_of_class(queue, COL_CLASS_QUEUE)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_insert_item_into_current(queue,
                                         item,
                                         COL_DSP_END,
                                         NULL,
                                         0,
                                         COL_INSERT_NOCHECK);

    TRACE_FLOW_STRING("col_enqueue_item", "Exit.");
    return error;
}

/* Dequeue item */
int col_dequeue_item(struct collection_item *queue,
                     struct collection_item **item)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_dequeue_item", "Entry point.");

    /* Check that queue is not empty */
    if (queue == NULL) {
        TRACE_ERROR_STRING("queue can't be NULL", "");
        return EINVAL;
    }

    /* Make sure it is a queue */
    if (!col_is_of_class(queue, COL_CLASS_QUEUE)) {
        TRACE_ERROR_STRING("Wrong class", "");
        return EINVAL;
    }

    error = col_extract_item_from_current(queue,
                                          COL_DSP_FRONT,
                                          NULL,
                                          0,
                                          0,
                                          item);

    TRACE_FLOW_STRING("col_dequeue_item", "Exit.");
    return error;
}
