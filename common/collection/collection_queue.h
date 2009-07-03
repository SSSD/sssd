/*
    QUEUE

    Header file for queue implemented using collection interface.

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

#ifndef COLLECTION_QUEUE_H
#define COLLECTION_QUEUE_H

#include "collection.h"


#define COL_CLASS_QUEUE 40000
#define COL_NAME_QUEUE  "queue"

/* Function that creates a queue object */
int col_create_queue(struct collection_item **queue);

/* Function that destroys a queue object */
void col_destroy_queue(struct collection_item *queue);

/* Family of functions that add property to a queue */
/* Put a string property to queue.  */
int col_enqueue_str_property(struct collection_item *queue,
                             const char *property,
                             const char *string,
                             int length);
/* Put a binary property to queue.  */
int col_enqueue_binary_property(struct collection_item *queue,
                                const char *property,
                                void *binary_data,
                                int length);
/* Put an int property to queue. */
int col_enqueue_int_property(struct collection_item *queue,
                             const char *property,
                             int number);
/* Put an unsigned int property to queue. */
int col_enqueue_unsigned_property(struct collection_item *queue,
                                  const char *property,
                                  unsigned int number);
/* Put a long property. */
int col_enqueue_long_property(struct collection_item *queue,
                              const char *property,
                              long number);
/* Put an unsigned long property. */
int col_enqueue_ulong_property(struct collection_item *queue,
                               const char *property,
                               unsigned long number);
/* Put a double property. */
int col_enqueue_double_property(struct collection_item *queue,
                                const char *property,
                                double number);
/* Put a bool property. */
int col_enqueue_bool_property(struct collection_item *queue,
                              const char *property,
                              unsigned char logical);

/* Put any property */
int col_enqueue_any_property(struct collection_item *queue, /* Queue */
                             const char *property,          /* Name */
                             int type,                      /* Data type */
                             void *data,                    /* Pointer to the data */
                             int length);                   /* Length of the data. For
                                                             * strings it includes the
                                                             * trailing 0 */
/* Push item */
int col_enqueue_item(struct collection_item *queue,
                     struct collection_item *item);


/* Get item from queue */
int col_dequeue_item(struct collection_item *queue,
                     struct collection_item **item);


#endif
