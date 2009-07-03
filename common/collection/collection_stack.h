/*
    STACK

    Header file for stack implemented using collection interface.

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

#ifndef COLLECTION_STACK_H
#define COLLECTION_STACK_H

#include <collection.h>


#define COL_CLASS_STACK 30000
#define COL_NAME_STACK  "stack"

/* Function that creates a stack object */
int col_create_stack(struct collection_item **stack);

/* Function that destroys a stack object */
void col_destroy_stack(struct collection_item *stack);

/* Family of functions that push property to stack */
/* Push a string property to stack.  */
int col_push_str_property(struct collection_item *stack,
                          const char *property,
                          const char *string,
                          int length);
/* Push a binary property to stack.  */
int col_push_binary_property(struct collection_item *stack,
                             const char *property,
                             void *binary_data,
                             int length);
/* Push an int property to stack. */
int col_push_int_property(struct collection_item *stack,
                          const char *property,
                          int number);
/* Push an unsigned int property to stack. */
int col_push_unsigned_property(struct collection_item *stack,
                               const char *property,
                               unsigned int number);
/* Push a long property. */
int col_push_long_property(struct collection_item *stack,
                           const char *property,
                           long number);
/* Push an unsigned long property. */
int col_push_ulong_property(struct collection_item *stack,
                            const char *property,
                            unsigned long number);
/* Push a double property. */
int col_push_double_property(struct collection_item *stack,
                             const char *property,
                             double number);
/* Push a bool property. */
int col_push_bool_property(struct collection_item *stack,
                           const char *property,
                           unsigned char logical);

/* Push any property */
int col_push_any_property(struct collection_item *stack, /* Stack */
                          const char *property,          /* Name */
                          int type,                      /* Data type */
                          void *data,                    /* Pointer to the data */
                          int length);                   /* Length of the data. For
                                                          * strings it includes the
                                                          * trailing 0 */
/* Push item */
int col_push_item(struct collection_item *stack,
                  struct collection_item *item);


/* Pop item */
int col_pop_item(struct collection_item *stack,
                 struct collection_item **item);

#endif
