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

/**
 * @defgroup stack STACK interface
 *
 * Stack interface is a wrapper on top of the \ref collection
 * interface. It implements a stack using a collection object.
 *
 * @{
 */

/** @brief Class for the stack object */
#define COL_CLASS_STACK 30000
/** @brief All stacks use this name as the name of the collection */
#define COL_NAME_STACK  "stack"

/**
 * @brief Create stack.
 *
 * Function that creates a stack object.
 *
 * @param[out] stack             Newly created stack object.
 *
 * @return 0          - Stack was created successfully.
 * @return ENOMEM     - No memory.
 *
 */
int col_create_stack(struct collection_item **stack);

/**
 * @brief Destroy stack.
 *
 * Function that destroys a stack object.
 *
 * @param[in] stack              Stack object to destroy.
 *
 */

void col_destroy_stack(struct collection_item *stack);

/**
 * @brief Push string to the stack.
 *
 * @param[in] stack       Stack object.
 * @param[in] property    Name of the property.<br>
 *                        Name should consist of the ASCII characters
 *                        with codes non less than space.
 *                        Exclamation mark character is
 *                        a special character and can't be used
 *                        in name of collection or property.<br>
 *                        Maximum allowed length is defined at compile time.
 *                        The default value is 64k.
 * @param[in] string      Null terminated string to add.
 * @param[in] length      Length of the string. Should include the length
 *                        of the terminating 0.
 *                        If the length is shorter than the full string
 *                        the string will be truncated. If the length is
 *                        longer than the actual string there might be
 *                        garbage at end of the actual string.
 *                        Library will always properly NULL terminate
 *                        the string at the given position dictated
 *                        by length but in no way will inspect the validity
 *                        of the passed in data. This is left to the calling
 *                        application.
 *
 * @return 0 - Property was pushed successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_push_str_property(struct collection_item *stack,
                          const char *property,
                          const char *string,
                          int length);
/**
 * @brief Push binary value to the stack.
 *
 * @param[in] stack       Stack object.
 * @param[in] property    Name of the property.<br>
 *                        Name should consist of the ASCII characters
 *                        with codes non less than space.
 *                        Exclamation mark character is
 *                        a special character and can't be used
 *                        in name of collection or property.<br>
 *                        Maximum allowed length is defined at compile time.
 *                        The default value is 64k.
 * @param[in] binary_data Data to add.
 * @param[in] length      Length of the binary data.
 *
 * @return 0 - Property was pushed successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_push_binary_property(struct collection_item *stack,
                             const char *property,
                             void *binary_data,
                             int length);
/**
 * @brief Push integer value to the stack.
 *
 * @param[in] stack       Stack object.
 * @param[in] property    Name of the property.<br>
 *                        Name should consist of the ASCII characters
 *                        with codes non less than space.
 *                        Exclamation mark character is
 *                        a special character and can't be used
 *                        in name of collection or property.<br>
 *                        Maximum allowed length is defined at compile time.
 *                        The default value is 64k.
 * @param[in] number      Value to add.
 *
 * @return 0 - Property was pushed successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_push_int_property(struct collection_item *stack,
                          const char *property,
                          int32_t number);
/**
 * @brief Push unsigned value to the stack.
 *
 * @param[in] stack       Stack object.
 * @param[in] property    Name of the property.<br>
 *                        Name should consist of the ASCII characters
 *                        with codes non less than space.
 *                        Exclamation mark character is
 *                        a special character and can't be used
 *                        in name of collection or property.<br>
 *                        Maximum allowed length is defined at compile time.
 *                        The default value is 64k.
 * @param[in] number      Value to add.
 *
 * @return 0 - Property was pushed successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_push_unsigned_property(struct collection_item *stack,
                               const char *property,
                               uint32_t number);
/**
 * @brief Push long integer value to the stack.
 *
 * @param[in] stack       Stack object.
 * @param[in] property    Name of the property.<br>
 *                        Name should consist of the ASCII characters
 *                        with codes non less than space.
 *                        Exclamation mark character is
 *                        a special character and can't be used
 *                        in name of collection or property.<br>
 *                        Maximum allowed length is defined at compile time.
 *                        The default value is 64k.
 * @param[in] number      Value to add.
 *
 * @return 0 - Property was pushed successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_push_long_property(struct collection_item *stack,
                           const char *property,
                           int64_t number);
/**
 * @brief Push unsigned long value to the stack.
 *
 * @param[in] stack       Stack object.
 * @param[in] property    Name of the property.<br>
 *                        Name should consist of the ASCII characters
 *                        with codes non less than space.
 *                        Exclamation mark character is
 *                        a special character and can't be used
 *                        in name of collection or property.<br>
 *                        Maximum allowed length is defined at compile time.
 *                        The default value is 64k.
 * @param[in] number      Value to add.
 *
 * @return 0 - Property was pushed successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_push_ulong_property(struct collection_item *stack,
                            const char *property,
                            uint64_t number);
/**
 * @brief Push floating point value to the stack.
 *
 * @param[in] stack       Stack object.
 * @param[in] property    Name of the property.<br>
 *                        Name should consist of the ASCII characters
 *                        with codes non less than space.
 *                        Exclamation mark character is
 *                        a special character and can't be used
 *                        in name of collection or property.<br>
 *                        Maximum allowed length is defined at compile time.
 *                        The default value is 64k.
 * @param[in] number      Value to add.
 *
 * @return 0 - Property was pushed successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_push_double_property(struct collection_item *stack,
                             const char *property,
                             double number);
/**
 * @brief Push Boolean value to the stack.
 *
 * @param[in] stack       Stack object.
 * @param[in] property    Name of the property.<br>
 *                        Name should consist of the ASCII characters
 *                        with codes non less than space.
 *                        Exclamation mark character is
 *                        a special character and can't be used
 *                        in name of collection or property.<br>
 *                        Maximum allowed length is defined at compile time.
 *                        The default value is 64k.
 * @param[in] logical     Value to add.
 *
 * @return 0 - Property was pushed successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_push_bool_property(struct collection_item *stack,
                           const char *property,
                           unsigned char logical);

/**
 * @brief Push value of any type to the stack.
 *
 * @param[in] stack       Stack object.
 * @param[in] property    Name of the property.<br>
 *                        Name should consist of the ASCII characters
 *                        with codes non less than space.
 *                        Exclamation mark character is
 *                        a special character and can't be used
 *                        in name of collection or property.<br>
 *                        Maximum allowed length is defined at compile time.
 *                        The default value is 64k.
 * @param[in] type        Type to use.
 * @param[in] data        Data to add.
 * @param[in] length      Length of the data.
 *
 * @return 0 - Property was pushed successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_push_any_property(struct collection_item *stack,
                          const char *property,
                          int type,
                          void *data,
                          int length);

/**
 * @brief Push item into the stack.
 *
 * @param[in] stack       Stack object.
 * @param[in] item        Item to push.
 *
 * @return 0          - Item was pushed successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 */

int col_push_item(struct collection_item *stack,
                  struct collection_item *item);


/**
 * @brief Pop item from the stack.
 *
 * @param[in] stack       Stack object.
 * @param[out] item       Variable receives the value
 *                        of the retrieved item.
 *                        Will be set to NULL if there are
 *                        no more items in the stack.
 *
 * @return 0          - No internal issues detected.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 */
int col_pop_item(struct collection_item *stack,
                 struct collection_item **item);

#endif
