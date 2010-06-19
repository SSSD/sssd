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

/**
 * @defgroup queue QUEUE interface
 *
 * Queue interface is a wrapper on top of the \ref collection
 * interface. It implements a queue using a collection object.
 *
 * @{
 */

/** @brief Class for the queue object */
#define COL_CLASS_QUEUE 40000
/** @brief All queues use this name as the name of the collection */
#define COL_NAME_QUEUE  "queue"

/**
 * @brief Create queue.
 *
 * Function that creates a queue object.
 *
 * @param[out] queue             Newly created queue object.
 *
 * @return 0          - Queue was created successfully.
 * @return ENOMEM     - No memory.
 *
 */
int col_create_queue(struct collection_item **queue);

/**
 * @brief Destroy queue.
 *
 * Function that destroys a queue object.
 *
 * @param[in] queue              Queue object to destroy.
 *
 */
void col_destroy_queue(struct collection_item *queue);

/**
 * @brief Add string to the queue.
 *
 * @param[in] queue       Queue object.
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
 * @return 0 - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_enqueue_str_property(struct collection_item *queue,
                             const char *property,
                             const char *string,
                             int length);
/**
 * @brief Add binary value to the queue.
 *
 * @param[in] queue       Queue object.
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
 * @return 0 - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_enqueue_binary_property(struct collection_item *queue,
                                const char *property,
                                void *binary_data,
                                int length);
/**
 * @brief Add integer value to the queue.
 *
 * @param[in] queue       Queue object.
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
 * @return 0 - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_enqueue_int_property(struct collection_item *queue,
                             const char *property,
                             int32_t number);
/**
 * @brief Add unsigned value to the queue.
 *
 * @param[in] queue       Queue object.
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
 * @return 0 - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_enqueue_unsigned_property(struct collection_item *queue,
                                  const char *property,
                                  uint32_t number);
/**
 * @brief Add long integer value to the queue.
 *
 * @param[in] queue       Queue object.
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
 * @return 0 - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_enqueue_long_property(struct collection_item *queue,
                              const char *property,
                              int64_t number);
/**
 * @brief Add unsigned long value to the queue.
 *
 * @param[in] queue       Queue object.
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
 * @return 0 - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_enqueue_ulong_property(struct collection_item *queue,
                               const char *property,
                               uint64_t number);
/**
 * @brief Add floating point value to the queue.
 *
 * @param[in] queue       Queue object.
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
 * @return 0 - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_enqueue_double_property(struct collection_item *queue,
                                const char *property,
                                double number);
/**
 * @brief Add Boolean value to the queue.
 *
 * @param[in] queue       Queue object.
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
 * @return 0 - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_enqueue_bool_property(struct collection_item *queue,
                              const char *property,
                              unsigned char logical);

/**
 * @brief Add value of any type to the queue.
 *
 * @param[in] queue       Queue object.
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
 * @return 0 - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 *
 */
int col_enqueue_any_property(struct collection_item *queue,
                             const char *property,
                             int type,
                             void *data,
                             int length);

/**
 * @brief Push item into the queue.
 *
 * @param[in] queue       Queue object.
 * @param[in] item        Item to push.
 *
 * @return 0          - Item was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 */
int col_enqueue_item(struct collection_item *queue,
                     struct collection_item *item);

/**
 * @brief Get item from the queue.
 *
 * @param[in] queue       Queue object.
 * @param[out] item       Variable receives the value
 *                        of the retrieved item.
 *                        Will be set to NULL if there are
 *                        no more items in the queue.
 *
 * @return 0          - No internal issues detected.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid argument.
 */
int col_dequeue_item(struct collection_item *queue,
                     struct collection_item **item);


#endif
