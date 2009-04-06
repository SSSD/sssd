/*
    COLLECTION LIBRARY

    Header file for internal structures used by the collection interface.

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

#ifndef COLLECTION_PRIV_H
#define COLLECTION_PRIV_H

/* Define real strcutures */
/* Structure that holds one property.
 * This structure should never be assumed and used directly other than
 * inside the collection.c that contains actual implementation or
 * collection_tools.c or collection_utils.c.
 */
struct collection_item {
    /* Member that contains element linking information.
     * This member should never be directly accessed by an application.
     */
    struct collection_item *next;

    /* Your implementation can assume that these members
     * will always be members of the collection_item.
     * but you should use get_item_xxx functions to get them.
     */
    char *property;
    int property_len;
    int type;
    int length;
    void *data;
};


/* Internal iterator structure - exposed for reference.
 * Never access internals of this structure in your application.
 */
struct collection_iterator {
    struct collection_item *top;
    struct collection_item **stack;
    unsigned stack_size;
    unsigned stack_depth;
    int flags;
};


/* Special type of data that stores collection header information. */
struct collection_header {
    struct collection_item *last;
    unsigned reference_count;
    unsigned count;
    unsigned class;
};

#endif

