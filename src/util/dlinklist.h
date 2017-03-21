/*
   Unix SMB/CIFS implementation.
   some simple double linked list macros
   Copyright (C) Andrew Tridgell 1998

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

/* To use these macros you must have a structure containing a next and
   prev pointer */

#ifndef _DLINKLIST_H
#define _DLINKLIST_H


/* hook into the front of the list */
#define DLIST_ADD(list, p) \
do { \
    if (!(list)) { \
        (list) = (p); \
        (p)->next = (p)->prev = NULL; \
    } else { \
        (list)->prev = (p); \
        (p)->next = (list); \
        (p)->prev = NULL; \
        (list) = (p); \
    } \
} while (0)

/* remove an element from a list - element doesn't have to be in list. */
#define DLIST_REMOVE(list, p) \
do { \
    if ((p) == (list)) { \
        (list) = (p)->next; \
        if (list) { \
            (list)->prev = NULL; \
        } \
    } else { \
        if ((p)->prev) { \
            (p)->prev->next = (p)->next; \
        } \
        if ((p)->next) { \
            (p)->next->prev = (p)->prev; \
        } \
    } \
    if ((p) != (list)) { \
        (p)->next = (p)->prev = NULL; \
    } \
} while (0)

/* promote an element to the top of the list */
#define DLIST_PROMOTE(list, p) \
do { \
    DLIST_REMOVE(list, p); \
    DLIST_ADD(list, p); \
} while (0)

/* hook into the end of the list - needs a tmp pointer */
#define DLIST_ADD_END(list, p, type) \
do { \
    if (!(list)) { \
        (list) = (p); \
        (p)->next = (p)->prev = NULL; \
    } else { \
        type tmp; \
        for (tmp = (list); tmp->next; tmp = tmp->next) { \
            /* no op */ \
        } \
        tmp->next = (p); \
        (p)->next = NULL; \
        (p)->prev = tmp; \
    } \
} while (0)

/* insert 'p' after the given element 'el' in a list. If el is NULL then
   this is the same as a DLIST_ADD() */
#define DLIST_ADD_AFTER(list, p, el) \
do { \
    if (!(list) || !(el)) { \
        DLIST_ADD(list, p); \
    } else { \
        p->prev = el; \
        p->next = el->next; \
        el->next = p; \
        if (p->next) { \
            p->next->prev = p; \
        } \
    } \
} while (0)

/* demote an element to the end of the list, needs a tmp pointer */
#define DLIST_DEMOTE(list, p, type) \
do { \
    DLIST_REMOVE(list, p); \
    DLIST_ADD_END(list, p, type); \
} while (0)

/* concatenate two lists - putting all elements of the 2nd list at the
   end of the first list */
#define DLIST_CONCATENATE(list1, list2, type) \
do { \
    if (!(list1)) { \
        (list1) = (list2); \
    } else { \
        type tmp; \
        for (tmp = (list1); tmp->next; tmp = tmp->next) { \
            /* no op */ \
        } \
        tmp->next = (list2); \
        if (list2) { \
            (list2)->prev = tmp; \
        } \
    } \
} while (0)

/* insert all elements from list2 after the given element 'el' in the
 * first list */
#define DLIST_ADD_LIST_AFTER(list1, el, list2, type) \
do { \
    if (!(list1) || !(el) || !(list2)) { \
        DLIST_CONCATENATE(list1, list2, type); \
    } else { \
        type tmp; \
        for (tmp = (list2); tmp->next; tmp = tmp->next) { \
            /* no op */ \
        } \
        (list2)->prev = (el); \
        tmp->next = (el)->next; \
        (el)->next = (list2); \
        if (tmp->next != NULL) { \
            tmp->next->prev = tmp; \
        } \
    } \
} while (0);

#define DLIST_FOR_EACH(p, list) \
    for ((p) = (list); (p) != NULL; (p) = (p)->next)

#define DLIST_FOR_EACH_SAFE(p, q, list) \
    for ((p) = (list), (q) = (p) != NULL ? (p)->next : NULL; \
         (p) != NULL; \
         (p) = (q), (q) = (p) != NULL ? (p)->next : NULL)

#endif /* _DLINKLIST_H */
