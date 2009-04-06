/*
    COLLECTION LIBRARY

    Header file for collection interface.

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

#ifndef COLLECTION_H
#define COLLECTION_H

#ifndef EOK
#define EOK 0
#endif

#define COL_TYPE_STRING          0x00000001 /* For elements of type string the trailing 0 is counted into the length. */
#define COL_TYPE_BINARY          0x00000002
#define COL_TYPE_INTEGER         0x00000004
#define COL_TYPE_UNSIGNED        0x00000008
#define COL_TYPE_LONG            0x00000010
#define COL_TYPE_ULONG           0x00000020
#define COL_TYPE_DOUBLE          0x00000040
#define COL_TYPE_BOOL            0x00000080
#define COL_TYPE_COLLECTION      0x00000100 /* The item of this type denotes that starting element of a collection */
#define COL_TYPE_COLLECTIONREF   0x00000200 /* The item of this type denotes a pointer to already existing external collection */
#define COL_TYPE_END             0x10000000 /* Special type that denotes the end of the collection. Useful when traversing collection */
#define COL_TYPE_ANY             0x0FFFFFFF /* Special type that denotes any. Useful when traversing collection */

/* Any data we deal with can't be longer than this */
/* FIXME - make it compile time option */
#define COL_MAX_DATA    65535

/* Default class for a free form collection */
#define COL_CLASS_DEFAULT      0

/* The modes that define how one collection can be added to another */

#define COL_ADD_MODE_REFERENCE 0    /* One collection will contain a pointer of another */
#define COL_ADD_MODE_EMBED     1    /* One collection will be donated to become a part of another collection.
                                     * After that the donating connection handle should not be used or freed.
                                     * It means that it can be donated only once. The donation attempt will
                                     * fail if the collection is referenced by other collection. */
#define COL_ADD_MODE_CLONE     2    /* Creates a deep copy of a collection with its sub collections */


/* Modes how the collection is traversed */
#define COL_TRAVERSE_DEFAULT  0x00000000  /* No special flags - means it will go through all the items */
#define COL_TRAVERSE_ONELEVEL 0x00000001  /* Flag to traverse only high level - ignored it IGNORE flag is specified */
#define COL_TRAVERSE_END      0x00000002  /* Call handler once more when end of the collection is reached - good for processing nested collections */
                                          /* Flag is implied for iterator unless FLAT flag is specified */
#define COL_TRAVERSE_IGNORE   0x00000004  /* Ignore sub collections at all as if there are none */
#define COL_TRAVERSE_FLAT     0x00000008  /* Flatten the collection - FIXME - not implemented yet */
/* Additional iterator flags - not respected by traverse functions */
#define COL_TRAVERSE_SHOWSUB  0x00010000  /* Include header of the sub collections - respected by iterator */
                                          /* By default iterator returns just references and skips headers */
                                          /* Ignored if ONELEVEL flag is specified and not ignored */
                                          /* Ignored if FLAT flag is specified */
#define COL_TRAVERSE_ONLYSUB  0x00020000  /* Show header of the sub collection instead of reference - respected by iterator */
                                          /* Ignored if ONELEVEL flag is specified and not ignored */
                                          /* Ignored if FLAT flag is specified */

/* FIXME - move to event level - this does not belong to collection */
/* Time stamp property name */
#define TS_NAME         "stamp"
/* Time property name */
#define T_NAME          "time"

/* Match values */
#define COL_NOMATCH 0
#define COL_MATCH   1

/* Deapth for iteraor depth allocation block */
#define STACK_DEPTH_BLOCK   15

/* Public declaration of the private data */
#ifndef COLLECTION_PRIV_H
/* Structure that holds one property. */
struct collection_item;

/* Your implementation can assume that following members
 * will always be members of the collection_item.
 * but you should use get_item_xxx functions to get them.
 *   char *property;
 *   int property_len;
 *   int type;
 *   int length;
 *   void *data;
 */


/* Internal iterator structure */
struct collection_iterator;
#endif /* COLLECTION_PRIV_H */

/* IMPORATNAT - the collection is a set of items of different types.
 * There is always a header item in any collection that starts the collection.
 * Most of the functions in the interface (unless it is explicitly mentioned
 * otherwise) assume that the collection_item * argument points to the header element.
 * Passing in elements extracted from the middle of collection to the functions
 * that expect header elements is illegal. There might be not enough checking
 * at the moment but this will be enforced in future versions of the library.

/* IMPORTANT - To better understand how collections work imagine travel bags.
 * They usually come in different sizes and one can put a bag in a bag when they put away
 * to the shelf in a garage or closet. Collection is such bag except that you
 * can put other bags into each other even if they are not empty.
 * When you put items into a bag you do not see the contents of the bag.
 * You just hold the bag. How many other bags inside this bag you do not know.
 * But you might know that you put a "valet" somewhere there.
 * You ask the bag you hold: "find my valet and give it to me".
 * get_item function will return you the item that is you "valet".
 * You can then change something or just get information about the item you retrieved.
 * But in most cases you do not the valet itself. You want to get something from the vallet
 * or put something into it. IMO money would be an obvious choice.
 * To do this you use update_xxx_property functions.
 * There might be a bag somewhere deep and you might want to add something to it.
 * add_xxx_property_xxx functions allow you to specify sub collection you want the item
 * to be added to. If this sub collection argument is NULL top level collection is assumed.
 * The search in the collections users a dotted notation to refer to an item (or property)
 * You can search for "valet" and it will find any first instance of the "valet" in
 * your luggage. But you might have two valets. One is yours and another is your significant other's.
 * So you might say find "my.valet". It will find valet in your bad (collection) named "my".
 * This collection can be many levels deep inside other collections. You do not need to know
 * the full path to get to it. But if you have the full path you can use the fill path
 * like this "luggage.newbags.my.valet".
 * It is useful to be able to put bags into bags as well as get them out of each other.
 * When the collection is created the header keeps a reference count on how many
 * copies of the collection are known to the world. So one can put a collection into collection
 * and give up its access to it (embed) of still hold to the reference.
 * By embedding the collection the caller effectively gives up its responsibility
 * to destroy the collection after it is used.
 * By extracting reference from an internal collection the caller gains access to the
 * collection directly and thus has responsibility to destroy it after use.

/* Function that creates an named collection */
int create_collection(struct collection_item **ci,char *name,unsigned class);

/* Function that destroys a collection */
void destroy_collection(struct collection_item *ci);

/* Family of functions that add properties to an event */
/* See details about subcollection argument above. */
/* Family includes the following convinience functions: */
/* Add a string property to collection. Length should include the null terminating 0  */
int add_str_property(struct collection_item *ci,char *subcollection, char *property,char *string,int length);
/* Add a binary property to collection.  */
int add_binary_property(struct collection_item *ci,char *subcollection, char *property,void *binary_data,int length);
/* Add an int property to collection. */
int add_int_property(struct collection_item *ci,char *subcollection, char *property,int number);
/* Add an unsigned int property. */
int add_unsigned_property(struct collection_item *ci,char *subcollection, char *property,unsigned int number);
/* Add a long property. */
int add_long_property(struct collection_item *ci,char *subcollection, char *property,long number);
/* Add an unsigned long property. */
int add_ulong_property(struct collection_item *ci,char *subcollection, char *property,unsigned long number);
/* Add a double property. */
int add_double_property(struct collection_item *ci,char *subcollection, char *property,double number);
/* Add a bool property. */
int add_bool_property(struct collection_item *ci,char *subcollection, char *property,unsigned char logical);

/* Add any property */
int add_any_property(struct collection_item *ci,    /* Collection to find things in */
                     char *subcollection,           /* Subcollection */
                     char *property,                /* Name */
                     int type,                      /* Type of the passed in data */
                     void *data,                    /* Pointer to the new data */
                     int length);                   /* Length of the data. For strings should include trailing 0 */

/* The functions that add an item and immediately return you this item in the ret_ref parameter */
int add_str_property_with_ref(struct collection_item *ci,char *subcollection, char *property,char *string,int length,
                              struct collection_item **ret_ref);
int add_binary_property_with_ref(struct collection_item *ci,char *subcollection, char *property,void *binary_data,int length,
                                 struct collection_item **ret_ref);
int add_int_property_with_ref(struct collection_item *ci,char *subcollection, char *property,int number,
                              struct collection_item **ret_ref);
int add_unsigned_property_with_ref(struct collection_item *ci,char *subcollection, char *property,unsigned int number,
                                   struct collection_item **ret_ref);
int add_long_property_with_ref(struct collection_item *ci,char *subcollection, char *property,long number,
                               struct collection_item **ret_ref);
int add_ulong_property_with_ref(struct collection_item *ci,char *subcollection, char *property,unsigned long number,
                                struct collection_item **ret_ref);
int add_double_property_with_ref(struct collection_item *ci,char *subcollection, char *property,double number,
                                 struct collection_item **ret_ref);
int add_bool_property_with_ref(struct collection_item *ci,char *subcollection, char *property,unsigned char logical,
                                 struct collection_item **ret_ref);
int add_any_property_with_ref(struct collection_item *ci,char *subcollection,char *property,int type,void *data,int length,
                              struct collection_item **ret_ref);

/* FIXME - does not belong here - move to other place */
/* Function to create a timestamp */
/* Automatically adds/updates time and timestamp properties in the collection returning references */
int set_timestamp(struct collection_item *ci,
                  struct collection_item **timestr_ref,
                  struct collection_item **timeint_ref);


/* Update functions */
/* All update functions search the property using the search algorithm described at the top of the header file.
 * Use same dotted notation to specify a property.
 */
/* Update a string property in the collection. Length should include the null terminating 0  */
int update_str_property(struct collection_item *ci, char *property,int mode_flags, char *string,int length);
/* Update a binary property in the collection.  */
int update_binary_property(struct collection_item *ci, char *property,int mode_flags, void *binary_data,int length);
/* Update an int property in the collection. */
int update_int_property(struct collection_item *ci, char *property,int mode_flags, int number);
/* Update an unsigned int property. */
int update_unsigned_property(struct collection_item *ci, char *property,int mode_flags, unsigned int number);
/* Update a long property. */
int update_long_property(struct collection_item *ci, char *property,int mode_flags ,long number);
/* Update an unsigned long property. */
int update_ulong_property(struct collection_item *ci, char *property,int mode_flags, unsigned long number);
/* Update a double property. */
int update_double_property(struct collection_item *ci, char *property,int mode_flags, double number);
/* Update a double property. */
int update_bool_property(struct collection_item *ci, char *property,int mode_flags, unsigned char logical);


/* Update property in the collection */
int update_property(struct collection_item *ci,    /* Collection to find things in */
                    char *property_to_find,        /* Name to match */
                    int type,                      /* Type of the passed in data */
                    void *new_data,                /* Pointer to the new data */
                    int length,                    /* Length of the data. For strings should include trailing 0 */
                    int mode_flags);               /* How to traverse the collection  */




/* Add collection to collection */
int add_collection_to_collection(struct collection_item *ci,                   /* Collection handle to with we add another collection */
                                 char *sub_collection_name,                    /* Name of the sub collection to which
                                                                                  collection needs to be added as a property.
                                                                                  If NULL high level collection is assumed. */
                                 char *as_property,                            /* Name of the collection property.
                                                                                  If NULL, same property as the name of
                                                                                  the collection being added will be used. */
                                 struct collection_item *collection_to_add,    /* Collection to add */
                                 int mode);                                    /* How this collection needs to be added */

/* Create a deep copy of the current collection. */
/* Referenced collections of the donor are copied as sub collections. */
int copy_collection(struct collection_item **collection_copy,
                    struct collection_item *collection_to_copy,
                    char *name_to_use);

/* Signature of the callback that needs to be used when
   traversing a collection or looking for a specific item */
typedef int (*item_fn)(char *property,   /* The name of the property will be passed in this parameter. */
                       int property_len, /* Length of the property name will be passed in this parameter. */
                       int type,         /* Type of the data will be passed in this parameter */
                       void *data,       /* Pointer to the data will be passed in this parameter */
                       int length,       /* Length of data will be passed in this parameter */
                       void *custom_dat, /* Custom data will be passed in this parameter */
                       int *stop);       /* Pointer to variable where the handler can put non zero to stop processing */

/* Function to traverse the entire collection including optionally sub collections */
int traverse_collection(struct collection_item *ci,    /* Collection to traverse */
                        int mode_flags,                /* Flags defining how to traverse */
                        item_fn item_handler,          /* Handler called for each item */
                        void *custom_data);            /* Custom data passed around */

/* Search function. Looks up an item in the collection based on the property.
   Actually it is a traverse function with spacial traversing logic.
   It is the responsibility of the handler to set something in the custom data
   to indicate that the item was found.
   Function will not return error if the item is not found.
   It is the responsibility of the calling application to check
   the data passed in custom_data and see if the item was found and
   that the action was performed.
 */
int get_item_and_do(struct collection_item *ci,       /* Collection to find things in */
                    char *property_to_find,           /* Name to match */
                    int type,                         /* Type filter */
                    int mode_flags,                   /* How to traverse the collection */
                    item_fn item_handler,             /* Function to call when the item is found */
                    void *custom_data);               /* Custom data passed around */

/* Convenience function to get individual item */
/* Caller should be aware that this is not a copy of the item
 * but the pointer to actual item stored in the collection.
 * The returned pointer should never be altered or freed by caller of the function.
 * The caller should be sure that the collection does not go out of scope
 * while the pointer to its data is in use.
 * Working with the internals of the collection item structure directly
 * may cause problems in future if the internal implementation changes.
 */
int get_item(struct collection_item *ci,       /* Collection to find things in */
             char *property_to_find,           /* Name to match */
             int type,                         /* Type filter */
             int mode_flags,                   /* How to traverse the collection */
             struct collection_item **item);   /* Found item */

/* Group of functions that allows retrieving individual elements of the collection_item
 * hiding the internal implementation.
 */
char *get_item_property(struct collection_item *ci,int *property_len);
int get_item_type(struct collection_item *ci);
int get_item_length(struct collection_item *ci);
void *get_item_data(struct collection_item *ci);

/* If you want to modify the item that you got as a result of iterating through collection
 * or by calling get_item(). If you want to rename item provide a new name in the property
 * argument. If you want the data to remain unchanged use NULL as data parameter.
 * If item is a reference or collection the call will return error.
 * Previous type and data of the item is destroyed.
 */
int modify_item(struct collection_item *item,
                char *property,
                int type,
                void *data,
                int length);

/* Convenience functions that wrap modify_tem(). */
int modify_str_item(struct collection_item *item,
                    char *property,
                    char *string,
                    int length);
int modify_binary_item(struct collection_item *item,
                       char *property,
                       void *binary_data,
                       int length);
int modify_bool_item(struct collection_item *item,
                     char *property,
                     unsigned char logical);
int modify_int_item(struct collection_item *item,
                    char *property,
                    int number);
int modify_long_item(struct collection_item *item,
                     char *property,
                     long number);
int modify_ulong_item(struct collection_item *item,
                      char *property,
                      unsigned long number);
int modify_unsigned_item(struct collection_item *item,
                         char *property,
                         unsigned number);
int modify_double_item(struct collection_item *item,
                       char *property,
                       double number);

/* Delete property from the collection */
int delete_property(struct collection_item *ci,    /* Collection to find things in */
                    char *property_to_find,        /* Name to match */
                    int type,                      /* Type filter */
                    int mode_flags);               /* How to traverse the collection  */


/* Convenience function to check if the property is indeed in the collection */
int is_item_in_collection(struct collection_item *ci,  /* Collection to find things in */
                          char *property_to_find,      /* Name to match */
                          int type,                    /* Type filter */
                          int mode_flags,              /* How to traverse the collection */
                          int *found);                 /* Boolean that turns to nonzero if the match is found */


/* Get collection - get a pointer to a collection included into another collection */
/* Delete extracted collection after use to decrease reference count. */
int get_collection_reference(struct collection_item *ci,          /* High level collection */
                             struct collection_item **acceptor,   /* The pointer that will accept extracted handle */
                             char *collection_to_find);           /* Name to of the collection */

/* Get collection - if current item is a reference get a real collection from it. */
/* Delete extracted collection after use to decrease reference count. */
int get_reference_from_item(struct collection_item *ci,          /* Reference element of the high level collection */
                            struct collection_item **acceptor);   /* The pointer that will accept extracted handle */


/* Bind iterator to a collection */
int bind_iterator(struct collection_iterator **iterator,   /* The iterator to bind */
                  struct collection_item *ci,              /* Collection to bind iterator to */
                  int mode_flags);                         /* How the collection needs to be iterated */

/* Unbind the iterator from the collection */
void unbind_iterator(struct collection_iterator *iterator);

/* Get items from the collection one by one following the tree */
int iterate_collection(struct collection_iterator *iterator, struct collection_item **item);

/* Stop processing this subcollection and move to the next item in the collection 'level' levels up.*/
/* 'Level' parameter indicates how many levels up you want to jump. If 0 - call is a no op.
 * If the depth is less than requested level function will return error EINVAL.
 */
int iterate_up(struct collection_iterator *iterator, int level);

/* How deep are we relative to the top level.*/
int get_iterator_depth(struct collection_iterator *iterator, int *depth);

/* FIXME - Do we need to be able to rewind iterator? */

/* Set collection class */
int set_collection_class(struct collection_item *item,      /* Collection */
                         unsigned class);                   /* Class of the collection */

/* Get collection class */
int get_collection_class(struct collection_item *item,      /* Collection */
                         unsigned *class);                  /* Class of the collection */


/* Get collection count */
int get_collection_count(struct collection_item *item,      /* Collection */
                         unsigned *count);                  /* Count of elements in this collection.
                                                             * Each subcollection is counted as 1 element.
                                                             */

/* Convenience function to check if the collection is of the specific class */
/* In case of internal error assumes that collection is not of the right class */
int is_of_class(struct collection_item *item,      /* Collection */
                unsigned class);                   /* Class of the collection */



#endif
