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

#include <stdint.h>

/** @mainpage The COLLECTION interface
 * The collection is a set of items of different types.
 *
 * To better understand how collections work imagine travel bags.
 * They usually come in different sizes and one can put a bag in a bag when
 * they put away to the shelf in a garage or closet. Collection is such bag
 * except that you can put other bags into each other even if they are not
 * empty.<br>
 * When you put items into a bag you do not see the contents of the bag.
 * You just hold the bag. How many other bags inside this bag you do not know.
 * But you might know that you put a "wallet" somewhere there.
 * You ask the bag you hold: "find my wallet and give it to me".
 * get_item function will return you the item that is your "wallet".
 * You can then change something or just get information about the item you
 * retrieved. But in most cases you do not need the wallet itself. You want to
 * get something from the wallet or put something into it. IMO money would
 * be an obvious choice. To do this you use update_xxx_property functions.<br>
 * There might be a bag somewhere deep and you might want to add something to
 * it. add_xxx_property_xxx functions allow you to specify sub collection you
 * want the item to be added to. If this sub collection argument is NULL top
 * level collection is assumed.<br>
 * The search in the collections uses a "x!y!z" notation to refer to an item (or
 * property). You can search for "wallet" and it will find any first instance of
 * the "wallet" in your luggage. But you might have two wallets. One is yours and
 * another is your significant other's. So you might say find "my!wallet".
 * It will find wallet in your bag (collection) named "my". This collection can
 * be many levels deep inside other collections. You do not need to know the
 * full path to get to it. But if you have the full path you can use the fill
 * path like this "luggage!newbags!my!wallet".<br>
 * It is useful to be able to put bags into bags as well as get them out of each
 * other. When the collection is created the header keeps a reference count on
 * how many copies of the collection are known to the world. So one can put a
 * collection into collection and give up its access to it (embed) or still hold
 * to the reference. By embedding the collection the caller effectively gives
 * up its responsibility to destroy the collection after it is used.<br>
 * By extracting reference from an internal collection the caller gains access
 * to the collection directly and thus has responsibility to destroy it after
 * use.
 *
 * Internally collection is implemented as a link list rather than a hash
 * table.
 * This makes it suitable for small (dozens of items) sets of data for which
 * the order is important. Thus the collection properties and sub collections
 * can be used to model objects like a book case. Imagine a book case that
 * consists of multiple shelves. You can perform operations like "add a new
 * shelf after second shelf" or "put a book on the 4th shelf right before
 * the book with the red cover."
 *
 * A bit of terminology:
 * - <b>collection</b> - an object implemented as a link list that holds
 *                       properties (attributes).
 * - <b>property</b>  - a named logical element of the collection.
 * - <b>item</b>    - physical element of the collection, think about it
 *                    as a node in the link list.
 * - <b>value</b> - data associated with the property.
 * - <b>type</b> - type of the data associated with a property.
 * - <b>length</b> - length of the data associated with the property.
 * - <b>sub collection</b> - collection embedded into another collection.
 *                         It is a property with the value of a special
 *                         type. The name of the property that denotes
 *                         a sub collection can be different from the name
 *                         of the collection it refers to.
 * - <b>traverse</b> - call a function that will internally iterate
 *                     through a collection and do something with its
 *                     elements.
 * - <b>iterate</b> - step through a collection yourselves.
 *
 * Characters with codes less than space in ASCII table are illegal for
 * property names.
 * Character '!' also illegal in a property or collection name and
 * reserved for "x!y!z" notation.
 *
 * There is always a header item in any collection that starts the collection.
 * Most of the functions in the interface (unless explicitly stated otherwise)
 * assume that the collection_item * argument points to the header element.
 * Passing in elements extracted from the middle of a collection to functions
 * that expect header elements is illegal. There might be not enough checking
 * at the moment but this will be enforced in future versions of the library.
 *
 */

#ifndef EOK
#define EOK 0
#endif

/**
 * @defgroup collection COLLECTION interface
 * @{
 */

/**
 * @brief Default class for a free form collection.
 */
#define COL_CLASS_DEFAULT      0

/**
 * @brief Value indicates that property is not found.
 *
 * Used in search functions.
 */
#define COL_NOMATCH 0
/**
 * @brief Value indicates that property is found.
 *
 * Used in search functions.
 */
#define COL_MATCH   1


/**
 * @defgroup coltypes Type definition constants
 * @{
 */
/**
 * @brief Indicates that property is of type "string".
 *
 * For elements of type string the length includes the trailing 0.
 */
#define COL_TYPE_STRING          0x00000001
/** @brief Indicates that property is of type "binary". */
#define COL_TYPE_BINARY          0x00000002
/** @brief Indicates that property is of type "integer". */
#define COL_TYPE_INTEGER         0x00000004
/** @brief Indicates that property is of type "unsigned". */
#define COL_TYPE_UNSIGNED        0x00000008
/** @brief Indicates that property is of type "long". */
#define COL_TYPE_LONG            0x00000010
/** @brief Indicates that property is of type "unsigned long". */
#define COL_TYPE_ULONG           0x00000020
/** @brief Indicates that property is of type "double". */
#define COL_TYPE_DOUBLE          0x00000040
/** @brief Indicates that property is of Boolean type. */
#define COL_TYPE_BOOL            0x00000080
/**
 * @brief Indicates that property is of type "collection".
 *
 * The item of this type denotes that starting element of a
 * collection.
 */
#define COL_TYPE_COLLECTION      0x00000100
/**
 * @brief Indicates that property is of type "sub collection".
 *
 * An item of this type is a pointer to an existing external
 * collection.
 */
#define COL_TYPE_COLLECTIONREF   0x00000200
/**
 * @brief Special type that denotes the end of the collection.
 *
 * Useful when traversing collections.
 */
#define COL_TYPE_END             0x10000000
/**
 * @brief Special type that denotes any property in the collection.
 *
 * Useful when traversing collection and searching for a property
 * of unknown type but known name.
 */
#define COL_TYPE_ANY             0x0FFFFFFF
/**
 * @}
 */


/**
 * @defgroup addmodes Constants defining add modes
 *
 * The following constants define how one collection can be added to another.
 *
 * @{
 */
/** @brief Add a collection into a collection as a reference */
#define COL_ADD_MODE_REFERENCE 0
/**
 * @brief Embed the collection into another collection.
 *
 * The collection will become part of another collection.
 * After this operation the handle to the collection being added
 * should not be used or freed.
 * Embedding a collection can be done only once.
 * If the collection is referenced by another collection,
 * the operation will fail.
 */
#define COL_ADD_MODE_EMBED     1
/**
 * @brief Perform a deep copy.
 *
 * Perform a deep copy of a collection with
 * all its sub collections */
#define COL_ADD_MODE_CLONE     2
/**
 * @brief Create a flattened copy.
 *
 * Create a deep copy of a collection with
 * its sub collections flattening and NOT
 * resolving duplicates.
 */
#define COL_ADD_MODE_FLAT      3
/**
 * @brief Create a flattened copy with constructed names.
 *
 * Creates a deep copy of a collection with
 * its sub collections flattening and NOT
 * resolving duplicates. Names are constructed
 * in dotted notation.
 * For example the sub collection
 * named "sub" containing "foo" and
 * "bar" will be flattened as:
 * "sub.foo", "sub.bar".
 */
#define COL_ADD_MODE_FLATDOT   4
/**
 * @}
 */


/**
 * @defgroup traverseconst Constants defining traverse modes
 *
 * The following constants define how a collection can be
 * traversed or iterated.
 *
 * Flags defined below can generally be combined with each other.
 *
 * \ref COL_TRAVERSE_FLAT, \ref COL_TRAVERSE_SHOWSUB,
 * \ref COL_TRAVERSE_ONLYSUB are mutually exclusive flags.
 * If combined together results will be unpredictable.<br>
 * <b>DO NOT MIX THEM IN ONE ITERATOR.</b>
 *
 *
 * @{
 */
/** @brief Traverse all items in the collection. */
#define COL_TRAVERSE_DEFAULT  0x00000000
/**
 * @brief Traverse only the top level.
 *
 * Traverse only top level
 * ignored if the IGNORE flag is
 * specified
 */
#define COL_TRAVERSE_ONELEVEL 0x00000001
/**
 * @brief Insert end collection marker.
 *
 * Call the handler once more when the
 * end of the collection is reached.
 * Specifying this flag would cause a traversing
 * function to call a callback once more passing
 * in a virtual property of type \ref COL_TYPE_END.
 * Good for processing nested collections.
 */
#define COL_TRAVERSE_END      0x00000002
/** @brief Ignore sub collections as if none is present. */
#define COL_TRAVERSE_IGNORE   0x00000004
/**
 * @brief Flatten the collection.
 *
 * Traversing this way would act as if
 * all the properties of sub collection are properties
 * of the root collection. The referencing properties or
 * headers of the referenced collections are skipped.
 *
 * If we think of the book case example
 * this is very useful when one wants to iterate through
 * all the books skipping information about
 * which shelf they are on.
 */
#define COL_TRAVERSE_FLAT     0x00000008
/**
 * @defgroup moreiterflag Additional iterator flags
 *
 * \note NOTE: These flags ignored by traverse functions and
 *             can be used only in the iterator.
 *
 * @{
 */
/**
 * @brief Include headers of sub collections.
 *
 * When one collection is embedded or referenced by another collection
 * there are two names we can be interested in. The name of the property
 * that defines the reference and the name of the embedded collection.
 * It is recommended that they be the same, however there may be cases
 * when the name of the referencing property and referenced collection
 * should be different. By default only the name of the referencing
 * property is returned while iterating through the collection and
 * its sub collections. Specifying this flag would cause the names
 * of the collection (header elements) be included into the iteration
 * process.
 *
 * Flag is ignored if the \ref COL_TRAVERSE_ONELEVEL flag is
 * specified and not ignored.
 * Flag is ignored is also ignored if the FLAT flag is specified. */
#define COL_TRAVERSE_SHOWSUB  0x00010000
/**
 * @brief Show sub collections.
 *
 * Show the header of the sub collection instead of the reference.
 * Flag is ignored if the \ref COL_TRAVERSE_ONELEVEL flag is
 * specified and not ignored.
 * Flag is ignored is also ignored if the FLAT flag is specified. */
#define COL_TRAVERSE_ONLYSUB  0x00020000
/**
 * @}
 */

/**
 * @}
 */

/**
 * @defgroup copyconst Constants defining copy modes
 *
 * The following constants define modes accepted by copy
 * collection function(s).
 *
 * @{
 */
/**
 * @brief Perform a deep copy.
 *
 * Referenced collections of the donor are copied as sub
 * collections.
 */
#define COL_COPY_NORMAL         0
/**
 * @brief Perform a deep flat copy.
 *
 * Collection is flattened. No name construction performed.
 */
#define COL_COPY_FLAT           1
/**
 * @brief Perform a deep flat copy constructing names.
 *
 * Collection is flattened. Names are concatenated with dot.
 */
#define COL_COPY_FLATDOT        2
/** @brief Perform a deep copy but leave references as references. */
#define COL_COPY_KEEPREF        3
/** @brief Copy only top level collection. */
#define COL_COPY_TOP            4
/**
 * @}
 */

/**
 * @defgroup sortconst Constants defining sort order
 *
 * All flags can be combined in OR operation.
 * Flags \ref COL_SORT_ASC and \ref COL_SORT_DESC are
 * mutually exclusive. If both specified the
 * collection will be sorted in the descending order.
 *
 * @{
 */
/** @brief Sort in ascending order. */
#define COL_SORT_ASC    0x00000000
/** @brief Sort in descending order. */
#define COL_SORT_DESC   0x00000001
/** @brief Sort all sub collections. */
#define COL_SORT_SUB    0x00000002
/**
 * @brief Sort only embedded sub collections.
 *
 * Ignored if \ref COL_SORT_SUB is not specified.
 */
#define COL_SORT_MYSUB  0x00000004
/**
 * @}
 */


/* Public declaration of the private data */
#ifndef COLLECTION_PRIV_H
/**
 * @struct collection_item
 * @brief Opaque structure that holds one property.
 *
 * Your implementation can assume that following members
 * will always be members of the collection_item.
 * but you should use get_item_xxx functions to get them
 * and never access internal data directly.
 *
 *   - char *property;
 *   - int property_len;
 *   - int type;
 *   - int length;
 *   - void *data;
 */
struct collection_item;
/**
 * @struct collection_iterator
 * @brief Opaque iterator structure.
 *
 * The iterator structure is used
 * when one wants to traverse the collection
 * going through its properties and optionally
 * sub collections.
 *
 * Caller should never assume
 * anything about internals of this structure.
 */
struct collection_iterator;

#endif /* COLLECTION_PRIV_H */


/**
 * @brief Create a collection
 *
 * The function will create a collection.
 * Each collection should have name and class.
 *
 * @param[out] ci     Newly allocated collection object.
 * @param[in]  name   The name is supposed to be a unique identifier of
 *                    the collection. This is useful when the collections
 *                    are stored within other collections or inside other
 *                    aggregation objects. Caller is free to use any name.
 *                    Name should consist of the ASCII characters with codes
 *                    non less than space. Exclamation mark character is
 *                    a special character and can't be used in name of
 *                    collection or property.<br>
 *                    Maximum allowed length is defined at compile time.
 *                    The default value is 64k.
 * @param[in]  cclass Class is used to relate the collection to a specific
 *                    group of the collections of the same structure.
 *                    This is very useful when you try to represent
 *                    objects using collections and you want to check if
 *                    the objects have same structure or not.
 *                    There is no predefined name space for the collection
 *                    classes. Defining classes is left to the application
 *                    developers.<br>
 *                    <b>NOTE:</b>
 *                    If you decide to build an interface using collection
 *                    library pick a range for the classes you are
 *                    going to use and make sure that they do not collide
 *                    with other interfaces built on top of the collection.
 *
 * @return 0          - Collection was created successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the collection name.
 * @return EMSGSIZE   - Collection name is too long.
 */
int col_create_collection(struct collection_item **ci,
                          const char *name,
                          unsigned cclass);

/**
 * @brief Destroy a collection
 *
 * The function will destroy a collection.
 *
 * @param[in] ci     Collection object.
 *
 */
void col_destroy_collection(struct collection_item *ci);

/**
 * @brief Copy item callback.
 *
 * Callback is used by the
 * \ref col_copy_collection_with_cb "col_copy_collection_with_cb" function.
 * Function is called after the new item is created but not yet
 * inserted into the target collection.
 * The implementer of the callback can alter the item data
 * or indicate to the caller that the item should be skipped.
 *
 * @param[in] item      Newly allocated item that will be inserted
 *                      into the new collection.
 * @param[in] ext_data  Data the application might want to
 *                      pass to the callback.
 * @param[out] skip     Pointer to a variable that indicates if the
 *                      item should be skipped or not.
 *                      Set this variable to any nonzero value
 *                      and the item will be skipped.
 * @return 0 - Success
 * @return Function can return any error code. This code
 * will be propagated through the internal functions and
 * returned to the application.
 *
 */
typedef int (*col_copy_cb)(struct collection_item *item,
                           void *ext_data,
                           int *skip);

/**
 * @brief Copy collection with data modification.
 *
 * Function create a deep copy of the current collection.
 * Calls caller provided callback before copying each item's data.
 * This is useful if the data needs to be resolved in some way.
 * The best use is when the template is copied and the values
 * in the template are resolved to the actual values.
 * The acceptable modes are defined \ref copyconst "here".
 *
 * @param[out] col_copy      Newly created collection object.
 * @param[in]  col_to_copy   Collection object that will be copied.
 * @param[in]  name_to_use   Name of the new collection.
 * @param[in]  copy_mode     How to \ref copyconst "copy".
 * @param[in]  copy_cb       Pointer to a callback \ref col_copy_cb.
 *                           Can be NULL. In this case data is copied
 *                           without modification.
 * @param[in]  ext_data      Data the application might want to
 *                           pass to the callback.
 *
 * @return 0          - Collection was copied successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - The value of some of the arguments is invalid.
 * @return Any error code returned by the callback.
 *
 */
int col_copy_collection_with_cb(struct collection_item **col_copy,
                                struct collection_item *col_to_copy,
                                const char *name_to_use,
                                int copy_mode,
                                col_copy_cb copy_cb,
                                void *ext_data);

/**
 * @brief Copy collection without data modification.
 *
 * Function creates a deep copy of the current collection.
 * It wraps the \ref col_copy_collection_with_cb function.
 * The acceptable modes are defined \ref copyconst "here".
 *
 * @param[out] col_copy      Newly created collection object.
 * @param[in]  col_to_copy   Collection object that will be copied.
 * @param[in]  name_to_use   Name of the new collection.
 * @param[in]  copy_mode     How to \ref copyconst "copy".
 *
 * @return 0          - Collection was copied successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - The value of some of the arguments is invalid.
 *
 */
int col_copy_collection(struct collection_item **col_copy,
                        struct collection_item *col_to_copy,
                        const char *name_to_use,
                        int copy_mode);

/**
 * @brief Add collection to collection.
 *
 * Function adds one collection into another
 * depending upon a specified \ref addmodes "mode".
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add collection to. If NULL the collection
 *                          is added to the root collection.
 * @param[in] as_property   Name of the property that will constitute
 *                          the reference. If NULL the name of
 *                          the collection being added will be used.
 *                          If specified the restrictions to
 *                          the name characters and length apply.
 *                          For more details about the name related
 *                          restrictions see
 *                          \ref addproperty "col_add_xxx_property"
 *                          functions.
 * @param[in] ci_to_add     Collection to add.
 * @param[in] mode          Specifies \ref addmodes "how"
 *                          the collection should be added.
 *
 * @return 0          - Collection was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - The value of some of the arguments is invalid.
 *                      The attempt to update a property which is
 *                      a reference to a collection or a collection
 *                      name.
 * @return ENOENT     - Property to update is not found.
*/
int col_add_collection_to_collection(struct collection_item *ci,
                                     const char *subcollection,
                                     const char *as_property,
                                     struct collection_item *ci_to_add,
                                     int mode);
/**
 * @brief Search Callback
 *
 * Signature of the callback that needs to be used when
 * traversing a collection or looking for a specific item.
 *
 * @param[in]  property      The name of the property will
 *                           be passed in this parameter.
 * @param[in]  property_len  Length of the property name
 *                           will be passed in this parameter.
 * @param[in]  type          Type of the data will be passed
 *                           in this parameter.
 * @param[in]  data          Pointer to the data will be passed
 *                           in this parameter.
 * @param[in]  length        Length of data will be passed in
 *                           this parameter.
 * @param[in]  custom_dat    Custom data will be passed in
 *                           this parameter.
 * @param[out] stop          Pointer to a variable where the handler
 *                           can put nonzero to stop traversing
 *                           of the collection.
 * @return 0 - Success
 * @return Function can return any error code. This code
 * will be propagated through the internal functions and
 * returned to the application.
 */
typedef int (*col_item_fn)(const char *property,
                           int property_len,
                           int type,
                           void *data,
                           int length,
                           void *custom_dat,
                           int *stop);


/**
 * @brief Traverse collection
 *
 * Function to traverse the entire collection
 * including (optionally) sub collections.
 *
 * @param[in]  ci           Collection object to traverse.
 * @param[in]  mode_flags   How to traverse.
 *                          See details \ref traverseconst "here".
 * @param[in]  item_handler Application supplied callback.
 *                          It will be called for each item
 *                          in the collection including headers.
 * @param[in]  custom_data  Custom data that application
 *                          might want to pass to the callback.
 *
 * @return 0          - Collection was traversed successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - The value of some of the arguments is invalid.
 * @return Any error code returned by the callback.
 *
 */
int col_traverse_collection(struct collection_item *ci,
                            int mode_flags,
                            col_item_fn item_handler,
                            void *custom_data);

/**
 * @brief Search and do function.
 *
 * Looks up an item in the collection based on the property and type.
 * Actually it is a traverse function with special traversing logic.
 * It traverses the whole collection but calls the supplied
 * callback only for the items that match the search criteria.
 * It is the responsibility of the caller to define how the callback
 * is going to indicate that the item it was looking for is found.
 * Function will not return error if the item is not found.
 * It is the responsibility of the calling application to check
 * the data passed in custom_data and see if the item was found and
 * that the action was performed.
 *
 * @param[in]  ci               Collection object to traverse.
 * @param[in]  property_to_find Name of the property to find.
 *                              Parameter supports "x!y"
 *                              notation.
 * @param[in]  type             Type filter. Only properties
 *                              of the given type will match.
 *                              Can be 0 to indicate that all
 *                              types should be evaluated.
 * @param[in]  mode_flags       How to traverse the collection.
 *                              See details \ref traverseconst "here".
 * @param[in]  item_handler     Function to call when the item is found.
 * @param[in]  custom_data      Custom data passed to the callback.
 *
 * @return 0          - Operation completed successfully.
 * @return EINVAL     - The value of some of the arguments is invalid.
 * @return ENOENT     - The search criteria is incorrect.
 * @return ENOMEM     - No memory.
 * @return Any error code returned by the callback.
 *
 */
int col_get_item_and_do(struct collection_item *ci,
                        const char *property_to_find,
                        int type,
                        int mode_flags,
                        col_item_fn item_handler,
                        void *custom_data);

/**
 * @brief Search function to get an item.
 *
 * Convenience function to get individual item.
 * Caller should be aware that this is not a copy of the item
 * but the pointer to actual item stored in the collection.
 * The returned pointer should never be altered or freed by caller of the function.
 * The caller should be sure that the collection does not go out of scope
 * while the pointer to its data is in use.
 * Working with the internals of the collection item structure directly
 * may cause problems in future if the internal implementation changes.
 * The caller needs to be aware that function does not return
 * error if item is not found. The caller needs to check if
 * item is not NULL to determine whether something was found.
 * Internally function is a wrapper around the \ref col_get_item_and_do
 * function.
 *
 * Use \ref getitem "item management" functions to work with the item.
 *
 * @param[in]  ci               Collection object to traverse.
 * @param[in]  property_to_find Name of the property to find.
 *                              Parameter supports "x!y"
 *                              notation.
 * @param[in]  type             Type filter. Only properties
 *                              of the given type will match.
 *                              Can be 0 to indicate that all
 *                              types should be evaluated.
 * @param[in]  mode_flags       How to traverse the collection.
 *                              See details \ref traverseconst "here".
 * @param[in]  item             Pointer to found item or NULL
 *                              if item is not found.
 *
 * @return 0          - No internal errors during search.
 * @return EINVAL     - The value of some of the arguments is invalid.
 * @return ENOENT     - The search criteria is incorrect.
 * @return ENOMEM     - No memory.
 *
 */
int col_get_item(struct collection_item *ci,
                 const char *property_to_find,
                 int type,
                 int mode_flags,
                 struct collection_item **item);

/**
 * @brief Sort collection.
 *
 * If the sub collections are included in sorting
 * each collection is sorted separately (this is not a global sort).
 * It might be dangerous to sort sub collections if
 * sub collection is not owned by the current collection.
 * If it is a reference to an external collection
 * there might be an issue. To skip the collections that
 * externally referenced use \ref COL_SORT_MYSUB flag.
 * Keep in mind that if a collection is referenced
 * more than once by other collection and that collection
 * is sorted with sub collections the referenced
 * collection will be sorted more than once.
 *
 * NOTE: Current implementation of the sorting
 * function is very simple and alternative
 * implementations might be provided later.
 *
 * @param[in]  col         Collection to sort.
 * @param[in]  cmp_flags   For more information see
 *                         \ref compflags "comparison flags".
 * @param[in]  sort_flags  For more information see
 *                         \ref sortconst "sort flags".
 *
 * @return 0          - No internal errors during sorting.
 * @return EINVAL     - The value of some of the arguments is invalid.
 *
 */
int col_sort_collection(struct collection_item *col,
                        unsigned cmp_flags,
                        unsigned sort_flags);

/**
 * @brief Delete property.
 *
 * Delete property from the collection.
 * It is recommended to use a more efficient function
 * \ref col_remove_item for the same purpose if
 * the property is unique or if the collection
 * has a known structure.
 * The col_delete_property function has some advantage only
 * if it is not known where property
 * resides and what is the structure of the collection.
 * In this case "foo!bar!baz" notation can be used in
 * the property_to_find argument to find and delete
 * the property "baz" that is in a sub collection "bar"
 * which is in turn a part of a collection "foo".
 *
 * @param[in]  ci                Collection to delete property from.
 * @param[in]  property_to_find  Property to delete.
 * @param[in]  type              Use type if names are not unique
 *                               and you know the type of the value
 *                               you want to delete. Otherwise set to 0.
 * @param[in]  mode_flags        The flags define how the collection
 *                               should be searched. For more information
 *                               see \ref traverseconst "traverse constants".
 *
 * @return 0          - Property was deleted successfully.
 * @return EINVAL     - The value of some of the arguments is invalid.
 * @return ENOMEM     - No memory.
 * @return ENOENT     - Property not found.
 *
 */
int col_delete_property(struct collection_item *ci,
                        const char *property_to_find,
                        int type,
                        int mode_flags);

/**
 * @brief Is property in the collection?
 *
 * Convenience function to check if the property
 * is indeed in the collection.
 *
 * @param[in]  ci                Collection to search.
 * @param[in]  property_to_find  Property to find.
 * @param[in]  type              Use type if names are not unique
 *                               and you know the type of the value
 *                               you want to check. Otherwise set to 0.
 * @param[in]  mode_flags        The flags define how the collection
 *                               should be searched. For more information
 *                               see \ref traverseconst "traverse constants".
 * @param[out] found             The variable that will receive the result
 *                               of the search.
 *                               COL_NOMATCH - if not found
 *                               COL_MATCH if found
 *
 * @return 0          - Search completed successfully.
 * @return EINVAL     - The value of some of the arguments is invalid.
 * @return ENOMEM     - No memory.
 *
 */
int col_is_item_in_collection(struct collection_item *ci,
                              const char *property_to_find,
                              int type,
                              int mode_flags,
                              int *found);

/**
 * @brief Get a reference to a collection
 *
 * Get a pointer to a collection included into another collection.
 * If the col_to_find is NULL function returns a reference
 * to the top level collection.
 * Delete extracted collection after use to decrease reference count.
 *
 * @param[in]  ci                Collection to search.
 * @param[out] acceptor          Variable that accepts pointer to
 *                               an extracted collection.
 *                               Use \ref col_destroy_collection to
 *                               free returned object reference after
 *                               use.
 * @param[in]  col_to_find       Collection to find.
 *                               "foo!bar!baz" notation can be used.
 *
 * @return 0          - Success.
 * @return EINVAL     - The value of some of the arguments is invalid.
 * @return ENOMEM     - No memory.
 */
int col_get_collection_reference(struct collection_item *ci,
                                 struct collection_item **acceptor,
                                 const char *col_to_find);

/**
 * @brief Get a reference from the item
 *
 * Get a pointer to a collection from a current item
 * if current item is a reference to the collection.
 * If current item is not a reference to a collection an error
 * will be returned.
 * Delete extracted collection after use to decrease reference count.
 *
 * @param[in]  item              Item to extract the reference from.
 * @param[out] acceptor          Variable that accepts pointer to
 *                               an extracted collection.
 *                               Use \ref col_destroy_collection to
 *                               free returned object reference after
 *                               use.
 *
 * @return 0          - Success.
 * @return EINVAL     - The value of some of the arguments is invalid.
 */
int col_get_reference_from_item(struct collection_item *item,
                                struct collection_item **acceptor);



/**
 * @brief Get collection class.
 *
 * The classes of the collections can be used to convey information
 * about the collection's internal structure.
 * Some interfaces built on top of the collection might
 * impose restrictions on the collection structure.
 * For example the interface can decide that it is going
 * to deal with the collections that do not have sub collections
 * and elements of the collections are always only strings.
 * So the interface will define a class of the collection
 * and create a function that would take the strings and create
 * such a collection. Then other functions of that interface
 * would check if the provided collection is of the specified class.
 * If not the interface would reject the collection right away.
 * If the collection is of the valid class the interface might
 * call the validation function to make sure that this is really
 * the case however it needs to validate it only once and lower level
 * functions can rely on the class value of the collection
 * without performing duplicate validation.
 *
 * @param[in]   ci                 Collection object.
 * @param[out]  cclass             Variable that will receive
 *                                 the value of the class.
 * @return 0          - Success.
 * @return EINVAL     - The value of some of the arguments is invalid.
 *
 */
int col_get_collection_class(struct collection_item *ci,
                             unsigned *cclass);

/**
 * @brief Set collection class.
 *
 * Sometimes as a result of the collection modification
 * the class of the collection can change.
 *
 * @param[in]   ci                 Collection object.
 * @param[in]   cclass             New class value.
 *
 * @return 0          - Success.
 * @return EINVAL     - The value of some of the arguments is invalid.
 *
 */
int col_set_collection_class(struct collection_item *ci,
                             unsigned cclass);

/**
 * @brief Get count of the elements.
 *
 * It is useful to know how many items are there in the collection.
 *
 * @param[in]   ci                 Collection object.
 * @param[out]  count              Variable will receive the value
 *                                 of the number of the items in
 *                                 the collection. Collection
 *                                 header or references to external
 *                                 collections are counted as well.
 *                                 This means that every collection
 *                                 has at least one item - the header.
 *
 * @return 0          - Success.
 * @return EINVAL     - The value of some of the arguments is invalid.
 *
 */
int col_get_collection_count(struct collection_item *ci,
                             unsigned *count);


/**
 * @brief Check the class of collection.
 *
 * Convenience function to check if the collection is of the specific class.
 * In case of internal error assumes that collection is not of the right class.
 *
 * @param[in]   ci                 Collection object.
 * @param[in]   cclass             Class value to compare to to.
 *
 * @return 0          - If any internal error or classes do not match.
 * @return 1          - No error and classes do match.
 *
 */
int col_is_of_class(struct collection_item *ci,
                    unsigned cclass);


/**
 * @defgroup addproperty Add property functions
 *
 * Functions in this section add properties to a collection.
 *
 * All the functions in this section add a property of the specified
 * type to the collection object.
 * They are convenience wrappers around the col_insert_xxx_property
 * functions.
 * They always append property to the end of the collection.
 *
 * Common parameters for these functions are:
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 * @{
 */

/**
 * @brief Add a string property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] string Null terminated string to add.
 * @param[in] length Length of the string. Should include the length
 *                   of the terminating 0.
 *                   If the length is shorter than the full string
 *                   the string will be truncated. If the length is
 *                   longer than the actual string there might be
 *                   garbage at end of the actual string.
 *                   Library will always properly NULL terminate
 *                   the string at the given position dictated
 *                   by length but in no way will inspect the validity
 *                   of the passed in data. This is left to the calling
 *                   application.
 *
 * @return 0 - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_str_property(struct collection_item *ci,
                         const char *subcollection,
                         const char *property,
                         const char *string,
                         int length);

/**
 * @brief Add a binary property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] binary_data   Data to add.
 * @param[in] length        Length of the data.
 *
 * @return 0 - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_binary_property(struct collection_item *ci,
                            const char *subcollection,
                            const char *property,
                            void *binary_data,
                            int length);

/**
 * @brief Add an integer property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] number        Integer value to add. Value is signed.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_int_property(struct collection_item *ci,
                         const char *subcollection,
                         const char *property,
                         int32_t number);

/**
 * @brief Add an unsigned integer property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] number        Unsigned integer value to add.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_unsigned_property(struct collection_item *ci,
                              const char *subcollection,
                              const char *property,
                              uint32_t number);

/**
 * @brief Add an long property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] number        Long integer value to add. Value is signed.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_long_property(struct collection_item *ci,
                          const char *subcollection,
                          const char *property,
                          int64_t number);

/**
 * @brief Add an unsigned long property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] number        Unsigned long integer value to add.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_ulong_property(struct collection_item *ci,
                           const char *subcollection,
                           const char *property,
                           uint64_t number);

/**
 * @brief Add a property of type double to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] number        Floating point value.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_double_property(struct collection_item *ci,
                            const char *subcollection,
                            const char *property,
                            double number);
/**
 * @brief Add a Boolean property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] logical       Boolean value. 0 - false, nonzero - true.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_bool_property(struct collection_item *ci,
                          const char *subcollection,
                          const char *property,
                          unsigned char logical);


/**
 * @brief Add a property of a specified type to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] type          See type definitions \ref coltypes "here".
 * @param[in] data          Data to add.
 * @param[in] length        Length of the data.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_any_property(struct collection_item *ci,
                         const char *subcollection,
                         const char *property,
                         int type,
                         void *data,
                         int length);

/**
 * @defgroup addprop_withref Add properties with reference
 *
 * Family of functions that add properties to a collection
 * and return reference to an item that holds
 * a newly created property.
 *
 * All the functions in this section append a property of
 * the specified type to the collection object.
 *
 * Parameters for the functions and return values are the same
 * as for the \ref addproperty "col_add_xxx_property" functions.
 * The only difference is that these functions have one additional
 * argument:
 *
 * @param[out] ret_ref  Reference to the newly added item that
 *                      holds the property.
 *
 * @{
 */

/**
 * @brief Add a string property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] string        Null terminated string to add.
 * @param[in] length        Length of the string. Should include the length
 *                          of the terminating 0.
 *                          If the length is shorter than the full string
 *                          the string will be truncated. If the length is
 *                          longer than the actual string there might be
 *                          garbage at end of the actual string.
 *                          Library will always properly NULL terminate
 *                          the string at the given position dictated
 *                          by length but in no way will inspect the validity
 *                          of the passed in data. This is left to the calling
 *                          application.
 * @param[out] ret_ref      Reference to the newly added item that
 *                          holds the property.
 *
 * @return 0 - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_str_property_with_ref(struct collection_item *ci,
                                  const char *subcollection,
                                  const char *property,
                                  char *string, int length,
                                  struct collection_item **ret_ref);

/**
 * @brief Add a binary property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] binary_data   Data to add.
 * @param[in] length        Length of the data.
 * @param[out] ret_ref      Reference to the newly added item that
 *                          holds the property.
 *
 * @return 0 - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_binary_property_with_ref(struct collection_item *ci,
                                     const char *subcollection,
                                     const char *property,
                                     void *binary_data, int length,
                                     struct collection_item **ret_ref);

/**
 * @brief Add an integer property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] number        Integer value to add. Value is signed.
 * @param[out] ret_ref      Reference to the newly added item that
 *                          holds the property.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_int_property_with_ref(struct collection_item *ci,
                                  const char *subcollection,
                                  const char *property, int32_t number,
                                  struct collection_item **ret_ref);

/**
 * @brief Add an unsigned integer property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] number        Unsigned integer value to add.
 * @param[out] ret_ref      Reference to the newly added item that
 *                          holds the property.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_unsigned_property_with_ref(struct collection_item *ci,
                                       const char *subcollection,
                                       const char *property, uint32_t number,
                                       struct collection_item **ret_ref);

/**
 * @brief Add an long property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] number        Long integer value to add. Value is signed.
 * @param[out] ret_ref      Reference to the newly added item that
 *                          holds the property.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_long_property_with_ref(struct collection_item *ci,
                                   const char *subcollection,
                                   const char *property, int64_t number,
                                   struct collection_item **ret_ref);

/**
 * @brief Add an unsigned long property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] number        Unsigned long integer value to add.
 * @param[out] ret_ref      Reference to the newly added item that
 *                          holds the property.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_ulong_property_with_ref(struct collection_item *ci,
                                    const char *subcollection,
                                    const char *property, uint64_t number,
                                    struct collection_item **ret_ref);

/**
 * @brief Add a property of type double to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] number        Floating point value.
 * @param[out] ret_ref      Reference to the newly added item that
 *                          holds the property.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_double_property_with_ref(struct collection_item *ci,
                                     const char *subcollection,
                                     const char *property, double number,
                                     struct collection_item **ret_ref);

/**
 * @brief Add a Boolean property to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] logical       Boolean value. 0 - false, nonzero - true.
 * @param[out] ret_ref      Reference to the newly added item that
 *                          holds the property.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_bool_property_with_ref(struct collection_item *ci,
                                   const char *subcollection,
                                   const char *property, unsigned char logical,
                                   struct collection_item **ret_ref);


/**
 * @brief Add a property of a specified type to a collection.
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 * @param[in] type          See type definitions \ref coltypes "here".
 * @param[in] data          Data to add.
 * @param[in] length        Length of the data.
 * @param[out] ret_ref      Reference to the newly added item that
 *                          holds the property.
 *
 * @return 0          - Property was added successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection is not found.
 *
 */
int col_add_any_property_with_ref(struct collection_item *ci,
                                  const char *subcollection,
                                  const char *property,
                                  int type, void *data, int length,
                                  struct collection_item **ret_ref);

/**
 * @}
 */

/**
 * @}
 */

/**
 * @defgroup insertproperty Insert property functions
 *
 * Functions in this section insert properties into a collection
 * at a specified position.
 *
 * Common parameters for these functions are:
 *
 * @param[in] ci            Root collection object.
 * @param[in] subcollection Name of the inner collection to
 *                          add property to. If NULL the property
 *                          is added to the root collection.
 * @param[in] disposition   Defines relation point.
 *                          For more information see
 *                          \ref dispvalues "disposition defines".
 * @param[in] refprop       Property to relate to
 * @param[in] idx           Index (see comments below).
 * @param[in] flags         Flags that control naming issues.
 * @param[in] property      Name of the property.<br>
 *                          Name should consist of the ASCII characters
 *                          with codes non less than space.
 *                          Exclamation mark character is
 *                          a special character and can't be used
 *                          in name of collection or property.<br>
 *                          Maximum allowed length is defined at compile time.
 *                          The default value is 64k.
 *
 *
 * Other arguments are the same as the arguments for the
 * \ref addproperty "col_add_xxx_property" functions.
 *
 * @return 0          - Property was insterted successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - Invalid characters in the property name.
 *                      Value argument is invalid in some way.
 * @return EMSGSIZE   - Property name is too long.
 * @return ENOENT     - Sub collection or property to relate to is not found.
 * @return EEXIST     - Property with given name already exists.
 *                      This error is returned if collection
 *                      should hold unique names.
 *                      For more information see description of the
 *                      "flags" argument.
 * @return ENOSYS     - Flag or disposition value is not implemented.
 * @{
 */
/** @brief Insert a string property. */
int col_insert_str_property(struct collection_item *ci,
                            const char *subcollection,
                            int disposition,
                            const char *refprop,
                            int idx,
                            unsigned flags,
                            const char *property,
                            const char *string,
                            int length);

/** @brief Insert a binary property. */
int col_insert_binary_property(struct collection_item *ci,
                               const char *subcollection,
                               int disposition,
                               const char *refprop,
                               int idx,
                               unsigned flags,
                               const char *property,
                               void *binary_data,
                               int length);

/** @brief Insert an integer property. */
int col_insert_int_property(struct collection_item *ci,
                            const char *subcollection,
                            int disposition,
                            const char *refprop,
                            int idx,
                            unsigned flags,
                            const char *property,
                            int32_t number);

/** @brief Insert an unsigned property. */
int col_insert_unsinged_property(struct collection_item *ci,
                                 const char *subcollection,
                                 int disposition,
                                 const char *refprop,
                                 int idx,
                                 unsigned flags,
                                 const char *property,
                                 uint32_t number);

/** @brief Insert a long property. */
int col_insert_long_property(struct collection_item *ci,
                             const char *subcollection,
                             int disposition,
                             const char *refprop,
                             int idx,
                             unsigned flags,
                             const char *property,
                             int64_t number);

/** @brief Insert an unsigned long property. */
int col_insert_ulong_property(struct collection_item *ci,
                              const char *subcollection,
                              int disposition,
                              const char *refprop,
                              int idx,
                              unsigned flags,
                              const char *property,
                              uint64_t number);

/** @brief Insert a property with a floating point value. */
int col_insert_double_property(struct collection_item *ci,
                               const char *subcollection,
                               int disposition,
                               const char *refprop,
                               int idx,
                               unsigned flags,
                               const char *property,
                               double number);

/** @brief Insert a property with a Boolean value. */
int col_insert_bool_property(struct collection_item *ci,
                             const char *subcollection,
                             int disposition,
                             const char *refprop,
                             int idx,
                             unsigned flags,
                             const char *property,
                             unsigned char logical);

/** @brief Insert a string property and get back a reference. */
int col_insert_str_property_with_ref(struct collection_item *ci,
                                     const char *subcollection,
                                     int disposition,
                                     const char *refprop,
                                     int idx,
                                     unsigned flags,
                                     const char *property,
                                     const char *string,
                                     int length,
                                     struct collection_item **ret_ref);

/** @brief Insert a binary property and get back a reference. */
int col_insert_binary_property_with_ref(struct collection_item *ci,
                                        const char *subcollection,
                                        int disposition,
                                        const char *refprop,
                                        int idx,
                                        unsigned flags,
                                        const char *property,
                                        void *binary_data,
                                        int length,
                                        struct collection_item **ret_ref);

/** @brief Insert an integer property and get back a reference. */
int col_insert_int_property_with_ref(struct collection_item *ci,
                                     const char *subcollection,
                                     int disposition,
                                     const char *refprop,
                                     int idx,
                                     unsigned flags,
                                     const char *property,
                                     int32_t number,
                                     struct collection_item **ret_ref);

/** @brief Insert an unsigned property and get back a reference. */
int col_insert_unsinged_property_with_ref(struct collection_item *ci,
                                          const char *subcollection,
                                          int disposition,
                                          const char *refprop,
                                          int idx,
                                          unsigned flags,
                                          const char *property,
                                          uint32_t number,
                                          struct collection_item **ret_ref);

/** @brief Insert a long property and get back a reference. */
int col_insert_long_property_with_ref(struct collection_item *ci,
                                      const char *subcollection,
                                      int disposition,
                                      const char *refprop,
                                      int idx,
                                      unsigned flags,
                                      const char *property,
                                      int64_t number,
                                      struct collection_item **ret_ref);

/** @brief Insert an unsigned long property and get back a reference. */
int col_insert_ulong_property_with_ref(struct collection_item *ci,
                                       const char *subcollection,
                                       int disposition,
                                       const char *refprop,
                                       int idx,
                                       unsigned flags,
                                       const char *property,
                                       uint64_t number,
                                       struct collection_item **ret_ref);

/**
 * @brief Insert a property with a floating
 * point value and get back a reference.
 */
int col_insert_double_property_with_ref(struct collection_item *ci,
                                        const char *subcollection,
                                        int disposition,
                                        const char *refprop,
                                        int idx,
                                        unsigned flags,
                                        const char *property,
                                        double number,
                                        struct collection_item **ret_ref);

/** @brief Insert a property with a Boolean value and get back a reference. */
int col_insert_bool_property_with_ref(struct collection_item *ci,
                                      const char *subcollection,
                                      int disposition,
                                      const char *refprop,
                                      int idx,
                                      unsigned flags,
                                      const char *property,
                                      unsigned char logical,
                                      struct collection_item **ret_ref);

/** @brief Insert property of any type and get back a reference. */
int col_insert_property_with_ref(struct collection_item *ci,
                                 const char *subcollection,
                                 int disposition,
                                 const char *refprop,
                                 int idx,
                                 unsigned flags,
                                 const char *property,
                                 int type,
                                 const void *data,
                                 int length,
                                 struct collection_item **ret_ref);


/**
 * @}
 */

/**
 * @defgroup updateproperty Update property functions
 *
 * Functions in this section update properties in a collection.
 *
 * All update functions search the property using the
 * internal traverse function.
 * Use same "x!y" notation to specify a property.
 * For more details about the search logic see
 * \ref col_get_item_and_do function.
 *
 * The existing value of the property is destroyed and lost.
 *
 * It is not possible to rename the property using these functions.
 * To do more advanced modifications see \ref col_modify_item function
 * and \ref modwrap "item modification wrappers" .
 *
 * Common parameters for these functions are:
 *
 * @param[in] ci            Root collection object.
 * @param[in] property      Name of the property.
 * @param[in] mode_flags    Specify how the collection
 *                          should to be traversed.
 *
 * The rest of the arguments specify the new values for
 * the property. For more details about these arguments see
 * the description of the \ref addproperty "col_add_xxx_property"
 * corresponding function.
 *
 *
 * @return 0          - Property was updated successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - The value of some of the arguments is invalid.
 *                      The attempt to update a property which is
 *                      a reference to a collection or a collection
 *                      name.
 * @return ENOENT     - Property to update is not found.
 *
 * @{
 */
/**
 * Update a property with a string value.
 * Length should include the terminating 0.
 */
int col_update_str_property(struct collection_item *ci,
                            const char *property,
                            int mode_flags,
                            char *string,
                            int length);
/**
 * Update a property with a binary value.
 */
int col_update_binary_property(struct collection_item *ci,
                               const char *property,
                               int mode_flags,
                               void *binary_data,
                               int length);
/**
 * Update a property with an integer value.
 */
int col_update_int_property(struct collection_item *ci,
                            const char *property,
                            int mode_flags,
                            int32_t number);
/**
 * Update a property with an unsigned value.
 */
int col_update_unsigned_property(struct collection_item *ci,
                                 const char *property,
                                 int mode_flags,
                                 uint32_t number);
/**
 * Update a property with a long value.
 */
int col_update_long_property(struct collection_item *ci,
                             const char *property,
                             int mode_flags,
                             int64_t number);
/**
 * Update a property with an unsigned long value.
 */
int col_update_ulong_property(struct collection_item *ci,
                              const char *property,
                              int mode_flags,
                              uint64_t number);
/**
 * Update a property with a floating point value.
 */
int col_update_double_property(struct collection_item *ci,
                               const char *property,
                               int mode_flags,
                               double number);
/**
 * Update a property with a Boolean value.
 */
int col_update_bool_property(struct collection_item *ci,
                             const char *property,
                             int mode_flags,
                             unsigned char logical);

/**
 * Update a property with a value by specifying type
 * and value. See definitions of the type constants
 * \ref coltypes "here".
 * All other col_update_xxx_property functions are wrappers
 * around this one.
 */
int col_update_property(struct collection_item *ci,
                        const char *property,
                        int type,
                        void *new_data,
                        int length,
                        int mode_flags);


/**
 * @}
 */

/**
 * @defgroup getitem Item management
 *
 * Group of functions that allows retrieving individual elements
 * of the \ref collection_item hiding the internal implementation.
 *
 * @{
 */

/**
 * @defgroup compflags Comparison flags
 *
 * This section describes the flags used in item comparison.
 *
 * Flags:
 * - \ref COL_CMPIN_PROP_EQU
 * - \ref COL_CMPIN_PROP_BEG
 * - \ref COL_CMPIN_PROP_MID
 * - \ref COL_CMPIN_PROP_END
 *
 * are mutually exclusive.
 *
 * All other flags can be provided in any combination.
 *
 * @{
 */
/** @brief Properties should be exactly equal */
#define COL_CMPIN_PROP_EQU    0x000000004
/** @brief Properties should start with the same substring. */
#define COL_CMPIN_PROP_BEG    0x000000005
/** @brief One property should be a substring of another. */
#define COL_CMPIN_PROP_MID    0x000000006
/** @brief Properties should have the same substring at the end. */
#define COL_CMPIN_PROP_END    0x000000007

/**
 * @brief Make sure that there is a dot.
 *
 * Useful with _BEG, _MID and _END flags to check that the there is
 * a dot (if present) in the right place (before, after or both).
 * For example the first item is named "foo.bar" and the second
 * is "bar". Using _END the "bar" will be found but if _DOT flag is
 * used too the function will also check if there was a "." before the found
 * string in this case.
 * Ignored in case of _EQU.
 */
#define COL_CMPIN_PROP_DOT     0x000000008

/** @brief Compare property lengths. */
#define COL_CMPIN_PROP_LEN     0x000000010

/** @brief Compare types. */
#define COL_CMPIN_TYPE         0x000000020

/** @brief Compare data lengths. */
#define COL_CMPIN_DATA_LEN     0x000000040

/**
 * @brief Compare data.
 *
 * Compares data (up to the length of the second one)
 * if type is the same. If type is different
 * function will assume data is different
 * without performing actual comparison.
 */
#define COL_CMPIN_DATA         0x000000080

/**
 * @}
 */


/**
 * @defgroup outflags Comparison results flags
 *
 * This section describes the flags set as a result of
 * a comparison operation.
 *
 * @{
 */

/**
 * @brief Second item's property is greater.
 *
 * If _EQU was specified and the property of the second item
 * is greater the following bit will be set
 */
#define COL_CMPOUT_PROP_STR    0x00000001

/**
 * @brief Second item's property is longer.
 *
 * If told to compare property lengths
 * and the second is longer this bit will be set.
 */
#define COL_CMPOUT_PROP_LEN    0x00000002
/**
 * @brief Second item's data is longer.
 *
 * If told to compare data lengths
 * and second is longer this bit will be set
 */
#define COL_CMPOUT_DATA_LEN    0x00000004
/**
 * @brief Second item's data is greater.
 *
 * If told to compare data
 * and types are the same, then
 * if the second one is greater this bit will
 * be set. If data is binary flag is never set.
 */
#define COL_CMPOUT_DATA    0x00000008

/**
 * @}
 */

/**
 * @defgroup dispvalues Disposition constants
 *
 * Possible dispositions for insert, extract and delete function(s).
 * Not all of these dispositions are implemented day one.
 * If disposition is not implemented the function
 * will return error ENOSYS.
 *
 * Other dispositions might be possible in future.
 *
 * @{
 */
/**
 * @brief Relate to the end of the collection
 *
 * For "insert":
 * - Add property to the end of the collection.
 *
 * For "extract" or "delete":
 * - Extract or delete the last property in the collection.
 */
#define COL_DSP_END             0
/**
 * @brief Relate to the beginning of the collection
 *
 * For "insert":
 * - Add property to the beginning of the collection right after the header.
 *
 * For "extract" or "delete":
 * - Extract or delete the first property in the collection.
 *   This is the one right after the header.
 */
#define COL_DSP_FRONT           1
/**
 * @brief Before the given property
 *
 * For "insert":
 * - Add property before the referenced property.
 *
 * For "extract" or "delete":
 * - Extract or delete the property that stands
 *   before the referenced property in the collection.
 *   If given property is the first in the collection
 *   ENOENT is returned.
 */
#define COL_DSP_BEFORE          2
/**
 * @brief After the given property
 *
 * For "insert":
 * - Add property immediately the referenced property.
 *
 * For "extract" or "delete":
 * - Extract or delete the property that stands
 *   after the referenced property in the collection.
 *   If given property is the last in the collection
 *   ENOENT is returned.
 */
#define COL_DSP_AFTER           3
/**
 * @brief Use index
 *
 * For "insert":
 * - The COL_DSP_INDEX adds the item as N-th item after header in the list.
 *   Index is zero based.
 *   If there are less than N items in the list the item is added to the end.
 *   The index value of 0 means that the item will be added immediately
 *   after the header. Index of 1 will mean that it is added after first data
 *   item and so on.
 *
 * For "extract" or "delete":
 * - In case of extraction or deletion the N-th item of the collection
 *   will be extracted or deleted.
 *   Index is zero based.
 *   If there are less than N+1 items in the list the function will return ENOENT.
 *
 */
#define COL_DSP_INDEX           4
/**
 * @brief Use first among duplicates
 *
 * This mode applies only to the list of duplicate
 * properties that are going one after another.
 *
 * For "insert":
 * - Add property as a first dup of the given property.
 *   The property name is taken from the item
 *   and the value refprop is ignored.
 *
 * For "extract" or "delete":
 * - Delete or extract first duplicate property.
 *   The property name is taken from the refprop.
 *   The property will be extracted or deleted if found
 *   regardless of whether there are any duplicates or not.
 */
#define COL_DSP_FIRSTDUP        5
/**
 * @brief Use last among duplicates
 *
 * This mode applies only to the list of duplicate
 * properties that are going one after another.
 *
 * For "insert":
 * - Add property as the last dup of the given property.
 *   The property name is taken from the item
 *   and the value refprop is ignored.
 *
 * For "extract" or "delete":
 * - Delete or extract the last duplicate of the property.
 *   The property name is taken from the refprop.
 *   Extracts or deletes last duplicate property in the uninterrupted
 *   sequence of properties with the same name.
 *   The property will be extracted or deleted if found
 *   regardless of whether there are any duplicates or not.
 */
#define COL_DSP_LASTDUP         6
/**
 * @brief Use N-th among duplicates
 *
 * This mode applies only to the list of duplicate
 * properties that are going one after another.
 *
 * For "insert":
 * - Add property as a N-th dup of the given property.
 *   The property name is taken from the item
 *   and the value refprop is ignored.
 *   Index is zero based.
 *   The COL_DSP_NDUP is used in case of the multi value property
 *   to add a new property with the same name into specific place
 *   in the list of properties with the same name.
 *   The index of 0 will mean to add the property before the first
 *   instance of the property with the same name.
 *   If the property does not exist ENOENT will be returned.
 *   If the index is greater than the last property with the same
 *   name the item will be added immediately after last
 *   property with the same name.
 *
 * For "extract" or "delete":
 * - Delete or extract N-th duplicate property.
 *   Index is zero based.
 *   The property name is taken from the refprop.
 *   If index is greater than number of duplicate
 *   properties in the sequence ENOENT is returned.
 *
 */
#define COL_DSP_NDUP            7
/**
 * @}
 */

/**
 * @defgroup insflags Flags used in insert item functions
 *
 * Flags that can be used with insert functions.
 *
 * In future can more flags might be added.
 *
 * <b>NOTE:</b> Use of the duplicate checking flags is costly
 * since it requires a forward look up of the whole
 * collection before the item is inserted.
 * Do not use it until it is absolutely necessary.
 *
 * @{
 */
/** @brief This is the default mode - no dup checks on insert */
#define COL_INSERT_NOCHECK      0
/**
 * @brief Check for duplicate name and overwrite.
 * Position arguments are ignored.
 */
#define COL_INSERT_DUPOVER      1
/**
 * @brief Check for duplicate name and type and overwrite.
 * Position arguments are ignored.
 */
#define COL_INSERT_DUPOVERT     2
/** @brief Return error EEXIST if the entry with the same name exists. */
#define COL_INSERT_DUPERROR     3
/**
 * @brief Return error EEXIST if the entry
 * with the same name and type exists.
 */
#define COL_INSERT_DUPERRORT    4
/** @brief Check for duplicates, overwrite,
 * extract and then move to the position requested.
 */
#define COL_INSERT_DUPMOVE      5
/** @brief Check for duplicate name and type, overwrite,
 * extract and then move to the position requested.
 */
#define COL_INSERT_DUPMOVET     6

/**
 * @}
 */



/**
 * @brief Get item property.
 *
 * Get name of the property from the item. If the item is a header
 * the name of the property is the name of the collection.
 * The element that denotes the collection header has
 * type \ref COL_TYPE_COLLECTION.
 * Optionally the property length can be retrieved too.
 *
 * @param[in]  ci               Item to get property from.
 *                              If item is invalid the function
 *                              will cause a segment violation.
 * @param[out] property_len     If not NULL the variable
 *                              will receive the length
 *                              of the property not counting
 *                              terminating 0.
 *
 * @return Property name.
 *
 */
const char *col_get_item_property(struct collection_item *ci,
                                  int *property_len);

/**
 * @brief Get item type.
 *
 * Get type from the item.
 *
 * @param[in]  ci               Item to get type from.
 *                              If item is invalid the function
 *                              will cause a segment violation.
 *
 * @return Item type.
 *
 */
int col_get_item_type(struct collection_item *ci);

/**
 * @brief Get value length from the item.
 *
 * Get value length from the item. For strings this includes
 * NULL terminating zero.
 *
 * @param[in]  ci               Item to get value length from.
 *                              If item is invalid the function
 *                              will cause a segment violation.
 *
 * @return Value length.
 *
 */
int col_get_item_length(struct collection_item *ci);

/**
 * @brief Get property value from the item.
 *
 * Get property value from the item.
 *
 * @param[in]  ci               Item to get value from.
 *                              If item is invalid the function
 *                              will cause a segment violation.
 *
 * @return Property value.
 *
 */
void *col_get_item_data(struct collection_item *ci);

/**
 * @brief Get hash value from the item.
 *
 * Get hash value from the item. The hash value is
 * 64-bit hash created from the property name.
 * It is done to optimize the searches.
 *
 * This function is exposed for some corner cases
 * that require low level operations, for example
 * for custom search callbacks to take advantage
 * of the internal hashes.
 *
 * @param[in]  ci               Item to get hash from.
 *                              If item is invalid the function
 *                              will cause a segment violation.
 *
 * @return Hash value.
 *
 */
uint64_t col_get_item_hash(struct collection_item *ci);

/**
 * @brief Calculate hash value for a string.
 *
 * Calculates hash value of the string using internal hashing
 * algorithm. Populates "length" with length
 * of the string not counting 0.
 *
 * This function is useful if you want to build a custom
 * search or collection sorting function.
 *
 * @param[in]  string   String to hash. If NULL hash is 0.
 * @param[in]  sub_len  If it is greater than zero
 *                      it is used to count how many
 *                      characters from string should
 *                      be included into hash calculation.
 *                      If 0 the actual length of the string
 *                      is determined and used.
 * @param[out]  length  Will receive the calculated length
 *                      of the provided string.
 *                      Length argument can be NULL.
 *
 * @return Hash value.
 */
uint64_t col_make_hash(const char *string, int sub_len, int *length);


/**
 * @brief Compare two items.
 *
 * The second item is evaluated against the first.
 * Function returns 0 if two items are the same
 * and non-zero otherwise.
 * The \ref compflags "in_flags" is a bit mask that
 * defines how the items should be compared.
 *
 * If items are different they might be sorted following
 * some order. For example one can order items by name
 * but not by type.
 * If the result of the function is non-zero
 * the \ref outflags "out_flags" (if provided) will be
 * set to indicate if the second item is greater
 * then the first.
 *
 * @param[in]  first      First item to compare.
 * @param[in]  second     Second item to compare.
 * @param[in]  in_flags   See \ref compflags "comparison flags".
 * @param[out] out_flags  See \ref outflags "output flags".
 *
 *
 * @return 0 if items are the same and nonzero otherwise.

 */
int col_compare_items(struct collection_item *first,
                      struct collection_item *second,
                      unsigned in_flags,
                      unsigned *out_flags);



/**
 * @brief Modify any item element.
 *
 * This function is useful if you want to modify the item that
 * you got as a result of \ref iterfunc "iterating" through
 * collection or by calling \ref col_get_item.
 * Previous type and data of the item is destroyed.
 *
 * If you want to rename an item provide a new name in the property
 * argument otherwise keep it NULL.
 *
 * If you want the data to remain unchanged use 0 as a length parameter.
 *
 * If item is a reference or a collection the call will return an error.
 *
 * The are several convenience function that are wrappers
 * around this function. For more information
 * see \ref modwrap "item modification wrappers".
 *
 * @param[in] item       Item to modify.
 * @param[in] property   Property name. Use NULL to leave the property
 *                       unchanged.
 * @param[in] type       See \ref coltypes "types" for more information.
 * @param[in] data       New value.
 * @param[in] length     New value. Use 0 to leave the value and its type
 *                       unchanged.
 *
 * @return 0          - Item was successfully modified.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - The value of some of the arguments is invalid.
 *                      The attempt to modify an item which is
 *                      a reference to a collection or a collection
 *                      name.
 */
int col_modify_item(struct collection_item *item,
                    const char *property,
                    int type,
                    const void *data,
                    int length);

/**
 * @defgroup modwrap Item modification wrappers
 *
 * The functions in this section are convenience wrappers
 * around \ref col_modify_item.
 * They return same error codes.
 *
 * @{
 */

/**
 * @brief Modify item property.
 *
 * This function is a convenience wrapper around \ref col_modify_item.
 * It is equivalent to: col_modify_item(item, property, 0, NULL, 0);
 *
 */
int col_modify_item_property(struct collection_item *item,
                             const char *property);

/**
 * @brief Modify item value to be a string.
 *
 * This function is a convenience wrapper around \ref col_modify_item.
 * It sets a value of the item to a provided string.
 * If property is not NULL it also renames the property.
 * If the length argument is not zero the string will be truncated to
 * this length. If the length is 0 the length will be calculated based
 * on the length of the actual string.
 * Original value is always destroyed.
 *
 * @return - same error values as \ref col_modify_item.
 */
int col_modify_str_item(struct collection_item *item,
                        const char *property,
                        const char *string,
                        int length);
/**
 * @brief Modify item value to be a binary blob.
 *
 * This function is a convenience wrapper around \ref col_modify_item.
 * It sets a value of the item to a provided binary buffer.
 * If property is not NULL it also renames the property.
 * Original value is always destroyed.
 *
 * @return - same error values as \ref col_modify_item.
 */
int col_modify_binary_item(struct collection_item *item,
                           const char *property,
                           void *binary_data,
                           int length);
/**
 * @brief Modify item value to be a Boolean.
 *
 * This function is a convenience wrapper around \ref col_modify_item.
 * It sets a value of the item to a provided logical value.
 * If property is not NULL it also renames the property.
 * Original value is always destroyed.
 *
 * @return - same error values as \ref col_modify_item.
 */
int col_modify_bool_item(struct collection_item *item,
                         const char *property,
                         unsigned char logical);
/**
 * @brief Modify item value to be an integer.
 *
 * This function is a convenience wrapper around \ref col_modify_item.
 * It sets a value of the item to a provided integer value.
 * If property is not NULL it also renames the property.
 * Original value is always destroyed.
 *
 * @return - same error values as \ref col_modify_item.
 */
int col_modify_int_item(struct collection_item *item,
                        const char *property,
                        int32_t number);
/**
 * @brief Modify item value to be a long integer.
 *
 * This function is a convenience wrapper around \ref col_modify_item.
 * It sets a value of the item to a provided long integer value.
 * If property is not NULL it also renames the property.
 * Original value is always destroyed.
 *
 * @return - same error values as \ref col_modify_item.
 */
int col_modify_long_item(struct collection_item *item,
                         const char *property,
                         int64_t number);
/**
 * @brief Modify item value to be an unsigned long.
 *
 * This function is a convenience wrapper around \ref col_modify_item.
 * It sets a value of the item to a provided unsigned long value.
 * If property is not NULL it also renames the property.
 * Original value is always destroyed.
 *
 * @return - same error values as \ref col_modify_item.
 */
int col_modify_ulong_item(struct collection_item *item,
                          const char *property,
                          uint64_t number);
/**
 * @brief Modify item value to be an unsigned integer.
 *
 * This function is a convenience wrapper around \ref col_modify_item.
 * It sets a value of the item to a provided unsigned integer value.
 * If property is not NULL it also renames the property.
 * Original value is always destroyed.
 *
 * @return - same error values as \ref col_modify_item.
 */
int col_modify_unsigned_item(struct collection_item *item,
                             const char *property,
                             uint32_t number);
/**
 * @brief Modify item value to be a floating point.
 *
 * This function is a convenience wrapper around \ref col_modify_item.
 * It sets a value of the item to a provided floating point value.
 * If property is not NULL it also renames the property.
 * Original value is always destroyed.
 *
 * @return - same error values as \ref col_modify_item.
 */
int col_modify_double_item(struct collection_item *item,
                           const char *property,
                           double number);

/**
 * @}
 */

/**
 * @brief Extract item from the collection.
 *
 * Function to find and remove an item from the collection.
 * Function does not destroy the item instead it returns a reference
 * to the item so it can be used later and inserted back into this or
 * other collection.
 * The function assumes that the caller knows the collection
 * the property is stored in.
 * The header of the collection can't be extracted with this function
 * but the reference to the collection can.
 *
 * Function allows specifying relative position of the item in the
 * collection. One can specify that he wants to extract an item
 * that is first in the collection or last, or after other item
 * in the collection. For more details see parameter definitions.
 *
 * After extracting the item from the collection the caller has to
 * either insert it back into some collection using \ref col_insert_item
 * or delete it using \ref col_delete_item.
 *
 *
 * @param[in]  ci              Collection object.
 * @param[in]  subcollection   Name of the sub collection to extract
 *                             item from. If NULL, the top level collection
 *                             is used. One can use "foo!bar!baz"
 *                             notation to identify the sub collection.
 * @param[in]  disposition     Constant that controls how the relative
 *                             position of the item to extract is determined.
 *                             For more information see \ref dispvalues
 *                             "disposition constants".
 * @param[in]  refprop         Name of the property to relate to.
 *                             This can be used to specify that function
 *                             should extract next item after the item
 *                             with this name. Leave NULL if the
 *                             disposition you are using does not
 *                             relate to an item in the collection.
 * @param[in]  idx             Index of the property to extract.
 *                             Useful for multi-value properties where
 *                             several properties have same name in a row.
 * @param[in]  type            Type filter. Only the item of the matching
 *                             type will be used. It can be a bit mask of
 *                             more than one type. Use 0 if you do not
 *                             need to filter by type.
 * @param[out] ret_ref         Variable will receive the value of the
 *                             pointer to the extracted item.
 *
 * @return 0          - Item was successfully extracted.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - The value of some of the arguments is invalid.
 * @return ENOENT     - Sub collection is not found.
 *                      The position can't be determined. For example
 *                      extracting next item after item with name "foo"
 *                      will cause this error if item "foo" is the last
 *                      item in the collection. There are other cases
 *                      when this error can be returned but the common
 *                      theme is that something was not found.
 * @return ENOSYS       Unknown disposition value.
 */
int col_extract_item(struct collection_item *ci,
                     const char *subcollection,
                     int disposition,
                     const char *refprop,
                     int idx,
                     int type,
                     struct collection_item **ret_ref);

/**
 * @brief Extract item from the current collection.
 *
 * Function is similar to the \ref col_extract_item.
 * It acts exactly the same as \ref col_extract_item when the
 * subcollection parameter of the \ref col_extract_item is set to NULL.
 *
 * @param[in]  ci              Collection object.
 * @param[in]  disposition     Constant that controls how the relative
 *                             position of the item to extract is determined.
 *                             For more information see \ref dispvalues
 *                             "disposition constants".
 * @param[in]  refprop         Name of the property to relate to.
 *                             This can be used to specify that function
 *                             should extract next item after the item
 *                             with this name. Leave NULL if the
 *                             disposition you are using does not
 *                             relate to an item in the collection.
 * @param[in]  idx             Index of the property to extract.
 *                             Useful for multi-value properties where
 *                             several properties have same name in a row.
 * @param[in]  type            Type filter. Only the item of the matching
 *                             type will be used. It can be a bit mask of
 *                             more than one type. Use 0 if you do not
 *                             need to filter by type.
 * @param[out] ret_ref         Variable will receive the value of the
 *                             pointer to the extracted item.
 *
 * @return 0          - Item was successfully extracted.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - The value of some of the arguments is invalid.
 * @return ENOENT     - Sub collection is not found.
 *                      The position can't be determined. For example
 *                      extracting next item after item with name "foo"
 *                      will cause this error if item "foo" is the last
 *                      item in the collection. There are other cases
 *                      when this error can be returned but the common
 *                      theme is that something was not found.
 * @return ENOSYS       Unknown disposition value.
 */
int col_extract_item_from_current(struct collection_item *ci,
                                  int disposition,
                                  const char *refprop,
                                  int idx,
                                  int type,
                                  struct collection_item **ret_ref);

/**
 * @brief Remove item from the collection.
 *
 * Function internally calls \ref col_extract_item and then
 * \ref col_delete_item for the extracted item.
 *
 * Function is similar to \ref col_delete_property function
 * but allows more specific information about what item (property)
 * to remove.
 *
 * The header will not be considered for deletion.
 *
 * @param[in]  ci              Collection object.
 * @param[in]  subcollection   Name of the sub collection to remove
 *                             item from. If NULL, the top level collection
 *                             is used. One can use "foo!bar!baz"
 *                             notation to identify the sub collection.
 * @param[in]  disposition     Constant that controls how the relative
 *                             position of the item to remove is determined.
 *                             For more information see \ref dispvalues
 *                             "disposition constants".
 * @param[in]  refprop         Name of the property to relate to.
 *                             This can be used to specify that function
 *                             should remove next item after the item
 *                             with this name. Leave NULL if the
 *                             disposition you are using does not
 *                             relate to an item in the collection.
 * @param[in]  idx             Index of the property to remove.
 *                             Useful for multi-value properties where
 *                             several properties have same name in a row.
 * @param[in]  type            Type filter. Only the item of the matching
 *                             type will be used. It can be a bit mask of
 *                             more than one type. Use 0 if you do not
 *                             need to filter by type.
 *
 * @return 0          - Item was successfully removed.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - The value of some of the arguments is invalid.
 * @return ENOENT     - Sub collection is not found.
 *                      The position can't be determined. For example
 *                      deleting next item after item with name "foo"
 *                      will cause this error if item "foo" is the last
 *                      item in the collection. There are other cases
 *                      when this error can be returned but the common
 *                      theme is that something was not found.
 * @return ENOSYS       Unknown disposition value.
 */
int col_remove_item(struct collection_item *ci,
                    const char *subcollection,
                    int disposition,
                    const char *refprop,
                    int idx,
                    int type);


/**
 * @brief Remove item from the current collection.
 *
 * Function is similar to the \ref col_remove_item.
 * It acts exactly the same as \ref col_remove_item when the
 * subcollection parameter of the \ref col_remove_item is set to NULL.
 *
 * @param[in]  ci              Collection object.
 * @param[in]  disposition     Constant that controls how the relative
 *                             position of the item to remove is determined.
 *                             For more information see \ref dispvalues
 *                             "disposition constants".
 * @param[in]  refprop         Name of the property to relate to.
 *                             This can be used to specify that function
 *                             should remove next item after the item
 *                             with this name. Leave NULL if the
 *                             disposition you are using does not
 *                             relate to an item in the collection.
 * @param[in]  idx             Index of the property to remove.
 *                             Useful for multi-value properties where
 *                             several properties have same name in a row.
 * @param[in]  type            Type filter. Only the item of the matching
 *                             type will be used. It can be a bit mask of
 *                             more than one type. Use 0 if you do not
 *                             need to filter by type.
 *
 * @return 0          - Item was successfully removed.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - The value of some of the arguments is invalid.
 * @return ENOENT     - Sub collection is not found.
 *                      The position can't be determined. For example
 *                      deleting next item after item with name "foo"
 *                      will cause this error if item "foo" is the last
 *                      item in the collection. There are other cases
 *                      when this error can be returned but the common
 *                      theme is that something was not found.
 * @return ENOSYS       Unknown disposition value.
 */
int col_remove_item_from_current(struct collection_item *ci,
                                 int disposition,
                                 const char *refprop,
                                 int idx,
                                 int type);

/**
 * @brief Insert item to the collection.
 *
 * <b>WARNING:</b> Only use this function to insert items
 * that were extracted using \ref col_extract_item or
 * \ref col_extract_item_from_current.
 * <b>NEVER</b> use it with items that were returned by:
 *  - \ref col_get_item
 *  - \ref addproperty "add property" functions
 *  - \ref addprop_withref "add property with reference" functions
 *  - \ref insertproperty "instert property" functions.
 *
 * The fundamental difference is that when you extracted item
 * using col_extract_item() it stops to be managed by a collection.
 * With such item you can:
 *  - a) Insert this item into another (or same) collection
 *  - b) Get item information using corresponding item management functions.
 *  - c) Destroy item using col_delete_item().
 *
 * You are required to do either a) or c) with such item.
 *
 * @param[in]  ci              Collection object.
 * @param[in]  subcollection   Name of the sub collection to insert
 *                             item into. If NULL, the top level collection
 *                             is used. One can use "foo!bar!baz"
 *                             notation to identify the sub collection.
 * @param[in]  item            Item to insert.
 * @param[in]  disposition     Constant that controls where to insert
 *                             the item.
 *                             For more information see \ref dispvalues
 *                             "disposition constants".
 * @param[in]  refprop         Name of the property to relate to.
 *                             This can be used to specify that function
 *                             should insert the item after the item
 *                             with this name. Leave NULL if the
 *                             disposition you are using does not
 *                             relate to an item in the collection.
 * @param[in]  idx             Index of the property to insert.
 *                             Useful for multi-value properties where
 *                             several properties have same name in a row.
 * @param[in]  flags           Flags that control naming issues.
 *                             See \ref insflags "insert flags"
 *                             for more details.
 *
 * @return 0          - Item was successfully extracted.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - The value of some of the arguments is invalid.
 * @return ENOENT     - Sub collection is not found.
 *                      The position can't be determined. For example
 *                      extracting next item after item with name "foo"
 *                      will cause this error if item "foo" is the last
 *                      item in the collection. There are other cases
 *                      when this error can be returned but the common
 *                      theme is that something was not found.
 * @return ENOSYS       Unknown disposition value.
 * @return EEXIST       If duplicate name/type checking is turned on
 *                      and duplicate name/type is detected.
 *
 */
int col_insert_item(struct collection_item *ci,
                    const char *subcollection,
                    struct collection_item *item,
                    int disposition,
                    const char *refprop,
                    int idx,
                    unsigned flags);

/**
 * @brief Insert item to the current collection.
 *
 * Function is equivalent to \ref col_insert_item with
 * subcollection parameter equal NULL.
 *
 * @param[in]  ci              Collection object.
 * @param[in]  item            Item to insert.
 * @param[in]  disposition     Constant that controls where to insert
 *                             the item.
 *                             For more information see \ref dispvalues
 *                             "disposition constants".
 * @param[in]  refprop         Name of the property to relate to.
 *                             This can be used to specify that function
 *                             should insert the item after the item
 *                             with this name. Leave NULL if the
 *                             disposition you are using does not
 *                             relate to an item in the collection.
 * @param[in]  idx             Index of the property to insert.
 *                             Useful for multi-value properties where
 *                             several properties have same name in a row.
 * @param[in]  flags           Flags that control naming issues.
 *                             See \ref insflags "insert flags"
 *                             for more details.
 *
 * @return 0          - Item was successfully extracted.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - The value of some of the arguments is invalid.
 * @return ENOENT     - Sub collection is not found.
 *                      The position can't be determined. For example
 *                      extracting next item after item with name "foo"
 *                      will cause this error if item "foo" is the last
 *                      item in the collection. There are other cases
 *                      when this error can be returned but the common
 *                      theme is that something was not found.
 * @return ENOSYS       Unknown disposition value.
 * @return EEXIST       If duplicate name/type checking is turned on
 *                      and duplicate name/type is detected.
 *
 */
int col_insert_item_into_current(struct collection_item *ci,
                                 struct collection_item *item,
                                 int disposition,
                                 const char *refprop,
                                 int idx,
                                 unsigned flags);



/**
 * @brief Delete extracted item.
 *
 * <b>NEVER</b> use this function to delete an item
 * that was not previously extracted from the collection.
 *
 * There is currently no function to create an item aside and
 * then insert it into the collection so the col_delete_item
 * has only one use. In future this may change.
 *
 * @param[in]  item            Item to delete.
 *
 */
void col_delete_item(struct collection_item *item);

/**
 * @}
 */


/**
 * @defgroup iterfunc Iterator interface
 *
 * The functions in this section allow iterating
 * through a collection in a loop where the caller
 * implements the loop. It is different from the search and
 * traverse functions described in other sections because those
 * functions implement the loop themselves and call provided
 * callback in a specific situation.
 *
 * @{
 */

/**
 * @brief Bind iterator to a collection.
 *
 * This function creates an iterator object and binds it to the collection.
 *
 * @param[out] iterator   Newly created iterator object.
 * @param[in]  ci         Collection to iterate.
 * @param[in]  mode_flags Flags define how to traverse the collection.
 *                        For more information see \ref traverseconst
 *                        "constants defining traverse modes".
 *
 * @return 0          - Iterator was created successfully.
 * @return ENOMEM     - No memory.
 * @return EINVAL     - The value of some of the arguments is invalid.
 *
 */
int col_bind_iterator(struct collection_iterator **iterator,
                      struct collection_item *ci,
                      int mode_flags);

/**
 * @brief Unbind the iterator from the collection.
 *
 * @param[in] iterator   Iterator object to free.
 */
void col_unbind_iterator(struct collection_iterator *iterator);

/**
 * @brief Iterate collection.
 *
 * Advance to next item in the collection. After the iterator is
 * bound it does not point to any item in the collection.
 * Use this function in the loop to step through all items
 * in the collection. See unit test for code examples.
 *
 * @param[in]  iterator   Iterator object to use.
 * @param[out] item       Pointer to the collection item.
 *                        Do not destroy or alter this pointer
 *                        in any ways. To access the internals
 *                        of the item use \ref getitem "item management"
 *                        functions.
 *                        The value of the item will be set to NULL if
 *                        the end of the collection is reached.
 *
 * @return 0          - Item was successfully retrieved.
 * @return EINVAL     - The value of some of the arguments is invalid.
 */
int col_iterate_collection(struct collection_iterator *iterator,
                           struct collection_item **item);

/**
 * @brief Move up
 *
 * Stop processing this sub collection and move to the next item in the
 * collection some levels up.
 *
 * @param[in]  iterator   Iterator object to use.
 * @param[in]  level      Indicates how many levels up you want to jump.
 *                        If 0 - call is a no op.
 *                        If the depth is less then requested level
 *                        the iterator will get to the 0 level and
 *                        next call to \ref col_iterate_collection
 *                        will return NULL item.
 *
 * @return 0          - Iterator was successfully repositioned.
 * @return EINVAL     - The value of some of the arguments is invalid.
 */
int col_iterate_up(struct collection_iterator *iterator, unsigned level);

/**
 * @brief Get current depth
 *
 * How deep are we relative to the top level?
 * This function will report depth that in some cases might look
 * misleading. The reason is that traverse flags affect the internal
 * level we are on at each moment.
 * For example the default traverse behavior is to show
 * references to the sub collections.
 * So when the item reference is returned the
 * depth automatically adjusted to level inside the sub collection.
 * So if function is called in this situation the level returned will
 * denote the level inside collection.
 * Now imagine that this collection is empty so the attempt to read
 * element will push you automatically one level up (in absence of the
 * \ref COL_TRAVERSE_END flag). If in this situation you encounter another
 * collection the reference will be returned and level automatically
 * adjusted to level inside the collection.
 * The point is that the level is reliable only after
 * a data item was returned.
 * To avoid this ambiguity another function \ref col_get_item_depth
 * was introduced.
 *
 * @param[in]  iterator   Iterator object to use.
 * @param[in]  depth      The variable will receive the depth
 *                        the iterator is on. The value is 0
 *                        if the iterator is on the top level.
 *
 * @return 0          - Success.
 * @return EINVAL     - The value of some of the arguments is invalid.
 */
int col_get_iterator_depth(struct collection_iterator *iterator, int *depth);

/**
 * @brief Get depth of the last returned item.
 *
 * @param[in]  iterator   Iterator object to use.
 * @param[in]  depth      The variable will receive the depth
 *                        the iterator is on.
 *                        Item from the top level will have
 *                        depth equal to 0. The value of 0
 *                        will also be returned if no item
 *                        was read so far.
 *
 * @return 0          - Success.
 * @return EINVAL     - The value of some of the arguments is invalid.
 */
int col_get_item_depth(struct collection_iterator *iterator, int *depth);

/**
 * @brief Pin iterator
 *
 * Pins down the iterator to loop around current point.
 *
 * This feature allows some search optimization.
 * The idea is to be able to put a 'pin'
 * into a specific place while iterating
 * the collection and make this place a new
 * "wrap around" place for the collection.
 * This means that next time you
 * iterate this collection you will start
 * iterating from the next item and
 * the item you got before setting pin will be
 * the last in your iteration cycle.
 *
 * Here is the example:
 *
 * Assume you have two collections that you need
 * to compare and perform some action on collection
 * 1 based on the presence of the item in collection 2.
 *  - Collection1 = A, B, C, D, E, F
 *  - Collection2 = A, C, F
 *
 * The usual approach is to try A from collection 1
 * against A, B, C from collection 2. "A" will be found
 *  right away. But to find "F" it has to be compared
 * to "A" and "C" first. The fact that the collections
 * are to some extent ordered can in some cases
 * help to reduce the number of comparisons.
 * If we found "C" in the list we can put a "pin"
 * into the collection there causing the iterator
 * to warp at this "pin" point. Since "D" and "E"
 * are not in the second collection we will have
 * to make same amount of comparisons in traditional
 * or "pinned" case to not find them.
 * To find "F" in pinned case there will be just one
 * comparison.
 *  - Traditional case = 1 + 3 + 2 + 3 + 3 + 3 = 15
 *  - Pinned case = 1 + 3 + 1 + 3 + 3 + 1 = 12
 *
 * It is a 20% comparison reduction.
 *
 * @param[in]  iterator   Iterator object to use.
 *
 * @return 0          - Success.
 * @return EINVAL     - The value of the argument is invalid.
 */
void col_pin_iterator(struct collection_iterator *iterator);

/**
 * @brief Rewind iterator
 *
 * Rewinds iterator to the current pin point which is by
 * default the beginning of the collection until changed by
 * \ref col_pin_iterator function.
 *
 * @param[in]  iterator   Iterator object to use.
 *
 * @return 0          - Success.
 * @return EINVAL     - The value of the argument is invalid.
 */
void col_rewind_iterator(struct collection_iterator *iterator);


/**
 * @}
 */

/**
 * @}
 */

#endif
