#ifndef DHASH_H
#define DHASH_H

/*****************************************************************************/
/******************************** Documentation ******************************/
/*****************************************************************************/

#if 0

Dynamic hash table implementation based on article in CACM April 1988 pp.
446-457, by Per-Ake Larson.

This implementation was based on a 3/7/1989 submission to comp.sources.misc by
Esmond Pitt (ejp@ausmelb.oz.AU) that emulated the hsearch(3) interface. The interface
was reworked to be much more flexible and significant new functionality was
added by John Dennis (jdennis@sharpeye.com).

A hash table maintains a set of <key,value> pairs. Lookups are performed by
locating the key in the table and returning its value.

A dynamic hash table keeps the number of hash collisions constant
independent of the number of entries in the hash table.

Both keys and values may be of different types. Two different key types are
supported, strings and unsigned longs. If the key type is a string the hash
library will automatically allocate memory to hold the hash key string and
will automatically free the memory for the key string when the hash entry
is destroyed. Items in the hash table only match when their key types match
AND the keys themselves match. For example if there were two hash entries,
one whose key type was an unsigned long equal to 1 and one whose key type was
a string equal to "1" they would not match, these are considered two
distinct entries.

The value of the key may be a undefined, pointer, an int, an unsigned int, a
long, an unsigned long, a float, or a double. The hash library does nothing
with user pointers (value.type == HASH_VALUE_PTR). Its the user responsibility
to free items pointed to by these pointers when a hash entry is deleted or the
hash table is destroyed (see hash_delete_callback and/or hash_destroy).

See dhash_example.c for an illustration of how one might use the API. It does not
represent complete API coverage nor the optimal way to do things in all cases,
it is just a general example.

#endif

/*****************************************************************************/
/******************************* Include Files *******************************/
/*****************************************************************************/

#include <stdbool.h>

/*****************************************************************************/
/*********************************** Defines *********************************/
/*****************************************************************************/

#if 1
#define HASH_STATISTICS
#endif

#define HASH_DEFAULT_DIRECTORY_BITS 5
#define HASH_DEFAULT_SEGMENT_BITS 5
#define HASH_DEFAULT_MIN_LOAD_FACTOR 1
#define HASH_DEFAULT_MAX_LOAD_FACTOR 5

#define HASH_ERROR_BASE -2000
#define HASH_ERROR_LIMIT (HASH_ERROR_BASE+20)
#define IS_HASH_ERROR(error)  (((error) >= HASH_ERROR_BASE) && ((error) < HASH_ERROR_LIMIT))

#define HASH_SUCCESS              0
#define HASH_ERROR_BAD_KEY_TYPE   (HASH_ERROR_BASE + 1)
#define HASH_ERROR_BAD_VALUE_TYPE (HASH_ERROR_BASE + 2)
#define HASH_ERROR_NO_MEMORY      (HASH_ERROR_BASE + 3)
#define HASH_ERROR_KEY_NOT_FOUND  (HASH_ERROR_BASE + 4)
#define HASH_ERROR_BAD_TABLE      (HASH_ERROR_BASE + 5)

/*****************************************************************************/
/******************************* Type Definitions ****************************/
/*****************************************************************************/

struct hash_table_str;
typedef struct hash_table_str hash_table_t;

typedef enum {
    HASH_KEY_STRING,
    HASH_KEY_ULONG
} hash_key_enum;

typedef enum
{
    HASH_VALUE_UNDEF,
    HASH_VALUE_PTR,
    HASH_VALUE_INT,
    HASH_VALUE_UINT,
    HASH_VALUE_LONG,
    HASH_VALUE_ULONG,
    HASH_VALUE_FLOAT,
    HASH_VALUE_DOUBLE
} hash_value_enum;

typedef struct hash_key_t {
    hash_key_enum type;
    union {
        const char *str;
        unsigned long ul;
    };
} hash_key_t;

typedef struct hash_value_t {
    hash_value_enum type;
    union {
        void *ptr;
        int i;
        unsigned int ui;
        long l;
        unsigned long ul;
        float f;
        double d;
    };
} hash_value_t;

typedef struct hash_entry_t {
    hash_key_t key;
    hash_value_t value;
} hash_entry_t;

#ifdef HASH_STATISTICS
typedef struct hash_statistics_t {
    unsigned long hash_accesses;
    unsigned long hash_collisions;
    unsigned long table_expansions;
    unsigned long table_contractions;
} hash_statistics_t;
#endif


/* typedef's for callback based iteration */
typedef bool(*hash_iterate_callback)(hash_entry_t *item, void *user_data);
typedef void (*hash_delete_callback)(hash_entry_t *item);

/* typedef's for iteration object based iteration */
struct hash_iter_context_t;
typedef hash_entry_t *(*hash_iter_next_t)(struct hash_iter_context_t *iter);
struct hash_iter_context_t {
    hash_iter_next_t next;
};

/* typedef for hash_create_ex() */
typedef void *(*hash_alloc_func)(size_t size);
typedef void (*hash_free_func)(void *ptr);

/*****************************************************************************/
/*************************  External Global Variables  ***********************/
/*****************************************************************************/

/*****************************************************************************/
/****************************  Exported Functions  ***************************/
/*****************************************************************************/

/*
 * Given an error code returned by a hash function, map it to a error string.
 * Returns NULL if the error code is unrecognized.
 */
const char* hash_error_string(int error);

/*
 * Create a new hash table with room for n initial entries.  hash_create returns
 * an opaque pointer to the new hash table in the table parameter. Functions
 * operating on the hash table pass in this hash table pointer. This means you
 * may have as many concurrent hash tables as you want. The delete_callback
 * parameter is a pointer to a function which will be called just prior to a
 * hash entry being deleted. This is useful when the hash value has items which
 * may need to be disposed of. The delete_callback may be NULL.
 */
int hash_create(unsigned long count, hash_table_t **tbl, hash_delete_callback delete_callback);

/*
 * Create a new hash table and fine tune it's configurable parameters.
 * Refer to CACM article for explanation of parameters.
 *
 * directory_bits: number of address bits allocated to top level directory array.
 * segment_bits: number of address bits allocated to segment array.
 * min_load_factor: table contracted when the ratio of entry count to bucket count
 *                  is less than the min_load_factor the table is contracted.
 * max_load_factor: table expanded when the ratio of entry count to bucket count
 *                  is greater than the max_load_factor the table is expanded.
 * alloc_func: function pointer for allocation
 * free_func: funciton pointer for freeing memory allocated with alloc_func
 *
 * Note directory_bits + segment_bits must be <= number of bits in unsigned long
 */
int hash_create_ex(unsigned long count, hash_table_t **tbl,
                   unsigned int directory_bits, unsigned int segment_bits,
                   unsigned long min_load_factor, unsigned long max_load_factor,
                   hash_alloc_func alloc_func,
                   hash_free_func free_func,
                   hash_delete_callback delete_callback);

#ifdef HASH_STATISTICS
/*
 * Return statistics for the table.
 */
int hash_get_statistics(hash_table_t *table, hash_statistics_t *statistics);
#endif

/*
 * hash_destroy deletes all entries in the hash table, freeing all memory used
 * in implementing the hash table. Some hash entries may have values which are
 * pointers to user data structures. User pointers are not free by hash_destroy,
 * they must be free by the caller. This may be done by iterating over all the
 * entries in the table using hash_iterate() and freeing the values or by
 * registering a delete callback when the table is created with
 * hash_create(). Note, hash keys which are strings will be automatically freed
 * by hash_destroy, the caller does not need to free the key strings.
 */
int hash_destroy(hash_table_t *table);

/*
 * Enter or update an item in the table referenced by key. If the key does not
 * exist yet the item will be created and inserted into the table with the
 * value, otherwise the value for the existing key is updated. The return value
 * may be HASH_ERROR_BAD_KEY_TYPE or HASH_ERROR_BAD_VALUE_TYPE if the key or
 * value type respectively is invalid. This function might also return
 * HASH_ERROR_NO_MEMORY.
 */
int hash_enter(hash_table_t *table, hash_key_t *key, hash_value_t *value);

/*
 * Using the key lookup the value associated with it in the table. If the key is
 * not in the table HASH_ERROR_KEY_NOT_FOUND is returned. If the type of key is
 * invalid HASH_ERROR_BAD_KEY_TYPE is returned. Otherwise HASH_SUCCESS is
 * returned. If the result is anything other than HASH_SUCCESS the value pointer
 * is not updated.
 */
int hash_lookup(hash_table_t *table, hash_key_t *key, hash_value_t *value);

/*
 * Like hash_lookup() except if the key is not in the table then it is entered
 * into the table and assigned the default_value. Thus it is not possible for
 * hash_get_default() to return HASH_ERROR_KEY_NOT_FOUND.
 */
int hash_get_default(hash_table_t *table, hash_key_t *key, hash_value_t *value, hash_value_t *default_value);

/*
 * Delete the item from the table. The key and its type are specified in the key
 * parameter which are passed by reference. If the key was in the table
 * HASH_SUCCESS is returned otherwise HASH_ERROR_KEY_NOT_FOUND is
 * returned. Memory allocated to hold the key if it was a string is free by the
 * hash library, but values which are pointers to user data must be freed by the
 * caller (see delete_callback).
 */
int hash_delete(hash_table_t *table, hash_key_t *key);

/*
 * Often it is useful to operate on every key and/or value in the hash
 * table. The hash_iterate function will invoke the users callback on every item
 * in the table as long as the callback returns a non-zero value. Returning a
 * zero from the callback can be used to halt the iteration prematurely if some
 * condition is met. The user_data parameter is passed to the callback
 * function. It can be used for any purpose the caller wants. The callback
 * parameter list is:
 *
 * bool callback(hash_entry_t *item, hash_table_t *user_data);
 *
 * WARNING: Do not modify the contents of the table during an iteration it will
 * produce undefined results. If you need to visit each item in the table and
 * potentially delete or insert some entries the proper way to do this is to
 * obtain a list of keys or items using hash_keys() or hash_items() which
 * returns a copy of the keys or items. You may then loop on the list returned
 * and safely update the table (don't forget to free the list when done).
 */
int hash_iterate(hash_table_t *table, hash_iterate_callback callback, void *user_data);

/*
 * This is another method to iterate on every key/value in the hash table.
 * However, unlike hash_iterate which requires a callback this function returns
 * an iterator object which contains a next() function pointer.  Each time
 * next() is invoked it returns a pointer to the next hash entry in the table,
 * then NULL when all entries have been visited. In some circumstances it's more
 * convenient than having to define a callback. Like hash_iterate() one must
 * never modify the table contents during iteration. If you intend to modify the
 * table during iteration use the functions which return an indepent list of
 * keys, values, or items instead and iterate on the list.  The iterator object
 * must be free'ed when you're done iterating by calling free() on it.
 *
 * Example:
 *
 * struct hash_iter_context_t *iter;
 * hash_entry_t *entry;
 *
 * iter = new_hash_iter_context(table);
 * while ((entry = iter->next(iter)) != NULL) {
 *     do_something(entry);
 * }
 * free(iter);
 */
struct hash_iter_context_t *new_hash_iter_context(hash_table_t *table);

/*
 * Return a count of how many items are currently in the table.
 */
unsigned long hash_count(hash_table_t *table);

/*
 * Get an array of all the keys in the table returned through the keys
 * parameter. The number of elements in the array is returned in the count
 * parameter. Each key in the array is a copy of the key in the table. Any
 * pointers in the key will be shared with the table entry thus both the item in
 * the array and the item in the table point to the same object. The array
 * should be freed by calling free(). The function may return
 * HASH_ERROR_NO_MEMORY, otherwise HASH_SUCCESS.
 */
int hash_keys(hash_table_t *table, unsigned long *count, hash_key_t **keys);

/*
 * Get an array of all the values in the table returned through the values
 * parameter. The number of elements in the array is returned in the count
 * parameter. Each value in the array is a copy of the value in the table. Any
 * pointers in the value will be shared with the table entry thus both the item in
 * the array and the item in the table point to the same object. The array
 * should be freed by calling free(). The function may return
 * HASH_ERROR_NO_MEMORY, otherwise HASH_SUCCESS.
 */
int hash_values(hash_table_t *table, unsigned long *count, hash_value_t **values);


/*
 * Get an array of all the entries in the table returned through the entries
 * parameter. The number of elements in the array is returned in the count
 * parameter. Each entry in the array is a copy of the entry in the table. Any
 * pointers in the entry will be shared with the table entry thus both the item in
 * the array and the item in the table point to the same object. The array
 * should be freed by calling free(). The function may return
 * HASH_ERROR_NO_MEMORY, otherwise HASH_SUCCESS.
 */
int hash_entries(hash_table_t *table, unsigned long *count, hash_entry_t **entries);

/*
 * Return boolean if the key is in the table.
 */
bool hash_has_key(hash_table_t *table, hash_key_t *key);

#endif
