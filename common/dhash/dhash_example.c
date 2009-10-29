#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "dhash.h"

struct my_data_t {
    int foo;
    char bar[128];
};

void delete_callback(hash_entry_t *entry)
{
    if (entry->value.type == HASH_VALUE_PTR) free(entry->value.ptr);
}

bool visit_callback(hash_entry_t *entry, void *user_data)
{
    unsigned long *count = (unsigned long *)user_data;
    struct my_data_t *my_data = (struct my_data_t *) entry->value.ptr;

    (*count)++;

    printf("%s = [foo=%d bar=%s]\n", entry->key.str, my_data->foo, my_data->bar);
    return true;
}

struct my_data_t *new_data(int foo, const char *bar)
{
    struct my_data_t *my_data = malloc(sizeof(struct my_data_t));
    my_data->foo = foo;
    strncpy(my_data->bar, bar, sizeof(my_data->bar));
    return my_data;
}
int main(int argc, char **argv)
{
    static hash_table_t *table = NULL;
    hash_key_t key, *keys;
    hash_value_t value;
    struct hash_iter_context_t *iter;
    hash_entry_t *entry;
    unsigned long i, n_entries;
    int error;
    struct my_data_t *my_data = new_data(1024, "Hello World!");
    unsigned long count;

    /* Create a hash table */
    if ((error = hash_create(10, &table, delete_callback)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot create hash table (%s)\n", hash_error_string(error));
        return error;
    }

    /* Enter a key named "My Data" and specify it's value as a pointer to my_data */
    key.type = HASH_KEY_STRING;
    key.str = strdup("My Data");
    value.type = HASH_VALUE_PTR;
    value.ptr = my_data;

    if ((error = hash_enter(table, &key, &value)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot add to table \"%s\" (%s)\n", key.str, hash_error_string(error));
        return error;
    }

    /* Get a list of keys and print them out, free the list when we're done */
    if ((error = hash_keys(table, &count, &keys)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot get key list (%s)\n", hash_error_string(error));
        return error;
    }

    for (i = 0; i < count; i++)
        printf("key: %s\n", keys[i].str);
    free(keys);

    /* Lookup the key named "My Data" */
    key.type = HASH_KEY_STRING;
    key.str = strdup("My Data");
    if ((error = hash_lookup(table, &key, &value)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot find key \"%s\" (%s)\n", key.str, hash_error_string(error));
    }

    /* Visit each entry in the table, callback will increment count on each visit */
    printf("Iterate using callback\n");
    count = 0;
    hash_iterate(table, visit_callback, &count);

    /* Assure number of visits equal the table size */
    assert(count == hash_count(table));

    /* Visit each entry using iterator object */
    printf("Iterate using iterator\n");
    n_entries = 0;
    iter = new_hash_iter_context(table);
    while ((entry = iter->next(iter)) != NULL) {
        struct my_data_t *data = (struct my_data_t *) entry->value.ptr;

        printf("%s = [foo=%d bar=%s]\n", entry->key.str, data->foo, data->bar);
        n_entries++;
    }
    free(iter);
    /* Assure number of visits equal the table size */
    assert(n_entries == hash_count(table));

    /* Remove the entry, deletion callback will be invoked */
    key.type = HASH_KEY_STRING;
    key.str = strdup("My Data");
    if ((error = hash_delete(table, &key)) != HASH_SUCCESS) {
        fprintf(stderr, "cannot delete from table (%s)\n", hash_error_string(error));
    }

    /* Assure key is no longer in table */
    assert (!hash_has_key(table, &key));

    /* Free the table */
    hash_destroy(table);

    return 0;
}
