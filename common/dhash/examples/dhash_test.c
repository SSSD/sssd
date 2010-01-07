#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include "dhash.h"

#define DEFAULT_MAX_TEST (500)
hash_entry_t *iter_result_1 = NULL;
hash_entry_t *iter_result_2 = NULL;

unsigned long max_test = DEFAULT_MAX_TEST;
int verbose = 0;

const char *error_string(int error)
{
    if (IS_HASH_ERROR(error))
        return hash_error_string(error);

    return strerror(error);
}

char *key_string(hash_key_t *key)
{
    static char buf[1024];

    switch(key->type) {
    case HASH_KEY_ULONG:
        snprintf(buf, sizeof(buf), "key ulong = %lu", key->ul);
        break;
    case HASH_KEY_STRING:
        snprintf(buf, sizeof(buf), "key string = \"%s\"", key->str);
        break;
    default:
        snprintf(buf, sizeof(buf), "unknown key type = %d", key->type);
        break;
    }
    return buf;
}

char *value_string(hash_value_t *value)
{
    static char buf[1024];

    switch(value->type) {
    case HASH_VALUE_UNDEF:
        snprintf(buf, sizeof(buf), "value undefined");
        break;
    case HASH_VALUE_PTR:
        snprintf(buf, sizeof(buf), "value str = \"%s\"", (char *)value->ptr);
        break;
    case HASH_VALUE_INT:
        snprintf(buf, sizeof(buf), "value int = %d", value->i);
        break;
    case HASH_VALUE_UINT:
        snprintf(buf, sizeof(buf), "value unsigned int = %u", value->ui);
        break;
    case HASH_VALUE_LONG:
        snprintf(buf, sizeof(buf), "value long = %ld", value->l);
        break;
    case HASH_VALUE_ULONG:
        snprintf(buf, sizeof(buf), "value unsigned long = %lu", value->ul);
        break;
    case HASH_VALUE_FLOAT:
        snprintf(buf, sizeof(buf), "value float = %f", value->f);
        break;
    case HASH_VALUE_DOUBLE:
        snprintf(buf, sizeof(buf), "value double = %f", value->f);
        break;
    default:
        snprintf(buf, sizeof(buf), "unknown value type = %d", value->type);
        break;
    }

    return buf;
}

char *entry_string(hash_entry_t *entry)
{
    static char buf[1024];

    snprintf(buf, sizeof(buf), "[%s] = [%s]", key_string(&entry->key), value_string(&entry->value));

    return buf;

}

bool callback(hash_entry_t *item, void *user_data)
{
    unsigned long *callback_count = (unsigned long *)user_data;

    iter_result_1[*callback_count] = *item;

    (*callback_count)++;

    if (verbose) printf("%s\n", entry_string(item));
    return true;
}

void delete_callback(hash_entry_t *item, hash_destroy_enum type, void *pvt)
{
    if (item->value.type == HASH_VALUE_PTR) free(item->value.ptr);
}

typedef struct test_val_t {
    long val;
    char *str;
} test_val_t;


int main(int argc, char **argv)
{
    test_val_t *test = NULL;
    long i, k;
    int status;
    hash_value_t value;
    hash_key_t key;
    char buf[1024];
    hash_table_t *table = NULL;
    unsigned long callback_count = 0;
    unsigned int directory_bits = HASH_DEFAULT_DIRECTORY_BITS;
    unsigned int segment_bits = HASH_DEFAULT_SEGMENT_BITS;
    unsigned long min_load_factor = HASH_DEFAULT_MIN_LOAD_FACTOR;
    unsigned long max_load_factor = HASH_DEFAULT_MAX_LOAD_FACTOR;

    while (1) {
        int arg;
        int option_index = 0;
        static struct option long_options[] = {
            {"count", 1, 0, 'c'},
            {"verbose", 1, 0, 'v'},
            {"quiet", 1, 0, 'q'},
            {"directory-bits", 1, 0, 'd'},
            {"segment-bits", 1, 0, 's'},
            {"min-load-factor", 1, 0, 'l'},
            {"max-load-factor", 1, 0, 'h'},
            {0, 0, 0, 0}
        };

        arg = getopt_long(argc, argv, "c:vqd:s:l:h:",
                          long_options, &option_index);
        if (arg == -1) break;

        switch (arg) {
        case 'c':
            max_test = atol(optarg);
            break;
        case 'v':
            verbose = 1;
            break;
        case 'q':
            verbose = 0;
            break;
        case 'd':
            directory_bits = atoi(optarg);
            break;
        case 's':
            segment_bits = atoi(optarg);
            break;
        case 'l':
            min_load_factor = atol(optarg);
            break;
        case 'h':
            max_load_factor = atol(optarg);
            break;
        }
    }

    if ((test = (test_val_t *) calloc(max_test, sizeof(test_val_t))) == NULL) {
        fprintf(stderr, "Failed to allocate test array\n");
        exit(1);
    }
    if ((iter_result_1 = (hash_entry_t *) calloc(max_test, sizeof(hash_entry_t))) == NULL) {
        fprintf(stderr, "Failed to allocate iter_result_1 array\n");
        exit(1);
    }
    if ((iter_result_2 = (hash_entry_t *) calloc(max_test, sizeof(hash_entry_t))) == NULL) {
        fprintf(stderr, "Failed to allocate iter_result_2 array\n");
        exit(1);
    }


    /* Initialize the random number generator */
    srandom(time(0));

    /* Create the hash table as small as possible to exercise growth */
    if ((status = hash_create_ex(1, &table,
                                 directory_bits, segment_bits,
                                 min_load_factor, max_load_factor,
                                 NULL, NULL, NULL,
                                 delete_callback, NULL)) != HASH_SUCCESS) {
        fprintf(stderr, "table creation failed at line %d (%s)\n", __LINE__, error_string(status));
        exit(1);
    }

    /* Initialize the array of test values */
    for (i = 0; i < max_test; i++) {
        test[i].val = random();
        /* If the value is odd we'll use a string as the key,
         * otherwise we'll use an unsigned long as the key */
        if (test[i].val & 1) {
            key.type = HASH_KEY_STRING;
            sprintf(buf, "%ld", test[i].val);
            test[i].str = strdup(buf);
        }
    }

    /* Enter all the test values into the hash table */
    for (i = 0; i < max_test; i++) {
        if (test[i].val & 1) {
            key.type = HASH_KEY_STRING;
            key.str = test[i].str;
            value.type = HASH_VALUE_PTR;
            value.ptr = (void *) strdup(test[i].str);
        }
        else {
            key.type = HASH_KEY_ULONG;
            key.ul = test[i].val;
            value.type = HASH_VALUE_LONG;
            value.l = test[i].val;
        }

        if (hash_has_key(table, &key)) {
            fprintf(stderr, "Error: %ld already in table when inserting, i = %lu, at line %d\n",
                    test[i].val, i, __LINE__);
            exit(1);
        }
        if ((status = hash_enter(table, &key, &value)) != HASH_SUCCESS) {
            fprintf(stderr, "Error: %ld failed insertion at line %d (%s) \n",
                    test[i].val, __LINE__, error_string(status));
            exit(1);
        }
    }

    /* Now visit each entry in the table using a callback iterator,
     * store what we found in iter_result_1 for testing the iterator object later on */
    if (verbose) printf("callback iterate:\n");
    callback_count = 0;
    if ((status = hash_iterate(table, callback, &callback_count)) != HASH_SUCCESS) {
        fprintf(stderr, "hash_iterate failed at line %d (%s)\n", __LINE__, error_string(status));
        exit(1);
    }
    if (verbose) printf("hash_count=%ld,  callback_count=%ld\n", hash_count(table), callback_count);

    if (hash_count(table) != callback_count) {
        fprintf(stderr, "Error: hash_count(%ld) != callback_count(%ld) at line %d\n",
                hash_count(table), callback_count, __LINE__);
        exit(1);
    }

    /* Now vist each entry in the table using an iterator object */
    {
        struct hash_iter_context_t *iter;
        unsigned long n_items;
        hash_entry_t *entry;

        if (verbose) printf("iter iterate:\n");

        n_items = 0;
        iter = new_hash_iter_context(table);

        while ((entry = iter->next(iter)) != NULL) {
            if (verbose) printf("%s\n", entry_string(entry));
            iter_result_2[n_items] = *entry;
            n_items++;
        }
        if (verbose) printf("hash_count=%ld,  n_items=%ld\n", hash_count(table), n_items);

        if (hash_count(table) != n_items) {
            fprintf(stderr, "Error: hash_count(%ld) != n_items(%ld) at line %d\n",
                    hash_count(table), n_items, __LINE__);
            exit(1);
        }
        free(iter);
    }

    /* Both iterators should have visited each item in the same order, verify ... */
    for (i = 0; i < max_test; i++) {
        if (memcmp(&iter_result_1[i], &iter_result_2[i], sizeof(iter_result_1[0])) != 0) {
            fprintf(stderr, "Error: iter_result_1[%lu] != iter_result_2[%lu] at line %d\n",
                    i, i, __LINE__);
            exit(1);
        }
    }

    /* Get an array of keys in the table, print them out */
    {
        unsigned long count;
        hash_key_t *keys;

        if (verbose) printf("\nhash_keys:\n");
        if ((status = hash_keys(table, &count, &keys)) != HASH_SUCCESS) {
            fprintf(stderr, "hash_keys failed at line %d (%s)\n",
                    __LINE__, error_string(status));
            exit(1);
        }

        if (hash_count(table) != count) {
            fprintf(stderr, "Error: hash_count(%ld) != hash_keys() count(%ld) at line %d\n",
                    hash_count(table), count, __LINE__);
            exit(1);
        }

        for (i = 0; i < count; i++) {
            if (verbose) printf("%s\n", key_string(&keys[i]));
        }
        free(keys);
    }

    /* Get an array of values in the table, print them out */
    {
        unsigned long count;
        hash_value_t *values;

        if (verbose) printf("\nhash_values:\n");
        hash_values(table, &count, &values);

        if (hash_count(table) != count) {
            fprintf(stderr, "Error: hash_count(%ld) != hash_values() count(%ld) at line %d\n",
                    hash_count(table), count, __LINE__);
            exit(1);
        }

        for (i = 0; i < count; i++) {
            if (verbose) printf("%s\n", value_string(&values[i]));
        }
        free(values);
    }

    /* Get an array of items in the table, print them out */
    {
        unsigned long count;
        hash_entry_t *entries;

        if (verbose) printf("\nhash_entries:\n");
        hash_entries(table, &count, &entries);

        if (hash_count(table) != count) {
            fprintf(stderr, "Error: hash_count(%ld) != hash_entries() count(%ld) at line %d\n",
                    hash_count(table), count, __LINE__);
            exit(1);
        }

        for (i = 0; i < count; i++) {
            if (verbose) printf("%s\n", entry_string(&entries[i]));
        }
        free(entries);
    }

    /* See if we can find every key */
    for (i = max_test - 1; i >= 0; i--) {
        if (test[i].val & 1) {
            key.type = HASH_KEY_STRING;
            key.str = test[i].str;
        }
        else {
            key.type = HASH_KEY_ULONG;
            key.ul = test[i].val;
        }
        if ((status = hash_lookup(table, &key, &value)) != HASH_SUCCESS) {
            fprintf(stderr, "Error: failed first lookup for value %ld at index %ld at line %d (%s)\n",
                    test[i].val, i, __LINE__, error_string(status));
            exit(1);
        }
        else {
            switch(value.type) {
            case HASH_VALUE_PTR:
                if (strcmp((char *)value.ptr, test[i].str) != 0) {
                    fprintf(stderr, "Error: corrupt ptr data for %lu at line %d\n", i, __LINE__);
                    exit(1);
                }
                break;
            case HASH_VALUE_LONG:
                if (value.l != test[i].val) {
                    fprintf(stderr, "Error: corrupt long data for %lu at line %d\n", i, __LINE__);
                    exit(1);
                }
                break;
            default:
                fprintf(stderr, "Error: unknown value type for %lu\n", i);
                break;
            }
        }
    }


    /*
     * Delete a key, make sure we can't find it, assure we can find all other
     * keys.
     */
    for (i = 0; i < max_test; i++) {
        if (test[i].val & 1) {
            key.type = HASH_KEY_STRING;
            key.str = test[i].str;
        }
        else {
            key.type = HASH_KEY_ULONG;
            key.ul = test[i].val;
        }

        if ((status = hash_lookup(table, &key, &value)) != HASH_SUCCESS) {
            fprintf(stderr, "Error: failed delete lookup for value %ld at index %ld at line %d (%s)\n",
                    test[i].val, i, __LINE__, error_string(status));
            exit(1);
        }

        if ((status = hash_delete(table, &key)) != HASH_SUCCESS) {
            fprintf(stderr, "Error: %ld not in table when deleting, i = %lu at line %d (%s)\n",
                    test[i].val, i, __LINE__, error_string(status));
            exit(1);
        }

        if (hash_lookup(table, &key, &value) != HASH_ERROR_KEY_NOT_FOUND) {
            fprintf(stderr, "Error: found in table after deletion, value = %ld at index %ld at line %d\n",
                    test[i].val, i, __LINE__);
            exit(1);
        }
        /* See if we can find all remaining keys */
        for (k = i + 1; k < max_test; k++) {
            if (test[k].val & 1) {
                key.type = HASH_KEY_STRING;
                key.str = test[k].str;
            } else {
                key.type = HASH_KEY_ULONG;
                key.ul = test[k].val;
            }
            if ((status = hash_lookup(table, &key, &value)) != HASH_SUCCESS) {
                fprintf(stderr, "Error: failed second lookup for value %ld, i = %lu k = %lu at line %d (%s)\n",
                        test[k].val, i, k, __LINE__, error_string(status));
                exit(1);
            } else {
                switch(value.type) {
                case HASH_VALUE_PTR:
                    if (strcmp((char *)value.ptr, test[k].str) != 0) {
                        fprintf(stderr, "Error: corrupt ptr data for %lu at line %d\n", k, __LINE__);
                        exit(1);
                    }
                    break;
                case HASH_VALUE_LONG:
                    if (value.l != test[k].val) {
                        fprintf(stderr, "Error: corrupt long data for %lu at line %d\n", k, __LINE__);
                        exit(1);
                    }
                    break;
                default:
                    fprintf(stderr, "Error: unknown value type (%d) for %lu\n", value.type, k);
                    break;
                }
            }
        }
    }

    if (verbose) printf("\n");

#ifdef HASH_STATISTICS
    {
        hash_statistics_t stats;

        if ((status = hash_get_statistics(table, &stats)) != HASH_SUCCESS) {
            fprintf(stderr, "Error: could not get statistics at line %d (%s)\n",
                    __LINE__, error_string(status));
            exit(1);
        }

        printf("Statistics: Accesses = %ld, Collisions = %ld, Collision Rate = %.2f, Expansions = %ld, Contractions = %ld\n",
               stats.hash_accesses, stats.hash_collisions,
               ((float)stats.hash_collisions / (float)stats.hash_accesses),
               stats.table_expansions, stats.table_contractions);
    }
#endif

    if ((status = hash_destroy(table)) != HASH_SUCCESS) {
        fprintf(stderr, "table destruction failed at line %d (%s)\n",
                __LINE__, error_string(status));
        exit(1);
    }

    for (i = 0; i < max_test; i++) {
        if (test[i].val & 1) {
            free(test[i].str);
        }
    }
    free(test);
    free(iter_result_1);
    free(iter_result_2);

    printf("Successfully tested %lu values\n", max_test);
    return 0;
}
