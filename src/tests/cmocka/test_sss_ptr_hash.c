/*
    Copyright (C) 2020 Red Hat

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

#include "tests/cmocka/common_mock.h"
#include "util/sss_ptr_hash.h"

static const int MAX_ENTRIES_AMOUNT = 5;

static void populate_table(hash_table_t *table, int **payloads)
{
    char key[2] = {'z', 0};

    for (int i = 0; i < MAX_ENTRIES_AMOUNT; ++i) {
        payloads[i] = talloc_zero(global_talloc_context, int);
        assert_non_null(payloads[i]);
        *payloads[i] = i;
        key[0] = '0'+(char)i;
        assert_int_equal(sss_ptr_hash_add(table, key, payloads[i], int), 0);
    }

    assert_int_equal((int)hash_count(table), MAX_ENTRIES_AMOUNT);
}

static void free_payload_cb(hash_entry_t *item, hash_destroy_enum type, void *pvt)
{
    int *counter;

    assert_non_null(item);
    assert_non_null(item->value.ptr);
    talloc_zfree(item->value.ptr);

    assert_non_null(pvt);
    counter = (int *)pvt;
    (*counter)++;
}

void test_sss_ptr_hash_with_free_cb(void **state)
{
    hash_table_t *table;
    int free_counter = 0;
    int *payloads[MAX_ENTRIES_AMOUNT];

    table = sss_ptr_hash_create(global_talloc_context,
                                free_payload_cb,
                                &free_counter);
    assert_non_null(table);

    populate_table(table, payloads);

    /* check explicit removal from the hash */
    sss_ptr_hash_delete(table, "1", false);
    assert_int_equal((int)hash_count(table), MAX_ENTRIES_AMOUNT-1);
    assert_int_equal(free_counter, 1);

    /* check implicit removal triggered by payload deletion */
    talloc_free(payloads[3]);
    assert_int_equal((int)hash_count(table), MAX_ENTRIES_AMOUNT-2);
    assert_int_equal(free_counter, 2);

    /* try to remove non existent entry */
    sss_ptr_hash_delete(table, "q", false);
    assert_int_equal((int)hash_count(table), MAX_ENTRIES_AMOUNT-2);
    assert_int_equal(free_counter, 2);

    /* clear all */
    sss_ptr_hash_delete_all(table, false);
    assert_int_equal((int)hash_count(table), 0);
    assert_int_equal(free_counter, MAX_ENTRIES_AMOUNT);

    /* check that table is still operable */
    populate_table(table, payloads);
    sss_ptr_hash_delete(table, "2", false);
    assert_int_equal((int)hash_count(table), MAX_ENTRIES_AMOUNT-1);
    assert_int_equal(free_counter, MAX_ENTRIES_AMOUNT+1);

    talloc_free(table);
    assert_int_equal(free_counter, MAX_ENTRIES_AMOUNT*2);
}

void test_sss_ptr_hash_overwrite_with_free_cb(void **state)
{
    hash_table_t *table;
    int free_counter = 0;
    unsigned long count;
    char *payload;
    char *value;
    errno_t ret;

    table = sss_ptr_hash_create(global_talloc_context,
                                free_payload_cb,
                                &free_counter);
    assert_non_null(table);

    payload = talloc_strdup(table, "test_value1");
    assert_non_null(payload);
    talloc_set_name_const(payload, "char");
    ret = sss_ptr_hash_add_or_override(table, "test", payload, char);
    assert_int_equal(ret, 0);
    count = hash_count(table);
    assert_int_equal(count, 1);
    value = sss_ptr_hash_lookup(table, "test", char);
    assert_ptr_equal(value, payload);


    payload = talloc_strdup(table, "test_value2");
    assert_non_null(payload);
    talloc_set_name_const(payload, "char");
    ret = sss_ptr_hash_add_or_override(table, "test", payload, char);
    assert_int_equal(ret, 0);
    count = hash_count(table);
    assert_int_equal(count, 1);
    value = sss_ptr_hash_lookup(table, "test", char);
    assert_ptr_equal(value, payload);

    talloc_free(table);
    assert_int_equal(free_counter, 2);
}

struct table_wrapper
{
    hash_table_t **table;
};

static void lookup_cb(hash_entry_t *item, hash_destroy_enum type, void *pvt)
{
    hash_table_t *table;
    hash_key_t *keys;
    unsigned long count;
    int *value = NULL;
    int sum = 0;

    assert_non_null(pvt);
    table = *((struct table_wrapper *)pvt)->table;
    assert_non_null(table);

    if (type == HASH_TABLE_DESTROY) {
        /* table is being destroyed */
        return;
    }

    assert_int_equal(hash_keys(table, &count, &keys), HASH_SUCCESS);
    for (unsigned int i = 0; i < count; ++i) {
        assert_int_equal(keys[i].type, HASH_KEY_STRING);
        value = sss_ptr_hash_lookup(table, keys[i].c_str, int);
        assert_non_null(value);
        sum += *value;
    }
    DEBUG(SSSDBG_TRACE_ALL, "sum of all values = %d\n", sum);
    talloc_free(keys);
}

/* main difference with `test_sss_ptr_hash_with_free_cb()`
 * is that table cb here doesn't delete payload so
 * this is requested via `free_value(s)` arg
 */
void test_sss_ptr_hash_with_lookup_cb(void **state)
{
    hash_table_t *table;
    struct table_wrapper wrapper;
    int *payloads[MAX_ENTRIES_AMOUNT];

    wrapper.table = &table;
    table = sss_ptr_hash_create(global_talloc_context,
                                lookup_cb,
                                &wrapper);
    assert_non_null(table);

    populate_table(table, payloads);

    /* check explicit removal from the hash */
    sss_ptr_hash_delete(table, "2", true);
    assert_int_equal((int)hash_count(table), MAX_ENTRIES_AMOUNT-1);

    /* check implicit removal triggered by payload deletion */
    talloc_free(payloads[0]);
    assert_int_equal((int)hash_count(table), MAX_ENTRIES_AMOUNT-2);

    /* clear all */
    sss_ptr_hash_delete_all(table, true);
    assert_int_equal((int)hash_count(table), 0);
    /* teardown function shall verify there are no leaks
     * on global_talloc_context and so that payloads[] were freed
     */

    /* check that table is still operable */
    populate_table(table, payloads);

    talloc_free(table);
    /* d-tor triggers hash_destroy() but since cb here doesn free payload
     * this should be done manually
     */
    for (int i = 0; i < MAX_ENTRIES_AMOUNT; ++i) {
        talloc_free(payloads[i]);
    }
}

/* Just smoke test to verify that absence of cb doesn't break anything */
void test_sss_ptr_hash_without_cb(void **state)
{
    hash_table_t *table;
    int *payloads[MAX_ENTRIES_AMOUNT];

    table = sss_ptr_hash_create(global_talloc_context, NULL, NULL);
    assert_non_null(table);

    populate_table(table, payloads);

    sss_ptr_hash_delete(table, "4", true);
    assert_int_equal((int)hash_count(table), MAX_ENTRIES_AMOUNT-1);

    talloc_free(payloads[1]);
    assert_int_equal((int)hash_count(table), MAX_ENTRIES_AMOUNT-2);

    sss_ptr_hash_delete_all(table, true);
    assert_int_equal((int)hash_count(table), 0);

    talloc_free(table);
}
