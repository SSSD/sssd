/*
    Authors:
        Lukas Slebodnik <lslebodn@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: Tests for utility functions

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

#ifndef __TESTS__CMOCKA__TEST_UTILS_H__
#define __TESTS__CMOCKA__TEST_UTILS_H__

/* from src/tests/cmocka/test_sss_ssh.c */
void test_textual_public_key(void **state);

/* from src/tests/cmocka/test_string_utils.c */
void test_replace_whitespaces(void **state);
void test_reverse_replace_whitespaces(void **state);
void test_guid_blob_to_string_buf(void **state);
void test_get_last_x_chars(void **state);
void test_string_ends_with(void **state);
void test_concatenate_string_array(void **state);
void test_mod_defaults_list(void **state);

/* from src/tests/cmocka/test_sss_ptr_hash.c */
void test_sss_ptr_hash_with_free_cb(void **state);
void test_sss_ptr_hash_overwrite_with_free_cb(void **state);
void test_sss_ptr_hash_with_lookup_cb(void **state);
void test_sss_ptr_hash_without_cb(void **state);


#endif /* __TESTS__CMOCKA__TEST_UTILS_H__ */
