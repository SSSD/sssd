/*
    Authors:
        Lukas Slebodnik  <slebodnikl@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include "util/util.h"
#include "tests/cmocka/common_mock.h"

void test_replace_whitespaces(void **state)
{
    TALLOC_CTX *mem_ctx;
    const char *input_str = "Lorem ipsum dolor sit amet";
    const char *res;
    size_t i;

    struct {
        const char *input;
        const char *output;
        const char replace_char;
    } data_set[] = {
        { "", "", '-' },
        { " ", "-", '-' },
        { "abcd", "abcd", '-' },
        { "a b c d", "a-b-c-d", '-' },
        { " a b c d ", "-a-b-c-d-", '-' },
        { " ", "^", '^' },
        { "abcd", "abcd", '^' },
        { "a b c d", "a^b^c^d", '^' },
        { " a b c d ", "^a^b^c^d^", '^' },
        { " ", "^", '^' },
        { " ", " ", ' ' },
        { "    ", "    ", ' ' },
        { "abcd", "abcd", ' ' },
        { "a b c d", "a b c d", ' ' },
        { "a b^c d", "a b^c d", '^' },
        { NULL, NULL, '\0' },
    };

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);
    check_leaks_push(mem_ctx);

    res = sss_replace_space(mem_ctx, input_str, '\0');
    assert_string_equal(res, input_str);
    talloc_zfree(res);

    res = sss_replace_space(mem_ctx, input_str, '\0');
    assert_string_equal(res, input_str);
    talloc_zfree(res);

    for (i=0; data_set[i].input != NULL; ++i) {
        res = sss_replace_space(mem_ctx, data_set[i].input,
                                data_set[i].replace_char);
        assert_non_null(res);
        assert_string_equal(res, data_set[i].output);
        talloc_zfree(res);
    }

    assert_true(check_leaks_pop(mem_ctx) == true);
    talloc_free(mem_ctx);
}

void test_reverse_replace_whitespaces(void **state)
{
    TALLOC_CTX *mem_ctx;
    char *input_str = discard_const_p(char, "Lorem ipsum dolor sit amet");
    char *res;
    size_t i;

    struct {
        const char *input;
        const char *output;
        const char replace_char;
    } data_set[] = {
        { "", "", '-' },
        { "-", " ", '-' },
        { "----", "    ", '-' },
        { "abcd", "abcd", '-' },
        { "a-b-c-d", "a b c d", '-' },
        { "-a-b-c-d-", " a b c d ", '-' },
        { "a b c d", "a b c d", '-' },
        { " a b c d ", " a b c d ", '-' },
        { "^", " ", '^' },
        { "^^^^", "    ", '^' },
        { "abcd", "abcd", '^' },
        { "a^b^c^d", "a b c d", '^' },
        { "^a^b^c^d^", " a b c d ", '^' },
        { " ", " ", ' ' },
        { "    ", "    ", ' ' },
        { "abcd", "abcd", ' ' },
        { "a b c d", "a b c d", ' ' },
        { " a b c d ", " a b c d ", ' ' },
        { "a b^c d", "a b^c d", '^' },
        { NULL, NULL, '\0' },
    };

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);
    check_leaks_push(mem_ctx);

    res = sss_reverse_replace_space(mem_ctx, input_str, '\0');
    assert_string_equal(res, input_str);
    talloc_free(res);

    res = sss_reverse_replace_space(mem_ctx, input_str, '\0');
    assert_string_equal(res, input_str);
    talloc_free(res);

    for (i=0; data_set[i].input != NULL; ++i) {
        input_str = discard_const_p(char, data_set[i].input);
        res = sss_reverse_replace_space(mem_ctx, input_str,
                                        data_set[i].replace_char);
        assert_non_null(res);
        assert_string_equal(res, data_set[i].output);
        talloc_zfree(res);
    }

    assert_true(check_leaks_pop(mem_ctx) == true);
    talloc_free(mem_ctx);
}

void test_guid_blob_to_string_buf(void **state)
{
    int ret;
    char str_buf[GUID_STR_BUF_SIZE];
    size_t c;

    /* How to get test data:
     * The objectGUID attribute contains a 16byte long binary value
     * representing the GUID of the object. This data can be converted
     * manually to the string representation but it might be easier to use
     * LDAP_SERVER_EXTENDED_DN_OID as described in [MS-ADST] section
     * 3.1.1.3.4.1.5. This is an LDAP extended control which adds the GUID and
     * the SID to the DN of an object. This can be activate with the -E
     * ldapsearch option like:
     *
     *  ldapsearch -E 1.2.840.113556.1.4.529=::MAMCAQE= ....
     *
     * where 'MAMCAQE=' is the base64 encoded BER sequence with the integer
     * value 1 (see [MS-ADTS] for details about possible values).
     *
     * Btw, if you want to use the string representation of a GUID to search
     * for an object in AD you have to use the GUID as the search base in the
     * following form:
     *
     *  ldapsearch b '<GUID=fea80d8d-dbd5-4f84-8574-7db0477f962e>' ...
     *
     * (please note that the '<' and '>' are really needed).
     */
    struct test_data {
        uint8_t blob[16];
        const char *guid_str;
    } test_data[] = {
        {{0x8d, 0x0d, 0xa8, 0xfe, 0xd5, 0xdb, 0x84, 0x4f,
          0x85, 0x74, 0x7d, 0xb0, 0x47, 0x7f, 0x96, 0x2e},
        "fea80d8d-dbd5-4f84-8574-7db0477f962e"},
        {{0x91, 0x7e, 0x2e, 0xf8, 0x4e, 0x44, 0xfa, 0x4e,
         0xb1, 0x13, 0x08, 0x98, 0x63, 0x49, 0x6c, 0xc6},
        "f82e7e91-444e-4efa-b113-089863496cc6"},
        {{0}, NULL}
    };

    ret = guid_blob_to_string_buf(NULL, str_buf, GUID_STR_BUF_SIZE);
    assert_int_equal(ret, EINVAL);

    ret = guid_blob_to_string_buf((const uint8_t *) "1234567812345678", NULL,
                                  GUID_STR_BUF_SIZE);
    assert_int_equal(ret, EINVAL);

    ret = guid_blob_to_string_buf((const uint8_t *) "1234567812345678", str_buf, 0);
    assert_int_equal(ret, EINVAL);

    for (c = 0; test_data[c].guid_str != NULL; c++) {
        ret = guid_blob_to_string_buf(test_data[c].blob, str_buf,
                                      sizeof(str_buf));
        assert_int_equal(ret, EOK);
        assert_string_equal(test_data[c].guid_str, str_buf);
    }
}

void test_get_last_x_chars(void **state)
{
    const char *s;

    s = get_last_x_chars(NULL, 0);
    assert_null(s);

    s = get_last_x_chars("abc", 0);
    assert_non_null(s);
    assert_string_equal(s, "");

    s = get_last_x_chars("abc", 1);
    assert_non_null(s);
    assert_string_equal(s, "c");

    s = get_last_x_chars("abc", 2);
    assert_non_null(s);
    assert_string_equal(s, "bc");

    s = get_last_x_chars("abc", 3);
    assert_non_null(s);
    assert_string_equal(s, "abc");

    s = get_last_x_chars("abc", 4);
    assert_non_null(s);
    assert_string_equal(s, "abc");
}

void test_concatenate_string_array(void **state)
{
    TALLOC_CTX *mem_ctx;
    char **a1;
    size_t a1_len = 2;
    char **a2;
    size_t a2_len = 3;
    char **res;
    size_t c;

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);
    check_leaks_push(mem_ctx);

    res = concatenate_string_array(mem_ctx, NULL, 0, NULL, 0);
    assert_non_null(res);
    assert_null(res[0]);
    talloc_free(res);

    a1 = talloc_array(mem_ctx, char *, a1_len);
    assert_non_null(a1);
    for (c = 0; c < a1_len; c++) {
        a1[c] = talloc_asprintf(a1, "%zu", c);
        assert_non_null(a1[c]);
    }

    a2 = talloc_array(mem_ctx, char *, a2_len);
    assert_non_null(a2);
    for (c = 0; c < a2_len; c++) {
        a2[c] = talloc_asprintf(a2, "%zu", c + a1_len);
        assert_non_null(a2[c]);
    }

    res = concatenate_string_array(mem_ctx, a1, a1_len, a2, a2_len);
    assert_non_null(res);
    assert_null(res[a1_len + a2_len]);
    for (c = 0; c < (a1_len + a2_len); c++) {
        assert_string_equal(res[c], talloc_asprintf(res, "%zu", c));
    }

    talloc_free(res);
    /* Since concatenate_string_array() uses talloc_realloc on a1 it should
     * not be needed to free a1 explicitly. */
    talloc_free(a2);

    assert_true(check_leaks_pop(mem_ctx) == true);
    talloc_free(mem_ctx);
}
