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
        const char *replace_string;
    } data_set[] = {
        { "", "", "-" },
        { " ", "-", "-" },
        { "\t", "-", "-" },
        { "\n", "-", "-" },
        { " \t\n ", "----", "-" },
        { "abcd", "abcd", "-" },
        { "a b c d", "a-b-c-d", "-" },
        { " a b c d ", "-a-b-c-d-", "-" },
        { " ", "^", "^" },
        { "\t", "^", "^" },
        { "\n", "^", "^" },
        { " \t\n ", "^^^^", "^" },
        { "abcd", "abcd", "^" },
        { "a b c d", "a^b^c^d", "^" },
        { " a b c d ", "^a^b^c^d^", "^" },
        { " ", "^", "^" },
        { "\t", ";-)", ";-)" },
        { "\n", ";-)", ";-)" },
        { " \t\n ", ";-);-);-);-)", ";-)" },
        { "abcd", "abcd", ";-)" },
        { "a b c d", "a;-)b;-)c;-)d", ";-)" },
        { " a b c d ", ";-)a;-)b;-)c;-)d;-)", ";-)" },
        { " ", " ", " " },
        { "    ", "    ", " " },
        { "abcd", "abcd", " " },
        { "a b c d", "a b c d", " " },
        { " a b c d ", " a b c d ", " " },
        { " ", " \t", " \t" },
        { "    ", " \t \t \t \t", " \t" },
        { "abcd", "abcd", " \t" },
        { "a b c d", "a \tb \tc \td", " \t" },
        { " a b c d ", " \ta \tb \tc \td \t", " \t" },
        { NULL, NULL, NULL },
    };

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);
    check_leaks_push(mem_ctx);

    res = sss_replace_whitespaces(mem_ctx, input_str, NULL);
    assert_true(res == input_str);

    res = sss_replace_whitespaces(mem_ctx, input_str, "");
    assert_true(res == input_str);

    for (i=0; data_set[i].input != NULL; ++i) {
        res = sss_replace_whitespaces(mem_ctx, data_set[i].input,
                                      data_set[i].replace_string);
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
        const char *replace_string;
    } data_set[] = {
        { "", "", "-" },
        { "-", " ", "-" },
        { "----", "    ", "-" },
        { "abcd", "abcd", "-" },
        { "a-b-c-d", "a b c d", "-" },
        { "-a-b-c-d-", " a b c d ", "-" },
        { "^", " ", "^" },
        { "^^^^", "    ", "^" },
        { "abcd", "abcd", "^" },
        { "a^b^c^d", "a b c d", "^" },
        { "^a^b^c^d^", " a b c d ", "^" },
        { ";-)", " ", ";-)" },
        { ";-);-);-);-)", "    ", ";-)" },
        { "abcd", "abcd", ";-)" },
        { "a;-)b;-)c;-)d", "a b c d", ";-)" },
        { ";-)a;-)b;-)c;-)d;-)", " a b c d ", ";-)" },
        { " ", " ", " " },
        { "    ", "    ", " " },
        { "abcd", "abcd", " " },
        { "a b c d", "a b c d", " " },
        { " a b c d ", " a b c d ", " " },
        { NULL, NULL, NULL },
    };

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);
    check_leaks_push(mem_ctx);

    res = sss_reverse_replace_whitespaces(mem_ctx, input_str, NULL);
    assert_true(res == input_str);

    res = sss_reverse_replace_whitespaces(mem_ctx, input_str, "");
    assert_true(res == input_str);

    for (i=0; data_set[i].input != NULL; ++i) {
        input_str = discard_const_p(char, data_set[i].input);
        res = sss_reverse_replace_whitespaces(mem_ctx, input_str,
                                      data_set[i].replace_string);
        assert_non_null(res);
        assert_string_equal(res, data_set[i].output);
        talloc_zfree(res);
    }

    assert_true(check_leaks_pop(mem_ctx) == true);
    talloc_free(mem_ctx);
}
