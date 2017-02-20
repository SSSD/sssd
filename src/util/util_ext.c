/*
   SSSD helper calls - can be used by libraries for external use as well

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include <talloc.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>

#define EOK 0

int split_on_separator(TALLOC_CTX *mem_ctx, const char *str,
                       const char sep, bool trim, bool skip_empty,
                       char ***_list, int *size)
{
    int ret;
    const char *substr_end = str;
    const char *substr_begin = str;
    const char *sep_pos = NULL;
    size_t substr_len;
    char **list = NULL;
    int num_strings = 0;
    TALLOC_CTX *tmp_ctx = NULL;

    if (str == NULL || *str == '\0' || _list == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    do {
        substr_len = 0;

        /* If this is not the first substring, then move from the separator. */
        if (sep_pos != NULL) {
            substr_end = sep_pos + 1;
            substr_begin = sep_pos + 1;
        }

        /* Find end of the first substring */
        while (*substr_end != sep && *substr_end != '\0') {
            substr_end++;
            substr_len++;
        }

        sep_pos = substr_end;

        if (trim) {
            /* Trim leading whitespace */
            while (isspace(*substr_begin) && substr_begin < substr_end) {
                substr_begin++;
                substr_len--;
            }

            /* Trim trailing whitespace */
            while (substr_end - 1 > substr_begin && isspace(*(substr_end-1))) {
                substr_end--;
                substr_len--;
            }
        }

        /* Copy the substring to the output list of strings */
        if (skip_empty == false || substr_len > 0) {
            list = talloc_realloc(tmp_ctx, list, char*, num_strings + 2);
            if (list == NULL) {
                ret = ENOMEM;
                goto done;
            }

            /* empty string is stored for substr_len == 0 */
            list[num_strings] = talloc_strndup(list, substr_begin, substr_len);
            if (list[num_strings] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            num_strings++;
        }

    } while (*sep_pos != '\0');

    if (list == NULL) {
        /* No allocations were done, make space for the NULL */
        list = talloc(tmp_ctx, char *);
        if (list == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }
    list[num_strings] = NULL;

    if (size) {
        *size = num_strings;
    }

    *_list = talloc_steal(mem_ctx, list);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

bool string_in_list(const char *string, char **list, bool case_sensitive)
{
    size_t c;
    int(*compare)(const char *s1, const char *s2);

    if (string == NULL || list == NULL || *list == NULL) {
        return false;
    }

    compare = case_sensitive ? strcmp : strcasecmp;

    for (c = 0; list[c] != NULL; c++) {
        if (compare(string, list[c]) == 0) {
            return true;
        }
    }

    return false;
}
