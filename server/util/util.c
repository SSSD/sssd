/*
    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <ctype.h>

#include "talloc.h"
#include "util/util.h"

/* split a string into an allocated array of strings.
 * the separator is a string, and is case-sensitive.
 * optionally single values can be trimmed of of spaces and tabs */
int split_on_separator(TALLOC_CTX *mem_ctx, const char *str,
                       const char sep, bool trim, char ***_list, int *size)
{
    const char *t, *p, *n;
    size_t l, len;
    char **list, **r;
    const char sep_str[2] = { sep, '\0'};

    if (!str || !*str || !_list) return EINVAL;

    t = str;

    list = NULL;
    l = 0;

    /* trim leading whitespace */
    if (trim)
        while (isspace(*t)) t++;

    /* find substrings separated by the separator */
    while (t && (p = strpbrk(t, sep_str))) {
        len = p - t;
        n = p + 1; /* save next string starting point */
        if (trim) {
            /* strip whitespace after the separator
             * so it's not in the next token */
            while (isspace(*t)) {
                t++;
                len--;
                if (len == 0) break;
            }
            p--;
            /* strip whitespace before the separator
             * so it's not in the current token */
            while (len > 0 && (isspace(*p))) {
                len--;
                p--;
            }
        }

        /* Add the token to the array, +2 b/c of the trailing NULL */
        r = talloc_realloc(mem_ctx, list, char *, l + 2);
        if (!r) {
            talloc_free(list);
            return ENOMEM;
        } else {
            list = r;
        }

        if (len == 0) {
            list[l] = talloc_strdup(list, "");
        } else {
            list[l] = talloc_strndup(list, t, len);
        }
        if (!list[l]) {
            talloc_free(list);
            return ENOMEM;
        }
        l++;

        t = n; /* move to next string */
    }

    /* Handle the last remaining token */
    if (t) {
        r = talloc_realloc(mem_ctx, list, char *, l + 2);
        if (!r) {
            talloc_free(list);
            return ENOMEM;
        } else {
            list = r;
        }

        if (trim) {
            /* trim leading whitespace */
            len = strlen(t);
            while (isspace(*t)) {
                t++;
                len--;
                if (len == 0) break;
            }
            /* trim trailing whitespace */
            p = t + len - 1;
            while (len > 0 && (isspace(*p))) {
                len--;
                p--;
            }

            if (len == 0) {
                list[l] = talloc_strdup(list, "");
            } else {
                list[l] = talloc_strndup(list, t, len);
            }
        } else {
            list[l] = talloc_strdup(list, t);
        }
        if (!list[l]) {
            talloc_free(list);
            return ENOMEM;
        }
        l++;
    }

    list[l] = NULL; /* terminate list */

    if (size) *size = l + 1;
    *_list = list;

    return EOK;
}
