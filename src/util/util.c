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

static void free_args(char **args)
{
    int i;

    if (args) {
        for (i = 0; args[i]; i++) free(args[i]);
        free(args);
    }
}

/* parse a string into arguments.
 * arguments are separated by a space
 * '\' is an escape character and can be used only to escape
 * itself or the white space.
 */
char **parse_args(const char *str)
{
    const char *p;
    char **ret, **r;
    char *tmp;
    int num;
    int i, e;

    tmp = malloc(strlen(str) + 1);
    if (!tmp) return NULL;

    ret = NULL;
    num = 0;
    e = 0;
    i = 0;
    p = str;
    while (*p) {
        switch (*p) {
        case '\\':
            if (e) {
                tmp[i] = '\\';
                i++;
                e = 0;
            } else {
                e = 1;
            }
            break;
        case ' ':
            if (e) {
                tmp[i] = ' ';
                i++;
                e = 0;
            } else {
                tmp[i] = '\0';
                i++;
            }
            break;
        default:
            if (e) {
                tmp[i] = '\\';
                i++;
                e = 0;
            }
            tmp[i] = *p;
            i++;
            break;
        }

        p++;

        /* check if this was the last char */
        if (*p == '\0') {
            if (e) {
                tmp[i] = '\\';
                i++;
                e = 0;
            }
            tmp[i] = '\0';
            i++;
        }
        if (tmp[i-1] != '\0' || strlen(tmp) == 0) {
            /* check next char and skip multiple spaces */
            continue;
        }

        r = realloc(ret, (num + 2) * sizeof(char *));
        if (!r) goto fail;
        ret = r;
        ret[num+1] = NULL;
        ret[num] = strdup(tmp);
        if (!ret[num]) goto fail;
        num++;
        i = 0;
    }

    free(tmp);
    return ret;

fail:
    free(tmp);
    free_args(ret);
    return NULL;
}
