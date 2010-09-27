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
#include "dhash.h"

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

char **dup_string_list(TALLOC_CTX *memctx, const char **str_list)
{
    int i = 0;
    int j = 0;
    char **dup_list;

    if (!str_list) {
        return NULL;
    }

    /* Find the size of the list */
    while (str_list[i]) i++;

    dup_list = talloc_array(memctx, char *, i+1);
    if (!dup_list) {
        return NULL;
    }

    /* Copy the elements */
    for (j = 0; j < i; j++) {
        dup_list[j] = talloc_strdup(dup_list, str_list[j]);
        if (!dup_list[j]) {
            talloc_free(dup_list);
            return NULL;
        }
    }

    /* NULL-terminate the list */
    dup_list[i] = NULL;

    return dup_list;
}

/* Take two string lists (terminated on a NULL char*)
 * and return up to three arrays of strings based on
 * shared ownership.
 *
 * Pass NULL to any return type you don't care about
 */
errno_t diff_string_lists(TALLOC_CTX *memctx,
                          char **_list1,
                          char **_list2,
                          char ***_list1_only,
                          char ***_list2_only,
                          char ***_both_lists)
{
    int error;
    errno_t ret;
    int i;
    int i2 = 0;
    int i12 = 0;
    hash_table_t *table;
    hash_key_t key;
    hash_value_t value;
    char **list1 = NULL;
    char **list2 = NULL;
    char **list1_only = NULL;
    char **list2_only = NULL;
    char **both_lists = NULL;
    unsigned long count;
    hash_key_t *keys;

    TALLOC_CTX *tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (!_list1) {
        list1 = talloc_array(tmp_ctx, char *, 1);
        if (!list1) {
            talloc_free(tmp_ctx);
            return ENOMEM;
        }
        list1[0] = NULL;
    }
    else {
        list1 = _list1;
    }

    if (!_list2) {
        list2 = talloc_array(tmp_ctx, char *, 1);
        if (!list2) {
            talloc_free(tmp_ctx);
            return ENOMEM;
        }
        list2[0] = NULL;
    }
    else {
        list2 = _list2;
    }

    error = hash_create(10, &table, NULL, NULL);
    if (error != HASH_SUCCESS) {
        talloc_free(tmp_ctx);
        return EIO;
    }

    key.type = HASH_KEY_STRING;
    value.type = HASH_VALUE_UNDEF;

    /* Add all entries from list 1 into a hash table */
    i = 0;
    while (list1[i]) {
        key.str = talloc_strdup(tmp_ctx, list1[i]);
        error = hash_enter(table, &key, &value);
        if (error != HASH_SUCCESS) {
            ret = EIO;
            goto done;
        }
        i++;
    }

    /* Iterate through list 2 and remove matching items */
    i = 0;
    while (list2[i]) {
        key.str = talloc_strdup(tmp_ctx, list2[i]);
        error = hash_delete(table, &key);
        if (error == HASH_SUCCESS) {
            if (_both_lists) {
                /* String was present in both lists */
                i12++;
                both_lists = talloc_realloc(tmp_ctx, both_lists, char *, i12+1);
                if (!both_lists) {
                    ret = ENOMEM;
                    goto done;
                }
                both_lists[i12-1] = talloc_strdup(both_lists, list2[i]);
                if (!both_lists[i12-1]) {
                    ret = ENOMEM;
                    goto done;
                }

                both_lists[i12] = NULL;
            }
        }
        else if (error == HASH_ERROR_KEY_NOT_FOUND) {
            if (_list2_only) {
                /* String was present only in list2 */
                i2++;
                list2_only = talloc_realloc(tmp_ctx, list2_only,
                                            char *, i2+1);
                if (!list2_only) {
                    ret = ENOMEM;
                    goto done;
                }
                list2_only[i2-1] = talloc_strdup(list2_only, list2[i]);
                if (!list2_only[i2-1]) {
                    ret = ENOMEM;
                    goto done;
                }

                list2_only[i2] = NULL;
            }
        }
        else {
            /* An error occurred */
            ret = EIO;
            goto done;
        }
        i++;
    }

    /* Get the leftover entries in the hash table */
    if (_list1_only) {
        error = hash_keys(table, &count, &keys);
        if (error != HASH_SUCCESS) {
            ret = EIO;
            goto done;
        }

        list1_only = talloc_array(tmp_ctx, char *, count+1);
        if (!list1_only) {
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; i < count; i++) {
            list1_only[i] = talloc_strdup(list1_only, keys[i].str);
            if (!list1_only[i]) {
                ret = ENOMEM;
                goto done;
            }
        }
        list1_only[count] = NULL;

        free(keys);

        *_list1_only = talloc_steal(memctx, list1_only);
    }

    if (_list2_only) {
        if (list2_only) {
            *_list2_only = talloc_steal(memctx, list2_only);
        }
        else {
            *_list2_only = talloc_array(memctx, char *, 1);
            if (!(*_list2_only)) {
                ret = ENOMEM;
                goto done;
            }
            *_list2_only[0] = NULL;
        }
    }

    if (_both_lists) {
        if (both_lists) {
            *_both_lists = talloc_steal(memctx, both_lists);
        }
        else {
            *_both_lists = talloc_array(memctx, char *, 1);
            if (!(*_both_lists)) {
                ret = ENOMEM;
                goto done;
            }
            *_both_lists[0] = NULL;
        }
    }

    ret = EOK;

done:
    hash_destroy(table);
    talloc_free(tmp_ctx);
    return ret;
}

static void *hash_talloc(const size_t size, void *pvt)
{
    return talloc_size(pvt, size);
}

static void hash_talloc_free(void *ptr, void *pvt)
{
    talloc_free(ptr);
}

errno_t sss_hash_create(TALLOC_CTX *mem_ctx,
                        unsigned long count,
                        hash_table_t **tbl)
{
    errno_t ret;
    hash_table_t *table;
    int hret;

    TALLOC_CTX *internal_ctx;
    internal_ctx = talloc_new(NULL);
    if (!internal_ctx) {
        return ENOMEM;
    }

    hret = hash_create_ex(count, &table, 0, 0, 0, 0,
                          hash_talloc, hash_talloc_free,
                          internal_ctx, NULL, NULL);
    switch (hret) {
    case HASH_SUCCESS:
        /* Steal the table pointer onto the mem_ctx,
         * then make the internal_ctx a child of
         * table.
         *
         * This way, we can clean up the values when
         * we talloc_free() the table
         */
        *tbl = talloc_steal(mem_ctx, table);
        talloc_steal(table, internal_ctx);
        return EOK;

    case HASH_ERROR_NO_MEMORY:
        ret = ENOMEM;
    default:
        ret = EIO;
    }

    DEBUG(0, ("Could not create hash table: [%d][%s]\n",
              hret, hash_error_string(hret)));

    talloc_free(internal_ctx);
    return ret;
}
