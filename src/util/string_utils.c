/*
    SSSD

    Authors:
        Lukas Slebodnik <slebodnikl@redhat.com>

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

const char * sss_replace_whitespaces(TALLOC_CTX *mem_ctx,
                                     const char *orig_name,
                                     const char *replace_string)
{
    char *new_name;
    const char *ptr;
    size_t replace_string_len;
    TALLOC_CTX *tmp_ctx;

    if (replace_string == NULL || replace_string[0] == '\0') {
        return orig_name;
    }

    replace_string_len = strlen(replace_string);
    /* faster implementations without multiple allocations */
    if (replace_string_len == 1) {
        char *p;
        new_name = talloc_strdup(mem_ctx, orig_name);
        if (new_name == NULL) {
            return NULL;
        }

        for (p = new_name; *p != '\0'; ++p) {
            if (isspace(*p)) {
                *p = replace_string[0];
            }
        }

        return new_name;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    new_name = talloc_strdup(tmp_ctx, "");
    if (new_name == NULL) {
        goto done;
    }

    ptr = orig_name;
    while (*ptr != '\0') {
        if (isspace(*ptr)) {
            new_name = talloc_asprintf_append(new_name, "%s", replace_string);
        } else {
            new_name = talloc_asprintf_append(new_name, "%c", *ptr);
        }
        if (new_name == NULL) {
            goto done;;
        }

        ++ptr;
    }

    new_name = talloc_steal(mem_ctx, new_name);
done:
    talloc_free(tmp_ctx);
    return new_name;
}

char * sss_reverse_replace_whitespaces(TALLOC_CTX *mem_ctx,
                                       char *orig_name,
                                       const char *replace_string)
{
    TALLOC_CTX *tmp_ctx;
    char *substr;
    char *new_name;
    const char *ptr = orig_name;
    size_t replace_string_len;

    if (replace_string == NULL || replace_string[0] == '\0') {
        return orig_name;
    }

    replace_string_len = strlen(replace_string);
    /* faster implementations without multiple allocations */
    if (replace_string_len == 1) {
        char *p;
        new_name = talloc_strdup(mem_ctx, orig_name);
        if (new_name == NULL) {
            return NULL;
        }

        for (p = new_name; *p != '\0'; ++p) {
            if (*p == replace_string[0] ) {
                *p = ' ';
            }
        }

        return new_name;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    new_name = talloc_strdup(tmp_ctx, "");
    if (new_name == NULL) {
        goto done;
    }

    do {
        substr = strstr(ptr, replace_string);
        if (substr != NULL) {
            new_name = talloc_asprintf_append(new_name, "%.*s ",
                                              (int)(substr - ptr), ptr);
            if (new_name == NULL) {
                goto done;
            }
            ptr += substr - ptr;
            ptr += replace_string_len;
        } else {
            new_name = talloc_asprintf_append(new_name, "%s", ptr);
            if (new_name == NULL) {
                goto done;
            }
        }
    } while (substr != NULL);

    new_name = talloc_steal(mem_ctx, new_name);
done:
    talloc_free(tmp_ctx);
    return new_name;
}
