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

#ifndef HAVE_ERRNO_T
#define HAVE_ERRNO_T
typedef int errno_t;
#endif

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

errno_t sss_filter_sanitize_ex(TALLOC_CTX *mem_ctx,
                               const char *input,
                               char **sanitized,
                               const char *ignore)
{
    char *output;
    size_t i = 0;
    size_t j = 0;
    char *allowed;

    /* Assume the worst-case. We'll resize it later, once */
    output = talloc_array(mem_ctx, char, strlen(input) * 3 + 1);
    if (!output) {
        return ENOMEM;
    }

    while (input[i]) {
        /* Even though this character might have a special meaning, if it's
         * explicitly allowed, just copy it and move on
         */
        if (ignore == NULL) {
            allowed = NULL;
        } else {
            allowed = strchr(ignore, input[i]);
        }
        if (allowed) {
            output[j++] = input[i++];
            continue;
        }

        switch(input[i]) {
        case '\t':
            output[j++] = '\\';
            output[j++] = '0';
            output[j++] = '9';
            break;
        case ' ':
            output[j++] = '\\';
            output[j++] = '2';
            output[j++] = '0';
            break;
        case '*':
            output[j++] = '\\';
            output[j++] = '2';
            output[j++] = 'a';
            break;
        case '(':
            output[j++] = '\\';
            output[j++] = '2';
            output[j++] = '8';
            break;
        case ')':
            output[j++] = '\\';
            output[j++] = '2';
            output[j++] = '9';
            break;
        case '\\':
            output[j++] = '\\';
            output[j++] = '5';
            output[j++] = 'c';
            break;
        case '\r':
            output[j++] = '\\';
            output[j++] = '0';
            output[j++] = 'd';
            break;
        case '\n':
            output[j++] = '\\';
            output[j++] = '0';
            output[j++] = 'a';
            break;
        default:
            output[j++] = input[i];
        }

        i++;
    }
    output[j] = '\0';
    *sanitized = talloc_realloc(mem_ctx, output, char, j+1);
    if (!*sanitized) {
        talloc_free(output);
        return ENOMEM;
    }

    return EOK;
}

errno_t sss_filter_sanitize(TALLOC_CTX *mem_ctx,
                            const char *input,
                            char **sanitized)
{
    return sss_filter_sanitize_ex(mem_ctx, input, sanitized, NULL);
}

/* There is similar function ldap_dn_normalize in openldap.
 * To avoid dependecies across project we have this own func.
 * Also ldb can do this but doesn't handle all the cases
 */
static errno_t sss_trim_dn(TALLOC_CTX *mem_ctx,
                           const char *input,
                           char **trimmed)
{
    int i = 0;
    int o = 0;
    int s;
    char *output;
    enum sss_trim_dn_state {
        SSS_TRIM_DN_STATE_READING_NAME,
        SSS_TRIM_DN_STATE_READING_VALUE
    } state = SSS_TRIM_DN_STATE_READING_NAME;

    *trimmed = NULL;

    output = talloc_array(mem_ctx, char, strlen(input) + 1);
    if (!output) {
        return ENOMEM;
    }

    /* skip leading spaces */
    while(isspace(input[i])) {
        ++i;
    }

    while(input[i] != '\0') {
        if (!isspace(input[i])) {
            switch (input[i]) {
            case '=':
                output[o++] = input[i++];
                if (state == SSS_TRIM_DN_STATE_READING_NAME) {
                    while (isspace(input[i])) {
                        ++i;
                    }
                    state = SSS_TRIM_DN_STATE_READING_VALUE;
                }
                break;
            case ',':
                output[o++] = input[i++];
                if (state == SSS_TRIM_DN_STATE_READING_VALUE) {
                    while (isspace(input[i])) {
                        ++i;
                    }
                    state = SSS_TRIM_DN_STATE_READING_NAME;
                }
                break;
            case '\\':
                output[o++] = input[i++];
                if (input[i] != '\0') {
                    output[o++] = input[i++];
                }
                break;
            default:
                if (input[i] != '\0') {
                    output[o++] = input[i++];
                }
                break;
            }

            continue;
        }

        /* non escaped space found */
        s = 1;
        while (isspace(input[i + s])) {
            ++s;
        }

        switch (state) {
        case SSS_TRIM_DN_STATE_READING_NAME:
            if (input[i + s] != '=') {
                /* this is not trailing space - should not be removed */
                while (isspace(input[i])) {
                    output[o++] = input[i++];
                }
            } else {
                i += s;
            }
            break;
        case SSS_TRIM_DN_STATE_READING_VALUE:
            if (input[i + s] != ',') {
                /* this is not trailing space - should not be removed */
                while (isspace(input[i])) {
                    output[o++] = input[i++];
                }
            } else {
                i += s;
            }
            break;
        }
    }

    output[o--] = '\0';

    /* trim trailing space */
    while (o >= 0 && isspace(output[o])) {
        output[o--] = '\0';
    }

    *trimmed = output;
    return EOK;
}

errno_t sss_filter_sanitize_dn(TALLOC_CTX *mem_ctx,
                               const char *input,
                               char **sanitized)
{
    errno_t ret;
    char *trimmed_dn = NULL;

    ret = sss_trim_dn(mem_ctx, input, &trimmed_dn);
    if (ret != EOK) {
        goto done;
    }

    ret = sss_filter_sanitize_ex(mem_ctx, trimmed_dn, sanitized, NULL);

 done:
    talloc_free(trimmed_dn);
    return ret;
}
