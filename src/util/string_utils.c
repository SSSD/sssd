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

static inline void replace_char_inplace(char *p, char match, char sub)
{
    for (; *p != '\0'; ++p) {
        if (*p == match) {
            *p = sub;
        }
    }
}

char *sss_replace_char(TALLOC_CTX *mem_ctx,
                       const char *in,
                       const char match,
                       const char sub)
{
    char *out;

    out = talloc_strdup(mem_ctx, in);
    if (out == NULL) {
        return NULL;
    }

    replace_char_inplace(out, match, sub);

    return out;
}

void sss_replace_space_inplace(char *orig_name,
                               const char subst)
{
    if (subst == '\0' || subst == ' ') {
        return;
    }

    if (strchr(orig_name, subst) != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Input [%s] already contains replacement character [%c].\n",
              orig_name, subst);
        sss_log(SSS_LOG_CRIT,
                "Name [%s] already contains replacement character [%c]. " \
                "No replacement will be done.\n",
                orig_name, subst);
        return;
    }

    replace_char_inplace(orig_name, ' ', subst);
}

void sss_reverse_replace_space_inplace(char *orig_name,
                                       const char subst)
{
    if (subst == '\0' || subst == ' ') {
        return;
    }

    if (strchr(orig_name, subst) != NULL && strchr(orig_name, ' ') != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Input [%s] contains replacement character [%c] and space.\n",
              orig_name, subst);
        return;
    }

    replace_char_inplace(orig_name, subst, ' ');
}

errno_t guid_blob_to_string_buf(const uint8_t *blob, char *str_buf,
                                size_t buf_size)
{
    int ret;

    if (blob == NULL || str_buf == NULL || buf_size < GUID_STR_BUF_SIZE) {
        DEBUG(SSSDBG_OP_FAILURE, "Buffer too small.\n");
        return EINVAL;
    }

    ret = snprintf(str_buf, buf_size,
         "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
         blob[3], blob[2], blob[1], blob[0],
         blob[5], blob[4],
         blob[7], blob[6],
         blob[8], blob[9],
         blob[10], blob[11],blob[12], blob[13],blob[14], blob[15]);
    if (ret != (GUID_STR_BUF_SIZE -1)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "snprintf failed.\n");
        return EIO;
    }

    return EOK;
}

const char *get_last_x_chars(const char *str, size_t x)
{
    size_t len;

    if (str == NULL) {
        return NULL;
    }

    len = strlen(str);

    if (len < x) {
        return str;
    }

    return (str + len - x);
}

errno_t string_begins_with(const char *str,
                           const char *prefix,
                           bool *_result)
{
    size_t len;
    size_t prefix_len;

    *_result = false;

    if (str == NULL) {
        return EINVAL;
    }

    len = strlen(str);
    prefix_len = strlen(prefix);

    if (prefix_len > len) {
        return EINVAL;
    }

    *_result = strncmp(prefix, str, prefix_len) == 0;

    return EOK;
}

errno_t string_ends_with(const char *str,
                         const char *suffix,
                         bool *_result)
{
    int res;
    size_t len;
    size_t suffix_len;

    *_result = false;

    if (str == NULL) {
        return EINVAL;
    }

    len = strlen(str);
    suffix_len = strlen(suffix);

    if (suffix_len > len) {
        return EINVAL;
    }

    res = strcmp(str + (len - suffix_len), suffix);

    *_result = !res;

    return EOK;
}

char **concatenate_string_array(TALLOC_CTX *mem_ctx,
                                char **arr1, size_t len1,
                                char **arr2, size_t len2)
{
    size_t i, j;
    size_t new_size = len1 + len2;
    char ** string_array = talloc_realloc(mem_ctx, arr1, char *, new_size + 1);
    if (string_array == NULL) {
        return NULL;
    }

    for (i=len1, j=0; i < new_size; ++i,++j) {
        string_array[i] = talloc_steal(string_array,
                                       arr2[j]);
    }

    string_array[i] = NULL;

    return string_array;
}

errno_t mod_defaults_list(TALLOC_CTX *mem_ctx, const char **defaults_list,
                          char **mod_list, char ***_list)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    size_t mod_list_size;
    const char **add_list;
    const char **remove_list;
    size_t c;
    size_t ai = 0;
    size_t ri = 0;
    size_t j = 0;
    char **list;
    size_t expected_list_size = 0;
    size_t defaults_list_size = 0;

    for (defaults_list_size = 0;
            defaults_list != NULL && defaults_list[defaults_list_size] != NULL;
            defaults_list_size++);

    for (mod_list_size = 0;
            mod_list != NULL && mod_list[mod_list_size] != NULL;
            mod_list_size++);

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    add_list = talloc_zero_array(tmp_ctx, const char *, mod_list_size + 1);
    remove_list = talloc_zero_array(tmp_ctx, const char *, mod_list_size + 1);

    if (add_list == NULL || remove_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (c = 0; mod_list != NULL && mod_list[c] != NULL; c++) {
        switch (mod_list[c][0]) {
        case '+':
            add_list[ai] = mod_list[c] + 1;
            ++ai;
            break;
        case '-':
            remove_list[ri] = mod_list[c] + 1;
            ++ri;
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE,
                  "The option "CONFDB_PAM_P11_ALLOWED_SERVICES" must start"
                  "with either '+' (for adding service) or '-' (for "
                  "removing service) got '%s'\n", mod_list[c]);
            ret = EINVAL;
            goto done;
        }
    }

    expected_list_size = defaults_list_size + ai + 1;

    list = talloc_zero_array(tmp_ctx, char *, expected_list_size);
    if (list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (c = 0; add_list[c] != NULL; ++c) {
        if (string_in_list(add_list[c], discard_const(remove_list), false)) {
            continue;
        }

        list[j] = talloc_strdup(list, add_list[c]);
        if (list[j] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        j++;
    }

    for (c = 0; defaults_list != NULL && defaults_list[c] != NULL; ++c) {
        if (string_in_list(defaults_list[c],
                           discard_const(remove_list), false)) {
            continue;
        }

        list[j] = talloc_strdup(list, defaults_list[c]);
        if (list[j] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        j++;
    }

    if (_list != NULL) {
        *_list = talloc_steal(mem_ctx, list);
    }

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);

    return ret;
}
