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

char *sss_replace_char(TALLOC_CTX *mem_ctx,
                       const char *in,
                       const char match,
                       const char sub)
{
    char *p;
    char *out;

    out = talloc_strdup(mem_ctx, in);
    if (out == NULL) {
        return NULL;
    }

    for (p = out; *p != '\0'; ++p) {
        if (*p == match) {
            *p = sub;
        }
    }

    return out;
}

char * sss_replace_space(TALLOC_CTX *mem_ctx,
                         const char *orig_name,
                         const char subst)
{
    if (subst == '\0' || subst == ' ') {
        return talloc_strdup(mem_ctx, orig_name);
    }

    if (strchr(orig_name, subst) != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Input [%s] already contains replacement character [%c].\n",
              orig_name, subst);
        sss_log(SSS_LOG_CRIT,
                "Name [%s] already contains replacement character [%c]. " \
                "No replacement will be done.\n",
                orig_name, subst);
        return talloc_strdup(mem_ctx, orig_name);
    }

    return sss_replace_char(mem_ctx, orig_name, ' ', subst);
}

char * sss_reverse_replace_space(TALLOC_CTX *mem_ctx,
                                 const char *orig_name,
                                 const char subst)
{
    if (subst == '\0' || subst == ' ') {
        return talloc_strdup(mem_ctx, orig_name);
    }

    if (strchr(orig_name, subst) != NULL && strchr(orig_name, ' ') != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Input [%s] contains replacement character [%c] and space.\n",
              orig_name, subst);
        return talloc_strdup(mem_ctx, orig_name);
    }

    return sss_replace_char(mem_ctx, orig_name, subst, ' ');
}

errno_t guid_blob_to_string_buf(const uint8_t *blob, char *str_buf,
                                size_t buf_size)
{
    int ret;

    if (blob == NULL || str_buf == NULL || buf_size < GUID_STR_BUF_SIZE) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Buffer too small.\n");
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
