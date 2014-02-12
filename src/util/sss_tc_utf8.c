/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2011 Red Hat

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
#include "util/sss_utf8.h"

char *
sss_tc_utf8_str_tolower(TALLOC_CTX *mem_ctx, const char *s)
{
    size_t nlen;
    uint8_t *ret;

    ret = sss_tc_utf8_tolower(mem_ctx, (const uint8_t *) s, strlen(s), &nlen);
    if (!ret) return NULL;

    ret = talloc_realloc(mem_ctx, ret, uint8_t, nlen+1);
    if (!ret) return NULL;

    ret[nlen] = '\0';
    return (char *) ret;
}

uint8_t *
sss_tc_utf8_tolower(TALLOC_CTX *mem_ctx, const uint8_t *s, size_t len, size_t *_nlen)
{
    uint8_t *lower;
    uint8_t *ret;
    size_t nlen;

    lower = sss_utf8_tolower(s, len, &nlen);
    if (!lower) return NULL;

    ret = talloc_memdup(mem_ctx, lower, nlen);
    sss_utf8_free(lower);
    if (!ret) return NULL;

    *_nlen = nlen;
    return ret;
}

errno_t sss_filter_sanitize_for_dom(TALLOC_CTX *mem_ctx,
                                    const char *input,
                                    struct sss_domain_info *dom,
                                    char **sanitized,
                                    char **lc_sanitized)
{
    int ret;

    ret = sss_filter_sanitize(mem_ctx, input, sanitized);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_filter_sanitize failed.\n");
        return ret;
    }

    if (dom->case_sensitive) {
        *lc_sanitized = talloc_strdup(mem_ctx, *sanitized);
    } else {
        *lc_sanitized = sss_tc_utf8_str_tolower(mem_ctx, *sanitized);
    }

    if (*lc_sanitized == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "%s failed.\n",
                                              dom->case_sensitive ?
                                                    "talloc_strdup" :
                                                    "sss_tc_utf8_str_tolower");
        return ENOMEM;
    }

    return EOK;
}
