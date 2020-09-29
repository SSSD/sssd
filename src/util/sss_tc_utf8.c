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

#include "config.h"

#ifdef HAVE_LIBUNISTRING
#include <stdlib.h>
#include <unistr.h>
#elif defined(HAVE_GLIB2)
#include <glib.h>
#endif

#include <talloc.h>
#include "util/util.h"

#ifdef HAVE_LIBUNISTRING
static void sss_utf8_free(char *ptr)
{
    free(ptr);
}
#elif defined(HAVE_GLIB2)
static void sss_utf8_free(char *ptr)
{
    g_free(ptr);
}
#else
#error No unicode library
#endif

/* Expects and returns NULL-terminated string;
 * result must be freed with sss_utf8_free()
 */
#ifdef HAVE_LIBUNISTRING
static char *sss_utf8_tolower(const char *s)
{
    size_t llen;
    return u8_tolower((const uint8_t *)s, strlen(s) + 1, NULL, NULL, NULL, &llen);
}
#elif defined(HAVE_GLIB2)
static char *sss_utf8_tolower(const char *s)
{
    return g_utf8_strdown((const gchar *)s, -1);
}
#else
#error No unicode library
#endif

char *sss_tc_utf8_str_tolower(TALLOC_CTX *mem_ctx, const char *s)
{
    char *lower;
    char *ret = NULL;

    lower = sss_utf8_tolower(s);
    if (lower) {
        ret = talloc_strdup(mem_ctx, lower);
        sss_utf8_free(lower);
    }

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
