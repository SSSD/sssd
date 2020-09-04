/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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

#include <string.h>
#include <errno.h>

#ifdef HAVE_LIBUNISTRING
#include <stdlib.h>
#include <unistr.h>
#include <unicase.h>
#elif defined(HAVE_GLIB2)
#include <glib.h>
#endif

#include "sss_utf8.h"

#ifdef HAVE_LIBUNISTRING
void sss_utf8_free(char *ptr)
{
    free(ptr);
}
#elif defined(HAVE_GLIB2)
void sss_utf8_free(char *ptr)
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
char *sss_utf8_tolower(const char *s)
{
    size_t llen;
    return u8_tolower((const uint8_t *)s, strlen(s) + 1, NULL, NULL, NULL, &llen);
}
#elif defined(HAVE_GLIB2)
char *sss_utf8_tolower(const char *s)
{
    return g_utf8_strdown((const gchar *)s, -1);
}
#else
#error No unicode library
#endif

#ifdef HAVE_LIBUNISTRING
bool sss_utf8_check(const uint8_t *s, size_t n)
{
    if (u8_check(s, n) == NULL) {
        return true;
    }
    return false;
}

#elif defined(HAVE_GLIB2)
bool sss_utf8_check(const uint8_t *s, size_t n)
{
    return g_utf8_validate((const gchar *)s, n, NULL);
}

#else
#error No unicode library
#endif

#ifdef HAVE_LIBUNISTRING
errno_t sss_utf8_case_eq(const uint8_t *s1, const uint8_t *s2)
{

    /* Do a case-insensitive comparison.
     * The input must be encoded in UTF8.
     * We have no way of knowing the language,
     * so we'll pass NULL for the language and
     * hope for the best.
     */
    int ret;
    int resultp;
    size_t n1, n2;
    errno = 0;

    n1 = u8_strlen(s1);
    n2 = u8_strlen(s2);

    ret = u8_casecmp(s1, n1,
                     s2, n2,
                     NULL, NULL,
                     &resultp);
    if (ret < 0) {
        /* An error occurred */
        return errno;
    }

    if (resultp == 0) {
        return EOK;
    }
    return ENOMATCH;
}

#elif defined(HAVE_GLIB2)
errno_t sss_utf8_case_eq(const uint8_t *s1, const uint8_t *s2)
{
    gchar *gs1;
    gchar *gs2;
    gssize n1, n2;
    gint gret;
    errno_t ret;

    n1 = g_utf8_strlen((const gchar *)s1, -1);
    n2 = g_utf8_strlen((const gchar *)s2, -1);

    gs1 = g_utf8_casefold((const gchar *)s1, n1);
    if (gs1 == NULL) {
        return ENOMEM;
    }

    gs2 = g_utf8_casefold((const gchar *)s2, n2);
    if (gs2 == NULL) {
        return ENOMEM;
    }

    gret = g_utf8_collate(gs1, gs2);
    if (gret == 0) {
        ret = EOK;
    } else {
        ret = ENOMATCH;
    }

    g_free(gs1);
    g_free(gs2);

    return ret;
}

#else
#error No unicode library
#endif

bool sss_string_equal(bool cs, const char *s1, const char *s2)
{
    if (cs) {
        return strcmp(s1, s2) == 0;
    }

    return sss_utf8_case_eq((const uint8_t *)s1, (const uint8_t *)s2) == EOK;
}
