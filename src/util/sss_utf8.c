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
void sss_utf8_free(void *ptr)
{
    return free(ptr);
}
#elif defined(HAVE_GLIB2)
void sss_utf8_free(void *ptr)
{
    return g_free(ptr);
}
#else
#error No unicode library
#endif

#ifdef HAVE_LIBUNISTRING
uint8_t *sss_utf8_tolower(const uint8_t *s, size_t len, size_t *_nlen)
{
    size_t llen;
    uint8_t *lower;

    lower = u8_tolower(s, len, NULL, NULL, NULL, &llen);
    if (!lower) return NULL;

    if (_nlen) *_nlen = llen;
    return lower;
}
#elif defined(HAVE_GLIB2)
uint8_t *sss_utf8_tolower(const uint8_t *s, size_t len, size_t *_nlen)
{
    gchar *glower;
    size_t nlen;
    uint8_t *lower;

    glower = g_utf8_strdown((const gchar *) s, len);
    if (!glower) return NULL;

    /* strlen() is safe here because g_utf8_strdown() always null-terminates */
    nlen = strlen(glower);

    lower = g_malloc(nlen);
    if (!lower) {
        g_free(glower);
        return NULL;
    }

    memcpy(lower, glower, nlen);
    g_free(glower);
    if (_nlen) *_nlen = nlen;
    return (uint8_t *) lower;
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

/* Returns EOK on match, ENOTUNIQ if comparison succeeds but
 * does not match.
 * May return other errno error codes on failure
 */
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
