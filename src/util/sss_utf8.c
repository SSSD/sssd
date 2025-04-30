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

#include <stdlib.h>
#include <utf8proc.h>

#include "sss_utf8.h"

bool sss_utf8_check(const uint8_t *s, size_t n)
{
    if (utf8proc_decompose((const utf8proc_uint8_t *)s, n, NULL, 0, 0) < 0) {
        return false;
    }

    return true;
}

errno_t sss_utf8_case_eq(const uint8_t *s1, const uint8_t *s2)
{
    /* Do a case-insensitive comparison.
     * The input must be encoded in UTF8.
     */
    int ret = EOK;
    char *s1c, *s2c;

    s1c = (char *)utf8proc_NFKC_Casefold((const utf8proc_uint8_t *)s1);
    s2c = (char *)utf8proc_NFKC_Casefold((const utf8proc_uint8_t *)s2);
    if ((s1c == NULL) || (s2c == NULL)) {
        ret = EINVAL;
        goto done;
    }

    if (strcmp(s1c, s2c) != 0) {
        ret = ENOMATCH;
    }

done:
    free(s1c);
    free(s2c);
    return ret;
}

bool sss_string_equal(bool cs, const char *s1, const char *s2)
{
    if (cs) {
        return strcmp(s1, s2) == 0;
    }

    return sss_utf8_case_eq((const uint8_t *)s1, (const uint8_t *)s2) == EOK;
}
