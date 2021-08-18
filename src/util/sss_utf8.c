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
#include <unistr.h>
#include <unicase.h>

#include "sss_utf8.h"

bool sss_utf8_check(const uint8_t *s, size_t n)
{
    if (u8_check(s, n) == NULL) {
        return true;
    }
    return false;
}

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

bool sss_string_equal(bool cs, const char *s1, const char *s2)
{
    if (cs) {
        return strcmp(s1, s2) == 0;
    }

    return sss_utf8_case_eq((const uint8_t *)s1, (const uint8_t *)s2) == EOK;
}
