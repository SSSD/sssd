/*
   SSSD

   SSSD Utility functions

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#include <stdlib.h>
#include <errno.h>
#include "util/strtonum.h"

int32_t strtoint32(const char *nptr, char **endptr, int base)
{
    long long ret = 0;

    errno = 0;
    ret = strtoll(nptr, endptr, base);

    if (ret > INT32_MAX) {
        errno = ERANGE;
        return INT32_MAX;
    }
    else if (ret < INT32_MIN) {
        errno = ERANGE;
        return INT32_MIN;
    }

    /* If errno was set by strtoll, we'll pass it back as-is */
    return (int32_t)ret;
}


uint32_t strtouint32(const char *nptr, char **endptr, int base)
{
    unsigned long long ret = 0;
    errno = 0;
    ret = strtoull(nptr, endptr, base);

    if (ret > UINT32_MAX) {
        errno = ERANGE;
        return UINT32_MAX;
    }

    /* If errno was set by strtoll, we'll pass it back as-is */
    return (uint32_t)ret;
}


uint16_t strtouint16(const char *nptr, char **endptr, int base)
{
    unsigned long long ret = 0;
    errno = 0;
    ret = strtoull(nptr, endptr, base);

    if (ret > UINT16_MAX) {
        errno = ERANGE;
        return UINT16_MAX;
    }

    /* If errno was set by strtoll, we'll pass it back as-is */
    return (uint16_t)ret;
}

