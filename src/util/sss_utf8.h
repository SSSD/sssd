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

#ifndef SSS_UTF8_H_
#define SSS_UTF8_H_

#ifndef ENOMATCH
#define ENOMATCH -1
#endif

#include <stdint.h>
#include <stdbool.h>

#include "util/util_errors.h"

bool sss_utf8_check(const uint8_t *s, size_t n);

/* Returns EOK on match, ENOTUNIQ if comparison succeeds but
 * does not match.
 * May return other errno error codes on failure
 */
errno_t sss_utf8_case_eq(const uint8_t *s1, const uint8_t *s2);


#endif /* SSS_UTF8_H_ */
