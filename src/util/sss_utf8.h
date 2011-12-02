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

#ifdef HAVE_LIBUNISTRING
#include <unistr.h>
#include <unicase.h>
#elif HAVE_GLIB2
#include <glib.h>
#endif
#include "util/util.h"

#ifndef ENOMATCH
#define ENOMATCH -1
#endif

bool sss_utf8_check(const uint8_t *s, size_t n);

errno_t sss_utf8_case_eq(const uint8_t *s1, const uint8_t *s2);


#endif /* SSS_UTF8_H_ */
