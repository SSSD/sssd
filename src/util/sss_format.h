/*
    SSSD

    sss_format.h

    Authors:
        Lukas Slebodnik <lslebodn@redhat.com>

    Copyright (C) 2013 Red Hat


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


#ifndef __SSS_FORMAT_H__
#define __SSS_FORMAT_H__

#include <inttypes.h>

/* key_serial_t is defined in keyutils.h as typedef int32_t */
#define SPRIkey_ser PRId32

/* rlim_t is defined with conditional build as unsigned type.
 * It seems that sizeof(rlim_t) is 8. It may be platform dependent, therefore
 * the same format will be used like with uint64_t.
 */

#define SPRIrlim PRIu64

#endif /* __SSS_FORMAT_H__ */
