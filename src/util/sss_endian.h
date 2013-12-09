/*
    SSSD

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

#ifndef SSS_ENDIAN_H_
#define SSS_ENDIAN_H_

#ifdef HAVE_ENDIAN_H
# include <endian.h>
#elif defined(HAVE_SYS_ENDIAN_H)
# include <sys/endian.h>
#endif /* !HAVE_ENDIAN_H && !HAVE_SYS_ENDIAN_H */

/* Endianness-compatibility for systems running older versions of glibc */

#ifndef le32toh
#ifndef HAVE_BYTESWAP_H
#error missing le32toh and byteswap.h
#else /* defined HAVE_BYTESWAP_H */
#include <byteswap.h>

/* support RHEL5 lack of definitions */
/* Copied from endian.h on glibc 2.15 */
#ifdef __USE_BSD
/* Conversion interfaces.  */
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define le32toh(x) (x)
#  define htole32(x) (x)
# else
#  define le32toh(x) __bswap_32 (x)
#  define htole32(x) __bswap_32 (x)
# endif
#endif /* __USE_BSD */

#endif /* HAVE_BYTESWAP_H */

#endif /* le32toh */

#endif /* SSS_ENDIAN_H_ */
