/*
   SSSD

   Client Interface for NSS and PAM.

   Authors:
        Stephen Gallagher <sgallagh@redhat.com>

   Copyright (C) Red Hat, Inc 2009

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SSS_PAM_MACROS_H
#define _SSS_PAM_MACROS_H

/* Older versions of the pam development headers do not include the
 * _pam_overwrite_n(n,x) macro. This implementation is copied from
 * the Fedora 11 _pam_macros.h.
 */
#ifdef HAVE_SECURITY__PAM_MACROS_H
# include <security/_pam_macros.h>
#endif /* HAVE_SECURITY__PAM_MACROS_H */

#ifndef _pam_overwrite
#define _pam_overwrite(x)        \
do {                             \
     register char *__xx__;      \
     if ((__xx__=(x)))           \
          while (*__xx__)        \
               *__xx__++ = '\0'; \
} while (0)
#endif /* _pam_overwrite */

#ifndef _pam_overwrite_n
#define _pam_overwrite_n(x,n)   \
do {                             \
     register char *__xx__;      \
     register unsigned int __i__ = 0;    \
     if ((__xx__=(x)))           \
        for (;__i__<n; __i__++) \
            __xx__[__i__] = 0; \
} while (0)
#endif /* _pam_overwrite_n */

#ifndef D
#define D(x)   do { } while (0)
#endif /* D */

#endif /* _SSS_PAM_MACROS_H */
