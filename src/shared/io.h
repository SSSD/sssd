/*
   SSSD

   SSSD Utility functions

   Copyright (C) Lukas Slebodnik           2013

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

#ifndef _SHARED_IO_H_
#define _SHARED_IO_H_

/* CAUTION:
 * This file is also used in sss_client (pam, nss). Therefore it have to be
 * minimalist and cannot include DEBUG macros or header file util.h.
 */

int sss_open_cloexec(const char *pathname, int flags, int *ret);
int sss_openat_cloexec(int dir_fd, const char *pathname, int flags, int *ret);

#endif /* _SHARED_IO_H_ */
