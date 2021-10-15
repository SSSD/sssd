/*
   SSSD

   SSSD Utility functions

   Copyright (C) Stephen Gallagher         2009

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

#ifndef _STRTONUM_H_
#define _STRTONUM_H_

#include <stdint.h>

int32_t strtoint32(const char *nptr, char **endptr, int base);
uint32_t strtouint32(const char *nptr, char **endptr, int base);

uint16_t strtouint16(const char *nptr, char **endptr, int base);

#endif /* _STRTONUM_H_ */
