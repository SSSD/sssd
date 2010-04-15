/*
    INI LIBRARY

    Header file for the internal parsing functions.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2010

    INI Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    INI Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with INI Library.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef INI_PARSE_H
#define INI_PARSE_H

#include <stdio.h>

/* Internal function to read line from INI file */
int read_line(FILE *file,
              char *buf,
              int read_size,
              char **key,
              char **value,
              int *length,
              int *ext_error);

#endif
