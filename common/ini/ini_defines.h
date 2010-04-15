/*
    INI LIBRARY

    Header file for the internal constants for the INI interface.

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

#ifndef INI_DEFINES_H
#define INI_DEFINES_H

#define NAME_OVERHEAD   10

#define SLASH           "/"


/* Name of the special collection used to store parsing errors */
#define FILE_ERROR_SET  "ini_file_error_set"

/* Text error strings used when errors are printed out */
#define WARNING_TXT         _("Warning")
#define ERROR_TXT           _("Error")
/* For parse errors */
#define WRONG_COLLECTION    _("Passed in list is not a list of parse errors.\n")
#define FAILED_TO_PROCCESS  _("Internal Error. Failed to process error list.\n")
#define ERROR_HEADER        _("Parsing errors and warnings in file: %s\n")
/* For grammar errors */
#define WRONG_GRAMMAR       _("Passed in list is not a list of grammar errors.\n")
#define FAILED_TO_PROC_G    _("Internal Error. Failed to process list of grammar errors.\n")
#define ERROR_HEADER_G      _("Logical errors and warnings in file: %s\n")
/* For validation errors */
#define WRONG_VALIDATION    _("Passed in list is not a list of validation errors.\n")
#define FAILED_TO_PROC_V    _("Internal Error. Failed to process list of validation errors.\n")
#define ERROR_HEADER_V      _("Validation errors and warnings in file: %s\n")

#define LINE_FORMAT         _("%s (%d) on line %d: %s\n")


/* Codes that parsing function can return */
#define RET_PAIR        0
#define RET_COMMENT     1
#define RET_SECTION     2
#define RET_INVALID     3
#define RET_EMPTY       4
#define RET_EOF         5
#define RET_ERROR       6

#define INI_ERROR       "errors"
#define INI_ERROR_NAME  "errname"

/* Internal sizes. MAX_KEY is defined in config.h */
#define MAX_VALUE       PATH_MAX
#define BUFFER_SIZE     MAX_KEY + MAX_VALUE + 3

/* Beffer length used for int to string conversions */
#define CONVERSION_BUFFER 80

/* Different error string functions can be passed as callbacks */
typedef const char * (*error_fn)(int error);

#endif
