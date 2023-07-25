/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2017 Red Hat

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

#ifndef _SBUS_ERRORS_H_
#define _SBUS_ERRORS_H_

#include <errno.h>
#include <dbus/dbus.h>

#include "util/util_errors.h"

#define SBUS_ERROR_SUCCESS          "sbus.Error.Success"

#define SBUS_ERROR_INTERNAL         "sbus.Error.Internal"
#define SBUS_ERROR_NOT_FOUND        "sbus.Error.NotFound"
#define SBUS_ERROR_KILLED           "sbus.Error.ConnectionKilled"
#define SBUS_ERROR_NO_CA            "sbus.Error.NoCA"
#define SBUS_ERROR_ERRNO            "sbus.Error.Errno"

errno_t sbus_error_to_errno(DBusError *error);

void
sbus_errno_to_error(TALLOC_CTX *mem_ctx,
                    errno_t ret,
                    const char **_error_name,
                    const char **_error_message);

#endif /* _SBUS_ERRORS_H_ */
