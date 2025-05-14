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

#include <errno.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/util_errors.h"
#include "util/strtonum.h"
#include "sbus/sbus_errors.h"

static const struct {
    const char *name;
    errno_t ret;
} sbus_error_table[] = {
    /* Custom errors. */
    { SBUS_ERROR_INTERNAL,          ERR_INTERNAL },
    { SBUS_ERROR_NOT_FOUND,         ENOENT },
    { SBUS_ERROR_KILLED,            ERR_SBUS_KILL_CONNECTION },
    { SBUS_ERROR_NO_CA,             ERR_CA_DB_NOT_FOUND},

    /* D-Bus standard errors. Some errno values may overlap, but when
     * finding its D-Bus pair the first match is returned. */
    { DBUS_ERROR_SERVICE_UNKNOWN,   ERR_SBUS_UNKNOWN_SERVICE},
    { DBUS_ERROR_UNKNOWN_INTERFACE, ERR_SBUS_UNKNOWN_INTERFACE},
    { DBUS_ERROR_UNKNOWN_PROPERTY,  ERR_SBUS_UNKNOWN_PROPERTY},
    { DBUS_ERROR_NAME_HAS_NO_OWNER, ERR_SBUS_UNKNOWN_OWNER},
    { DBUS_ERROR_NO_REPLY,          ERR_SBUS_NO_REPLY},
    { DBUS_ERROR_FAILED,            EFAULT},
    { DBUS_ERROR_NO_MEMORY,         ENOMEM},
    { DBUS_ERROR_TIMEOUT,           ETIMEDOUT},
    { DBUS_ERROR_NO_REPLY,          ETIMEDOUT},
    { DBUS_ERROR_IO_ERROR,          EIO},
    { DBUS_ERROR_BAD_ADDRESS,       EFAULT},
    { DBUS_ERROR_NOT_SUPPORTED,     ENOTSUP},
    { DBUS_ERROR_LIMITS_EXCEEDED,   ERANGE},
    { DBUS_ERROR_ACCESS_DENIED,     EPERM},
    { DBUS_ERROR_AUTH_FAILED,       EACCES},
    { DBUS_ERROR_NO_NETWORK,        ENETUNREACH},
    { DBUS_ERROR_DISCONNECTED,      ERR_OFFLINE},
    { DBUS_ERROR_INVALID_ARGS,      EINVAL},

    /* Should not happen so it can be as last item. */
    { SBUS_ERROR_SUCCESS,           EOK },
    { NULL, -1 }
};

errno_t sbus_error_to_errno(DBusError *error)
{
    uint32_t ret;
    int i;

    if (!dbus_error_is_set(error)) {
        return EOK;
    }

    if (dbus_error_has_name(error, SBUS_ERROR_ERRNO)) {
        ret = strtouint32(error->message, NULL, 10);
        if (errno != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected error format: [%s]\n",
                  error->message);
            return ERR_INTERNAL;
        } else if (ret == EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "An error was send but it indicates "
                  "success: [%s]\n", error->message);
            return ERR_INTERNAL;
        }

        return ret;
    }

    for (i = 0; sbus_error_table[i].name != NULL; i++) {
        if (dbus_error_has_name(error, sbus_error_table[i].name)) {
            return sbus_error_table[i].ret;
        }
    }

    return EIO;
}

void
sbus_errno_to_error(TALLOC_CTX *mem_ctx,
                    errno_t ret,
                    const char **_error_name,
                    const char **_error_message)
{
    char *message;
    int i;

    for (i = 0; sbus_error_table[i].ret != -1; i++) {
        if (sbus_error_table[i].ret == ret) {
            *_error_name = sbus_error_table[i].name;
            *_error_message = sss_strerror(ret);
            return;
        }
    }

    /* Error code was not translated. Create generic errno message. */
    message = talloc_asprintf(mem_ctx, "%u: %s", ret, sss_strerror(ret));
    if (message == NULL) {
        *_error_name = DBUS_ERROR_NO_MEMORY;
        *_error_message = sss_strerror(ENOMEM);
        return;
    }

    *_error_name = SBUS_ERROR_ERRNO;
    *_error_message = message;

    return;
}
