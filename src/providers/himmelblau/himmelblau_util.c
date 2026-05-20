/*
    SSSD

    Himmelblau Provider - Utility functions

    Authors:
        David Mulder <dmulder@suse.com>

    Copyright (C) 2026 SUSE

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

#include "config.h"

#include <security/pam_modules.h>
#include <errno.h>

#include "util/util.h"
#include "providers/himmelblau/himmelblau_common.h"

int
himmelblau_error_to_pam_status(errno_t himmelblau_error,
                               MSAL_ERROR *error_obj)
{
    /* Map errno-style errors and libhimmelblau-specific errors to PAM codes */
    switch (himmelblau_error) {
        case EOK:
            return PAM_SUCCESS;

        case EACCES:
        case EPERM:
            /* Authentication failed - wrong password or MFA code */
            return PAM_AUTH_ERR;

        case ENOENT:
            /* User doesn't exist in directory */
            return PAM_USER_UNKNOWN;

        case ETIMEDOUT:
            /* Timeout during MFA polling or network operation */
            return PAM_AUTHINFO_UNAVAIL;

        case ENETUNREACH:
        case ENETDOWN:
        case EHOSTUNREACH:
        case ECONNREFUSED:
            /* Network unavailable */
            return PAM_AUTHINFO_UNAVAIL;

        case EIO:
            /* I/O error - could be device enrollment failure or API error */
            return PAM_AUTHINFO_UNAVAIL;

        case ENOMEM:
            /* Out of memory */
            return PAM_BUF_ERR;

        case EINVAL:
            /* Invalid argument - programming error */
            return PAM_SYSTEM_ERR;

        default:
            DEBUG(SSSDBG_OP_FAILURE,
                  "Unknown himmelblau error: %d, returning PAM_SYSTEM_ERR\n",
                  himmelblau_error);
            return PAM_SYSTEM_ERR;
    }
}

const char *
himmelblau_pam_status_to_string(int pam_status)
{
    switch (pam_status) {
        case PAM_SUCCESS:
            return "PAM_SUCCESS";
        case PAM_AUTH_ERR:
            return "PAM_AUTH_ERR";
        case PAM_USER_UNKNOWN:
            return "PAM_USER_UNKNOWN";
        case PAM_AUTHINFO_UNAVAIL:
            return "PAM_AUTHINFO_UNAVAIL";
        case PAM_BUF_ERR:
            return "PAM_BUF_ERR";
        case PAM_SYSTEM_ERR:
            return "PAM_SYSTEM_ERR";
        case PAM_MODULE_UNKNOWN:
            return "PAM_MODULE_UNKNOWN";
        default:
            return "UNKNOWN_PAM_STATUS";
    }
}
