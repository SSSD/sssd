/*
    SSSD

    Authentication utility functions

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2012 Red Hat

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
#include <security/pam_appl.h>

static inline int cached_login_pam_status(int auth_res)
{
    switch (auth_res) {
    case EOK:
        return PAM_SUCCESS;
    case ERR_ACCOUNT_UNKNOWN:
        return PAM_AUTHINFO_UNAVAIL;
    case ERR_NO_CACHED_CREDS:
    case ERR_CACHED_CREDS_EXPIRED:
    case ERR_AUTH_DENIED:
        return PAM_PERM_DENIED;
    case ERR_AUTH_FAILED:
        return PAM_AUTH_ERR;
    default:
        return PAM_SYSTEM_ERR;
    }
}
