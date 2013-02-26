/*
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

    Authors:
        Simo Sorce <ssorce@redhat.com>
*/

#include "util/util.h"

struct err_string {
    const char *msg;
};

struct err_string error_to_str[] = {
    { "Invalid Error" },        /* ERR_INVALID */
    { "Internal Error" },       /* ERR_INTERNAL */
    { "Account Unknown" },      /* ERR_ACCOUNT_UNKNOWN */
    { "Invalid credential type" },  /* ERR_INVALID_CRED_TYPE */
    { "No credentials available" }, /* ERR_NO_CREDS */
    { "Credentials are expired" }, /* ERR_CREDS_EXPIRED */
    { "No cached credentials available" }, /* ERR_NO_CACHED_CREDS */
    { "Cached credentials are expired" }, /* ERR_CACHED_CREDS_EXPIRED */
    { "Authentication Denied" }, /* ERR_AUTH_DENIED */
    { "Authentication Failed" }, /* ERR_AUTH_FAILED */
    { "Password Change Denied" }, /* ERR_CHPASS_DENIED */
    { "Password Change Failed" }, /* ERR_CHPASS_FAILED */
    { "Network I/O Error" }, /* ERR_NETWORK_IO */
    { "Account Expired" }, /* ERR_ACCOUNT_EXPIRED */
    { "Password Expired" }, /* ERR_PASSWORD_EXPIRED */
};


const char *sss_strerror(errno_t error)
{
    if (IS_SSSD_ERROR(error)) {
        return error_to_str[SSSD_ERR_IDX(error)].msg;
    }

    return strerror(error);
}

