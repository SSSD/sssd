/*
    Authors:
        Iker Pedrosa <ipedrosa@redhat.com>

    Copyright (C) 2021 Red Hat

    SSSD tests: Fake nss dl load

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

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stddef.h>

#include "common_mock_nss_dl_load.h"


static enum nss_status
mock_getpwnam_r(const char *name, struct passwd *result,
                char *buffer, size_t buflen, int *errnop)
{
    void *pwd_pointer = NULL;
    int rc;

    rc = getpwnam_r(name, result, buffer, buflen, (struct passwd **)&pwd_pointer);
    if (rc == 0 && pwd_pointer == result) {
        *errnop = 0;
        return NSS_STATUS_SUCCESS;
    } else if (rc == 0 && (pwd_pointer == NULL)) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    } else {
        *errnop = rc;
        return NSS_STATUS_UNAVAIL;
    }
}

static enum nss_status
mock_getpwuid_r(uid_t uid, struct passwd *result,
                char *buffer, size_t buflen, int *errnop)
{
    void *pwd_pointer = NULL;
    int rc;

    rc = getpwuid_r(uid, result, buffer, buflen, (struct passwd **)&pwd_pointer);
    if (rc == 0 && pwd_pointer == result) {
        *errnop = 0;
        return NSS_STATUS_SUCCESS;
    } else if (rc == 0 && (pwd_pointer == NULL)) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    } else {
        *errnop = rc;
        return NSS_STATUS_UNAVAIL;
    }
}

errno_t mock_sss_load_nss_pw_symbols(struct sss_nss_ops *ops)
{
    ops->getpwnam_r = mock_getpwnam_r;
    ops->getpwuid_r = mock_getpwuid_r;

    return EOK;
}
