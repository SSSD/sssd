/*
    SSSD

    Kerberos 5 Backend Module -- Utilities

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include <unistd.h>

#include "util/util.h"

errno_t become_user(uid_t uid, gid_t gid)
{
    int ret;

    DEBUG(SSSDBG_FUNC_DATA, ("Trying to become user [%d][%d].\n", uid, gid));
    ret = setgid(gid);
    if (ret == -1) {
        DEBUG(1, ("setgid failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    ret = setuid(uid);
    if (ret == -1) {
        DEBUG(1, ("setuid failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    ret = setegid(gid);
    if (ret == -1) {
        DEBUG(1, ("setegid failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    ret = seteuid(uid);
    if (ret == -1) {
        DEBUG(1, ("seteuid failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    return EOK;
}

