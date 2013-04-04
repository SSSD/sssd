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

#include "util/util.h"
#include <grp.h>

errno_t become_user(uid_t uid, gid_t gid)
{
    uid_t cuid;
    int ret;

    DEBUG(SSSDBG_FUNC_DATA, ("Trying to become user [%d][%d].\n", uid, gid));

    /* skip call if we already are the requested user */
    cuid = geteuid();
    if (uid == cuid) {
        DEBUG(SSSDBG_FUNC_DATA, ("Already user [%d].\n", uid));
        return EOK;
    }

    /* drop supplmentary groups first */
    ret = setgroups(0, NULL);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("setgroups failed [%d][%s].\n", ret, strerror(ret)));
        return ret;
    }

    /* change gid so that root cannot be regained (changes saved gid too) */
    ret = setresgid(gid, gid, gid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("setresgid failed [%d][%s].\n", ret, strerror(ret)));
        return ret;
    }

    /* change uid so that root cannot be regained (changes saved uid too) */
    /* this call also takes care of dropping CAP_SETUID, so this is a PNR */
    ret = setresuid(uid, uid, uid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("setresuid failed [%d][%s].\n", ret, strerror(ret)));
        return ret;
    }

    return EOK;
}

