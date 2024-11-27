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

errno_t become_user(uid_t uid, gid_t gid, bool keep_set_uid)
{
    uid_t cuid;
    int ret = EOK;

    DEBUG(SSSDBG_FUNC_DATA,
          "Trying to become user [%"SPRIuid"][%"SPRIgid"].\n", uid, gid);

    /* skip call if we already are the requested user */
    cuid = geteuid();
    if (uid == cuid) {
        DEBUG(SSSDBG_FUNC_DATA, "Already user [%"SPRIuid"].\n", uid);
        goto done;
    }

    /* drop supplementary groups first */
    ret = setgroups(0, NULL);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "setgroups failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    /* change GID so that root cannot be regained (changes saved GID too) */
    ret = setresgid(gid, gid, gid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "setresgid failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    /* change UID so that root cannot be regained (changes saved UID too) */
    /* this call also takes care of dropping CAP_SETUID, so this is a PNR */
    ret = setresuid(uid, uid, (keep_set_uid ? -1 : uid));
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "setresuid failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

done:
    sss_drop_all_caps();

    return ret;
}
