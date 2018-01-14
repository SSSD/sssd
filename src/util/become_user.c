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

    DEBUG(SSSDBG_FUNC_DATA,
          "Trying to become user [%"SPRIuid"][%"SPRIgid"].\n", uid, gid);

    /* skip call if we already are the requested user */
    cuid = geteuid();
    if (uid == cuid) {
        DEBUG(SSSDBG_FUNC_DATA, "Already user [%"SPRIuid"].\n", uid);
        return EOK;
    }

    /* drop supplementary groups first */
    ret = setgroups(0, NULL);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "setgroups failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    /* change GID so that root cannot be regained (changes saved GID too) */
    ret = setresgid(gid, gid, gid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "setresgid failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    /* change UID so that root cannot be regained (changes saved UID too) */
    /* this call also takes care of dropping CAP_SETUID, so this is a PNR */
    ret = setresuid(uid, uid, uid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "setresuid failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    return EOK;
}

struct sss_creds {
    uid_t uid;
    gid_t gid;
    int num_gids;
    gid_t gids[];
};

errno_t restore_creds(struct sss_creds *saved_creds);

/* This is a reversible version of become_user, and returns the saved
 * credentials so that creds can be switched back calling restore_creds */
errno_t switch_creds(TALLOC_CTX *mem_ctx,
                     uid_t uid, gid_t gid,
                     int num_gids, gid_t *gids,
                     struct sss_creds **saved_creds)
{
    struct sss_creds *ssc = NULL;
    int size;
    int ret;
    uid_t myuid;
    uid_t mygid;

    DEBUG(SSSDBG_FUNC_DATA, "Switch user to [%d][%d].\n", uid, gid);

    myuid = geteuid();
    mygid = getegid();

    if (saved_creds) {
        /* save current user credentials */
        size = getgroups(0, NULL);
        if (size == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "Getgroups failed! (%d, %s)\n",
                                        ret, strerror(ret));
            goto done;
        }

        ssc = talloc_size(mem_ctx,
                          (sizeof(struct sss_creds) + size * sizeof(gid_t)));
        if (!ssc) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Allocation failed!\n");
            ret = ENOMEM;
            goto done;
        }
        ssc->num_gids = size;

        size = getgroups(ssc->num_gids, ssc->gids);
        if (size == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "Getgroups failed! (%d, %s)\n",
                                        ret, strerror(ret));
            /* free ssc immediately otherwise the code will try to restore
             * wrong creds */
            talloc_zfree(ssc);
            goto done;
        }

        /* we care only about effective ids */
        ssc->uid = myuid;
        ssc->gid = mygid;
    }

    /* if we are regaining root, set EUID first so that we have CAP_SETUID back,
     * and the other calls work too, otherwise call it last so that we can
     * change groups before we loose CAP_SETUID */
    if (uid == 0) {
        ret = setresuid(0, 0, 0);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "setresuid failed [%d][%s].\n", ret, strerror(ret));
            goto done;
        }
    }

    /* TODO: use libcap-ng if we need to get/set capabilities too? */

    if (myuid == uid && mygid == gid) {
        DEBUG(SSSDBG_FUNC_DATA, "Already user [%"SPRIuid"].\n", uid);
        talloc_zfree(ssc);
        return EOK;
    }

    /* try to setgroups first should always work if CAP_SETUID is set,
     * otherwise it will always fail, failure is not critical though as
     * generally we only really care about UID and at most primary GID */
    ret = setgroups(num_gids, gids);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC,
              "setgroups failed [%d][%s].\n", ret, strerror(ret));
    }

    /* change GID now, (leaves saved GID to current, so we can restore) */
    ret = setresgid(-1, gid, -1);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "setresgid failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    if (uid != 0) {
        /* change UID, (leaves saved UID to current, so we can restore) */
        ret = setresuid(-1, uid, -1);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "setresuid failed [%d][%s].\n", ret, strerror(ret));
            goto done;
        }
    }

    ret = 0;

done:
    if (ret) {
        /* attempt to restore creds first */
        restore_creds(ssc);
        talloc_free(ssc);
    } else if (saved_creds) {
        *saved_creds = ssc;
    }
    return ret;
}

errno_t restore_creds(struct sss_creds *saved_creds)
{
    if (saved_creds == NULL) {
        /* In case save_creds was saved with the UID already dropped */
        return EOK;
    }

    return switch_creds(saved_creds,
                        saved_creds->uid,
                        saved_creds->gid,
                        saved_creds->num_gids,
                        saved_creds->gids, NULL);
}
