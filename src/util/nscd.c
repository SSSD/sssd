/*
   SSSD

   nscd.c

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2010

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

#include <talloc.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "config.h"
#include "util/util.h"
#include "tools/tools_util.h"

#ifndef NSCD_RELOAD_ARG
#define NSCD_RELOAD_ARG "-i"
#endif

#if defined(NSCD_PATH) && defined(HAVE_NSCD)
int flush_nscd_cache(enum nscd_db flush_db)
{
    const char *service;
    pid_t nscd_pid;
    int ret, status;

    switch(flush_db) {
        case NSCD_DB_PASSWD:
            service = "passwd";
            break;

        case NSCD_DB_GROUP:
            service = "group";
            break;

        default:
            DEBUG(1, ("Unknown nscd database\n"));
            ret = EINVAL;
            goto done;
    }

    nscd_pid = fork();
    switch (nscd_pid) {
    case 0:
        execl(NSCD_PATH, "nscd", NSCD_RELOAD_ARG, service, NULL);
        /* if this returns it is an error */
        DEBUG(1, ("execl(3) failed: %d(%s)\n", errno, strerror(errno)));
        exit(errno);
    case -1:
        DEBUG(1, ("fork failed\n"));
        ret = EFAULT;
        break;
    default:
        do {
            errno = 0;
            ret = waitpid(nscd_pid, &status, 0);
        } while (ret == -1 && errno == EINTR);
        if (ret > 0) {
            if (WIFEXITED(status)) {
                ret = WEXITSTATUS(status);
                if (ret > 0) {
                    /* The flush fails if nscd is not running, so do not care
                    * about the return code */
                    DEBUG(8, ("Error flushing cache, is nscd running?\n"));
                }
            }
        } else {
            DEBUG(5, ("Failed to wait for children %d\n", nscd_pid));
            ret = EIO;
        }
    }

done:
    return ret;
}

#else   /* defined(NSCD_PATH) && defined(HAVE_NSCD) */
int flush_nscd_cache(enum nscd_db flush_db)
{
    return EOK;
}
#endif
